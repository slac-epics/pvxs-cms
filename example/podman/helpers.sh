# Shorthands for the demonstration laboratory:
#
#     source ./helpers.sh
#
# Then:
#
#     run_in lab         as guest    pvxget test:aiExample
#     run_in lab-pvacms  as admin    pvxcert -l --where "state:VALID and type:IOC"
#     run_in ml          as operator pvxput ml:aiExample 42
#     run_in internet    as guest without a certificate  pvxget test:aiExample
#     run_in testioc     as testioc  authnstd -u ioc
#
# Every shorthand can show the command it stands for instead of running it:
#
#     run_in lab-pvacms as admin --show pvxcert -l
#
# Several commands as one person:
#
#     run_in lab-pvacms as admin <<'EOF'
#         pvxcert -l
#         pvxcert -l --where "state:VALID"
#     EOF
#
# `run_in` on its own lists every place and person.

# ---------------------------------------------------------------------------- where things are
#
#   lab, ml                   a workstation inside a department
#   internet                  a workstation in the internet zone
#   lab-pvacms, ml-pvacms     a department's PVACMS
#   testioc, tstioc, ml-ioc   an IOC
#   gateway, ml-gateway       a department's boundary
#
#   guest, operator           ordinary users of a workstation
#   admin                     a department's certificate administrator
#   testioc, tstioc, mlioc,   the account a service runs as
#   gateway

# Which laboratory is up
_lab_topology() {
    local f="${LAB_HELPERS_DIR:-.}/.topology"
    [ -r "${f}" ] && head -1 "${f}" || echo unknown
}

_lab_topology_places() {
    local t var env="${LAB_HELPERS_DIR:-.}/topologies/topologies.env"
    t=$(_lab_topology)
    [ "${t}" = unknown ] && return 1
    [ -r "${env}" ] || return 1
    # shellcheck disable=SC1090
    . "${env}"
    var="TOPOLOGY_${t//-/_}_PLACES"
    local places
    places=$(eval "printf '%s' \"\${${var}-}\"")
    [ -n "${places}" ] || return 1
    printf '%s' "${places}"
}

_lab_place() {          # place -> compose service
    case "$1" in
        lab)          echo lab-client ;;
        ml)           echo ml-client ;;
        internet)     echo internet-client ;;
        lab-pvacms)   echo pvxs-lab-pvacms ;;
        ml-pvacms)    echo pvxs-lab-ml ;;
        testioc)      echo pvxs-lab-testioc ;;
        tstioc)       echo pvxs-lab-tstioc ;;
        ml-ioc)       echo pvxs-lab-ml-ioc ;;
        gateway)      echo pvxs-lab-gateway ;;
        ml-gateway)   echo pvxs-lab-ml-gateway ;;
        *) return 1 ;;
    esac
}

# Compose names a container after the project directory, so ask podman which container is
# running the service.
_lab_container() {
    local name
    name=$(podman ps --filter "label=com.docker.compose.service=$1" --format '{{.Names}}' 2>/dev/null | head -1)
    if [ -z "${name}" ]; then
        echo "run_in: nothing is running for '$1'. Start a laboratory with: reset_topology <topology>" >&2
        return 1
    fi
    printf '%s' "${name}"
}

# Run podman exec, handing through a terminal only when there is one on both sides.
_lab_podman() {
    if [ -t 0 ] && [ -t 1 ]; then podman exec -it "$@"; else podman exec "$@"; fi
}

# Rebuild the command line for the shell inside the container, keeping each argument whole.
# An argument that only needs quoting because it contains spaces gets plain double quotes, so
# a filter still reads as --where "state:VALID and type:IOC" when it is shown or logged;
# anything the far shell could interpret is escaped instead.
_lab_quote() {
    local arg out=
    for arg in "$@"; do
        case "${arg}" in
            *[\$\`\"\\\']*) out+=$(printf '%q' "${arg}") ;;
            *[[:space:]]*)  out+="\"${arg}\"" ;;
            "")             out+="''" ;;
            *)              out+="${arg}" ;;
        esac
        out+=' '
    done
    printf '%s' "${out}"
}

# Whether the authority this shell names is still the one the laboratory has.
_lab_ids_are_current() {
    local env_file="${LAB_HELPERS_DIR:-.}/.env"
    [ -r "${env_file}" ] || return 0
    [ -n "${LAB:-}" ] || return 0          # nothing named yet, so nothing to disagree

    local on_disk
    on_disk=$(sed -n 's/^LAB_ISSUER=//p' "${env_file}")
    [ -n "${on_disk}" ] || return 0
    [ "${on_disk}" != "${LAB}" ] || return 0

    echo "run_in: this shell names authority ${LAB}, but the laboratory now has ${on_disk}." >&2
    echo "        The authorities were minted again since these were read. Run: lab_ids" >&2
    return 1
}

run_in() {
    if [ "$#" -eq 0 ] || [ "$1" = --help ]; then
        sed -n '/^# ----* where things are/,/^_lab_place/p' "${LAB_HELPERS_DIR:-.}/helpers.sh" \
            | sed -e '$d' -e 's/^# \{0,1\}//'
        echo "usage: run_in <place> as <person> [without a certificate] [--show] <command...>"
        echo "       run_in <place> as <person>            with no command, opens a shell there"
        return 2
    fi

    local place="$1" who="$3" plain=no show="${RUN_IN_SHOW:-no}"
    if [ "$2" != as ] || [ -z "${who}" ]; then
        echo "run_in: say it as: run_in <place> as <person> <command...>" >&2; return 2
    fi
    shift 3

    _lab_ids_are_current || true

    # A person may be written <department>/<user>, which is the same user holding a
    # certificate from that department rather than from the one they are sitting in. It reads
    # as what it is - "ml/operator in lab" is the ML operator, at a lab
    # workstation - and it needs a keychain of its own, since the two certificates cannot
    # share one file. Anything without a slash is unchanged.
    local from_dept= keychain_name=client
    case "${who}" in
        */*) from_dept="${who%%/*}"; who="${who##*/}"; keychain_name="${from_dept}" ;;
    esac
    if [ -n "${from_dept}" ] && [ "${from_dept}" != lab ] && [ "${from_dept}" != ml ]; then
        echo "run_in: no department called '${from_dept}'. Write lab/<user> or ml/<user>." >&2
        return 2
    fi

    while [ "$#" -gt 0 ]; do
        case "$1" in
            without) [ "$2" = a ] && [ "$3" = certificate ] || {
                         echo "run_in: did you mean 'without a certificate'?" >&2; return 2; }
                     plain=yes; shift 3 ;;
            --show)  show=yes; shift ;;
            *)       break ;;
        esac
    done

    local service container places topology
    if ! service=$(_lab_place "${place}"); then
        echo "run_in: no place called '${place}'. Places: lab ml internet lab-pvacms ml-pvacms testioc tstioc ml-ioc gateway ml-gateway" >&2
        return 2
    fi

    # A real place, but one this laboratory has none of: say which is up and what it does have.
    if places=$(_lab_topology_places); then
        case " ${places} " in
            *" ${place} "*) ;;
            *) topology=$(_lab_topology)
               echo "run_in: the ${topology} laboratory has no '${place}'." >&2
               echo "        It has: ${places}" >&2
               echo "        Another topology does: reset_topology <topology>" >&2
               return 2 ;;
        esac
    fi

    # The administrator must run in a pvacms node in this demo.
    if [ "${who}" = admin ] && [ "${place}" != lab-pvacms ] && [ "${place}" != ml-pvacms ]; then
        echo "run_in: the administrator's identity lives on the PVACMS node, not at ${place}." >&2
        case "${place}" in
            lab|ml) echo "        Write: run_in ${place}-pvacms as admin ..." >&2 ;;
            *)      echo "        Write: run_in lab-pvacms as admin ...  (or ml-pvacms)" >&2 ;;
        esac
        return 2
    fi

    container=$(_lab_container "${service}") || return 1

    local attach="podman exec"
    if [ -t 0 ] && [ -t 1 ]; then attach="podman exec -it"; fi

    local script interactive=no
    if [ "$#" -gt 0 ]; then
        script=$(_lab_quote "$@")
    elif [ -t 0 ]; then
        interactive=yes
        script="export PS1=\"[${who}@${place}] > \"
exec bash --norc -i"
    else
        script=$(cat)
    fi

    local prelude=
    [ "${plain}" = yes ] && prelude='export EPICS_PVA_TLS_KEYCHAIN=
'
    case "${who}" in
        admin)
            # The identity PVACMS issued to itself.
            prelude="
export EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12
export EPICS_PVA_ADDR_LIST=127.0.0.1
export EPICS_PVA_AUTO_ADDR_LIST=NO
export EPICS_PVA_NAME_SERVERS=
" ;;
        guest|operator)
            # The login profile supplies the tool paths and the organisation.
            prelude="
_addr_was=\${EPICS_PVA_ADDR_LIST+set}
_addr=\${EPICS_PVA_ADDR_LIST-}
_ns_was=\${EPICS_PVA_NAME_SERVERS+set}
_ns=\${EPICS_PVA_NAME_SERVERS-}
_auto_was=\${EPICS_PVA_AUTO_ADDR_LIST+set}
_auto=\${EPICS_PVA_AUTO_ADDR_LIST-}
source ~/.${who}_bashrc 2>/dev/null
if [ -n \"\${_addr_was}\" ]; then
  export EPICS_PVA_ADDR_LIST=\"\${_addr}\";
else
  unset EPICS_PVA_ADDR_LIST;
fi
if [ -n \"\${_ns_was}\" ]; then
  export EPICS_PVA_NAME_SERVERS=\"\${_ns}\";
else
  unset EPICS_PVA_NAME_SERVERS;
fi
if [ -n \"\${_auto_was}\" ]; then
  export EPICS_PVA_AUTO_ADDR_LIST=\"\${_auto}\";
else
  unset EPICS_PVA_AUTO_ADDR_LIST;
fi
export EPICS_PVA_TLS_KEYCHAIN=\${HOME}/.config/pva/1.5/${keychain_name}.p12
${prelude}
" ;;
        *)
            # A service acting as itself, through its own login, which is where its keychain
            # path and its department's addressing come from.
            prelude="
source ~/.${who}_bashrc 2>/dev/null
${prelude}
" ;;
    esac
    script="
${prelude}export PVXS_LOG=\${PVXS_LOG:-none}
${script}"

    # Showing rather than running.
    if [ "${show}" = yes ]; then
        local quoted
        case "${script}" in
            *"'"*) quoted=$(printf '%q' "${script}") ;;
            *)     quoted="'${script}'" ;;
        esac
        case "${who}" in
            guest|operator) echo "${attach} --user ${who} ${container} bash -lc ${quoted}" ;;
            admin)          echo "${attach} ${container} bash -lc ${quoted}" ;;
            *)              echo "${attach} ${container} su - ${who} -c ${quoted}" ;;
        esac
        return 0
    fi

    case "${who}" in
        guest|operator) _lab_podman --user "${who}" "${container}" bash -lc "${script}" ;;
        admin)          _lab_podman "${container}" bash -lc "${script}" ;;
        *)              _lab_podman "${container}" su - "${who}" -c "${script}" ;;
    esac
}

# Build the images every laboratory is made from. The script is shared with the Kubernetes
# laboratory and lives one directory up; this and its kubernetes twin are the two ways in.
build_images() {
    JOBS="${JOBS:-}" CONTAINER_ENGINE=podman "${LAB_HELPERS_DIR:-.}/../bootstrap.sh" "$@"
}

# ------------------------------------------------------------------------------- conveniences

# This laboratory's issuer identifiers.
lab_ids() {
    local env_file="${LAB_HELPERS_DIR:-.}/.env"
    if [ ! -r "${env_file}" ]; then
        echo "no ${env_file} yet - run reset_topology <topology> first" >&2; return 1
    fi
    LAB=$(sed -n 's/^LAB_ISSUER=//p' "${env_file}")
    ML=$(sed -n 's/^ML_ISSUER=//p'  "${env_file}")
    LAB_SKID=$(sed -n 's/^LAB_ISSUER_SKID=//p' "${env_file}")
    ML_SKID=$(sed -n 's/^ML_ISSUER_SKID=//p'  "${env_file}")
    # A laboratory with one authority names it $ROOT, and has no departments.
    ROOT=$(sed -n 's/^ROOT_ISSUER=//p' "${env_file}")
    ROOT_SKID=$(sed -n 's/^ROOT_ISSUER_SKID=//p' "${env_file}")
    export LAB ML LAB_SKID ML_SKID ROOT ROOT_SKID
}

# Brings a laboratory up and reads its authorities into this shell, in one step.
#
# Minting an authority gives it a new identifier, and a shell that read the old one goes on
# naming an authority the laboratory no longer has. Every request then names something nothing
# answers for, which reads as a broken laboratory rather than a stale shell. Running the two
# together is the only way to be sure they agree, so the walkthrough says reset_topology and
# never ./reset.sh.
#
#     reset_topology <topology>                 discard the certificates, keep the authorities
#     reset_topology --authorities <topology>   mint new authorities as well
reset_topology() {
    local script="${LAB_HELPERS_DIR:-.}/reset.sh"
    if [ ! -x "${script}" ]; then
        echo "reset_topology: cannot run ${script}" >&2; return 1
    fi
    "${script}" "$@" || return $?
    # 'clear' takes the laboratory away and puts nothing in its place, so there are no
    # identifiers to read and nothing to report.
    case " $* " in *" clear "*) return 0 ;; esac
    # Only reached when the laboratory came up, so a failure above leaves the old values alone
    # rather than half-replacing them.
    lab_ids
}

# Shows the authorities under the names a shell uses for them.
#
# The file holds LAB_ISSUER and the rest, which is what compose substitutes and what the
# containers are given. A shell uses shorter names for the same values. Printing the file
# as it stands would name variables that lab_ids does not set, so it is printed the way it will
# be typed.
lab_ids_show() {
    local env_file="${LAB_HELPERS_DIR:-.}/.env"
    [ -r "${env_file}" ] || return 0
    local lab ml lab_skid ml_skid
    lab=$(sed -n 's/^LAB_ISSUER=//p' "${env_file}")
    ml=$(sed -n 's/^ML_ISSUER=//p' "${env_file}")
    lab_skid=$(sed -n 's/^LAB_ISSUER_SKID=//p' "${env_file}")
    ml_skid=$(sed -n 's/^ML_ISSUER_SKID=//p' "${env_file}")
    # A laboratory with one authority names it differently, and has no departments to show.
    local root root_skid
    root=$(sed -n 's/^ROOT_ISSUER=//p' "${env_file}")
    root_skid=$(sed -n 's/^ROOT_ISSUER_SKID=//p' "${env_file}")
    if [ -n "${root}" ]; then
        printf '    %-10s %s\n' "\$ROOT" "${root}" "\$ROOT_SKID" "${root_skid}"
        return 0
    fi
    printf '    %-9s %s\n' "\$LAB" "${lab}" "\$ML" "${ml}" "\$LAB_SKID" "${lab_skid}" "\$ML_SKID" "${ml_skid}"
}

# What the facility root's responder says about the root, and how to change it.
#
# The root is the one certificate the laboratory cannot ask about over Secure PVAccess: it has
# no status PV, and an answer carried over a connection it underwrites would be worth
# nothing. It names a responder instead, and each PVACMS asks that responder for the root's
# status.
#
# The responder reads its answer at start, so each of these rewrites the file and restarts it.

# The answer belongs to the laboratory that is up, so it is read from that laboratory's own
# directory.
_lab_authority_index() {
    local t; t=$(_lab_topology)
    [ "${t}" = unknown ] && { echo "no laboratory is up - run reset_topology <topology> first" >&2; return 1; }
    local index="${LAB_HELPERS_DIR:-.}/topologies/${t}/ocsp/index.txt"
    if [ ! -r "${index}" ]; then
        echo "the ${t} laboratory has no facility root, so there is no responder to ask." >&2
        echo "The federated-shared-root laboratory has one: reset_topology federated-shared-root" >&2
        return 1
    fi
    printf '%s' "${index}"
}

# podman-compose is told which laboratory, the same way reset.sh tells it: every topology makes
# the same set of containers, so the project name is fixed and the file chooses the laboratory.
_lab_compose() {
    local t; t=$(_lab_topology)
    [ "${t}" = unknown ] && return 1
    (cd "${LAB_HELPERS_DIR:-.}" \
     && podman-compose -p "$(basename "${LAB_HELPERS_DIR:-$PWD}")" \
                       -f "topologies/${t}/compose.yaml" "$@")
}

# The OCSP responder that answers for the facility root's revocation status:
#
#     ocsp_responder                   what it currently says about the root
#     ocsp_responder unreachable       make it unresponsive
#     ocsp_responder reachable         make it responsive
#     ocsp_responder revoke root       respond that the facility root is REVOKED
ocsp_responder() {
    case "${1:-says}" in
        says)
            # The status is stored in a file on the host.
            local index state
            index=$(_lab_authority_index 2>/dev/null)
            if [ -z "${index}" ]; then echo "no responder here"; return 0; fi
            state=$(podman ps --filter "label=com.docker.compose.service=pvxs-lab-ocsp-responder" \
                        --format '{{.State}}' 2>/dev/null | head -1)
            if [ "${state}" != running ]; then
                echo "the status of the facility root is UNKNOWN"; return 0
            fi
            case "$(cut -f1 "${index}")" in
                R) echo "the facility root is REVOKED" ;;
                V) echo "the facility root is VALID" ;;
                *) echo "internal error in the OCSP responder" ;;
            esac ;;
        unreachable)
            _lab_authority_index >/dev/null || return 1
            _lab_compose stop pvxs-lab-ocsp-responder >/dev/null 2>&1
            echo "the responder is stopped" ;;
        reachable)
            _lab_authority_index >/dev/null || return 1
            _lab_compose start pvxs-lab-ocsp-responder >/dev/null 2>&1
            echo "the responder is running"
            ocsp_responder says ;;
        revoke)
            [ "${2:-}" = root ] || { echo "usage: ocsp_responder revoke root" >&2; return 2; }
            local index; index=$(_lab_authority_index) || return 1
            # The revocation time is the two-digit-year form the index uses throughout; the
            # four-digit form makes the responder answer with an internal error.
            awk -F'\t' -v when="$(date -u +%y%m%d%H%M%SZ)" 'BEGIN{OFS="\t"}
                {print "R", $2, when, $4, $5, $6}' "${index}" > "${index}.new" && mv "${index}.new" "${index}"
            _lab_compose restart pvxs-lab-ocsp-responder >/dev/null 2>&1
            ocsp_responder says ;;
        *)
            echo "ocsp_responder: no subcommand '${1}'." >&2
            echo "usage: ocsp_responder [unreachable|reachable|revoke root]" >&2
            return 2 ;;
    esac
}

# One certificate request, with its outcome reported. "Valid certificate found" is not a
# failure: it is what an already-provisioned laboratory says, and go_tls is safe to run twice.
_ask() {
    local place="$1" who="$2"; shift 2
    local out; out=$(run_in "${place}" as "${who}" "$@" 2>&1 || true)
    if printf '%s' "${out}" | grep -q "Certificate identifier"; then
        printf '    %-10s %s\n' "${place}" "$(printf '%s' "${out}" | grep 'Certificate identifier' | sed 's/.*: //')"
    elif printf '%s' "${out}" | grep -q "Valid certificate found"; then
        printf '    %-10s already holds one\n' "${place}"
    else
        printf '    %-10s FAILED\n' "${place}"
        printf '%s\n' "${out}" | tail -3 | sed 's/^/        /'
    fi
}

# The trust anchor, copied to the workstation outside by hand. Never over an identity: the
# anchor and the identity share one file, so that would reduce the holder to anonymous.
copy_anchor() {
    local places; places=" $(_lab_topology_places) " || return 1
    case "${places}" in *" internet "*) ;; *)
        echo "copy_anchor: this laboratory has no workstation outside." >&2; return 2 ;;
    esac
    local mgr dst tmp who
    mgr=$(_lab_container "$(_lab_place lab-pvacms)") || return 1
    dst=$(_lab_container "$(_lab_place internet)") || return 1
    tmp="${TMPDIR:-/tmp}/trust_anchor.$$.p12"
    echo "==> copying the trust anchor to the workstation outside"
    # Beside the CA keychain, wherever that is: /etc/pvacms when the authority is installed
    # at start, beside the database when the manager minted its own.
    podman exec "${mgr}" sh -c '
        for f in /etc/pvacms/trust_anchor.p12 "$(dirname "${EPICS_PVACMS_DB}")/trust_anchor.p12"; do
            [ -s "${f}" ] && exec cat "${f}"
        done; exit 1' > "${tmp}" 2>/dev/null
    if [ ! -s "${tmp}" ]; then
        echo "    the certificate manager has not written a trust anchor." >&2
        rm -f "${tmp}"; return 1
    fi
    for who in guest operator; do
        if podman exec "${dst}" sh -c \
             'openssl pkcs12 -in "/home/'"${who}"'/.config/pva/1.5/client.p12" -nocerts -passin pass: -passout pass:x 2>/dev/null | grep -q "PRIVATE KEY"' 2>/dev/null; then
            echo "    ${who} already holds an identity, left alone"
            continue
        fi
        podman exec --user root "${dst}" install -d -o "${who}" -g "${who}" -m 0700 "/home/${who}/.config/pva/1.5" 2>/dev/null
        if podman cp "${tmp}" "${dst}:/home/${who}/.config/pva/1.5/client.p12" >/dev/null 2>&1; then
            podman exec --user root "${dst}" chown "${who}" "/home/${who}/.config/pva/1.5/client.p12" 2>/dev/null
            echo "    copied to ${who}"
        else
            echo "    could not copy it to ${who}" >&2
        fi
    done
    rm -f "${tmp}"
}

# Everything the walkthrough does by hand, in the order it has to be done in: IOCs before
# the gateway, because a gateway serves nothing until it holds a certificate and makes its
# upstream connections when it starts; the workstation outside last, because it can ask for
# nothing until the anchor has been carried across.
go_tls() {
    local places has_ml=no has_gateway=no has_internet=no
    places=" $(_lab_topology_places) "
    case "${places}" in *" ml "*) has_ml=yes ;; esac
    case "${places}" in *" gateway "*) has_gateway=yes ;; esac
    case "${places}" in *" internet "*) has_internet=yes ;; esac

    echo "==> asking for certificates inside the laboratory"
    _ask lab     guest    authnstd -u client
    _ask lab     operator authnstd -u client
    _ask testioc testioc  authnstd -u ioc
    _ask tstioc  tstioc   authnstd -u ioc
    [ "${has_gateway}" = yes ] && _ask gateway gateway authnstd -u ioc
    if [ "${has_ml}" = yes ]; then
        _ask ml         guest   authnstd -u client
        _ask ml-ioc     mlioc   authnstd -u ioc
        _ask ml-gateway gateway authnstd -u ioc
    fi

    echo "==> approving them"
    run_in lab-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
        | grep -E 'done|No certificates' || true
    if [ "${has_ml}" = yes ]; then
        run_in ml-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
            | grep -E 'done|No certificates' || true
    fi

    echo "==> restarting what now holds one"
    local c=
    c=$(_lab_container "$(_lab_place testioc)") && podman exec --user root "${c}" supervisorctl restart testioc >/dev/null 2>&1
    c=$(_lab_container "$(_lab_place tstioc)")  && podman exec --user root "${c}" supervisorctl restart tstioc  >/dev/null 2>&1
    if [ "${has_ml}" = yes ]; then
        c=$(_lab_container "$(_lab_place ml-ioc)") && podman exec --user root "${c}" supervisorctl restart mlioc >/dev/null 2>&1
    fi
    if [ "${has_gateway}" = yes ] || [ "${has_ml}" = yes ]; then
        # pvagw makes its upstream connections at start and does not retry them.
        podman ps --format '{{.Names}}' | grep -- '-gateway' | while read -r c; do
            [ -n "${c}" ] && podman restart "${c}" >/dev/null 2>&1
        done
        sleep 8
    fi

    # A laboratory with nothing outside it is provisioned already: no anchor to carry, no
    # boundary to cross.
    if [ "${has_internet}" != yes ]; then
        echo "==> no workstation outside this laboratory; done"
        return 0
    fi

    copy_anchor || return 1

    echo "==> waiting for the gateway to serve the internet"
    local i=0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        run_in gateway as gateway sh -c 'ss -lnt 2>/dev/null | grep -q 507' 2>/dev/null && break
        sleep 5
    done

    echo "==> asking for a certificate from the internet, across the gateway"
    local _last=
    for i in 1 2 3 4 5 6; do
        # An explicit branch, not a conditional expansion: zsh hands
        # ${X:+--issuer "${X}"} to the command as a single word.
        if [ -n "${LAB_SKID:-}" ]; then
            _last=$(run_in internet as guest authnstd -u client -n remote --issuer "${LAB_SKID}" 2>&1)
        else
            _last=$(run_in internet as guest authnstd -u client -n remote 2>&1)
        fi
        printf '%s\n' "${_last}" | grep -E 'Certificate identifier|Valid certificate found' && break
        sleep 5
    done
    # Every attempt failed: show the last error, because a silence here cannot be told
    # apart from success by anything that follows.
    if ! printf '%s\n' "${_last}" | grep -qE 'Certificate identifier|Valid certificate found'; then
        printf '%s\n' "${_last}" | tail -3 | sed 's/^/    /' >&2
    fi
    run_in lab-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
        | grep -E 'done|No certificates' || true
    sleep 3

    echo "==> reading across the gateway"
    local ok=no
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        run_in internet as guest pvxget test:aiExample >/dev/null 2>&1 && { ok=yes; break; }
        sleep 5
    done
    if [ "${ok}" = yes ]; then
        # A read alone proves reachability, not identity: a gateway forwards anonymous TLS
        # reads, so an empty keychain passes it. Say which one this was.
        if run_in internet as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12 2>/dev/null \
               | grep -q '^Entity Subject'; then
            echo "    the gateway is open to a holder with a valid certificate"
        else
            echo "    reading works, but the workstation outside holds no identity:" >&2
            echo "    the certificate request across the gateway did not succeed." >&2
            return 1
        fi
    else
        echo "    it still will not read. Look at the gateway:" >&2
        echo "        podman logs \$(podman ps --format '{{.Names}}' | grep -m1 -- '-gateway')" >&2
        return 1
    fi
}

lab_status() {
    local place service
    printf '%-12s %-19s %-10s %s\n' PLACE SERVICE STATE CONTAINER
    local all="lab-pvacms testioc tstioc gateway ml-pvacms ml-ioc ml-gateway lab ml internet"
    local places; places=$(_lab_topology_places) || places="${all}"
    # Split through a pipe rather than by expansion: zsh does not word-split ${places},
    # and this file is sourced by whichever shell the reader uses.
    echo "${places}" | tr ' ' '\n' | while read -r place; do
        [ -n "${place}" ] || continue
        service=$(_lab_place "${place}") || continue
        printf '%-12s %-19s %-10s %s\n' "${place}" "${service}" \
            "$(podman ps -a --filter "label=com.docker.compose.service=${service}" --format '{{.State}}' 2>/dev/null | head -1)" \
            "$(podman ps -a --filter "label=com.docker.compose.service=${service}" --format '{{.Names}}' 2>/dev/null | head -1)"
    done
}

# Remember where this file lives, so it can read .env and quote its own documentation back.
case "${BASH_SOURCE[0]:-$0}" in
    */*) LAB_HELPERS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd) ;;
    *)   LAB_HELPERS_DIR=$PWD ;;
esac
export LAB_HELPERS_DIR
lab_ids 2>/dev/null || true
