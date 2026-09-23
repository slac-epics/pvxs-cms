# Shorthands for the demonstration laboratory, so an example says what is run, where, and
# by whom. Source it once, from this directory:
#
#     source ./helpers.sh
#
# Then:
#
#     run_in lab         as guest    pvxget test:aiExample
#     run_in lab-manager as admin    pvxcert -l --where "state:VALID and type:IOC"
#     run_in ml          as operator pvxput ml:aiExample 42
#     run_in perimeter   as guest without a certificate  pvxget test:aiExample
#     run_in testioc     as testioc  authnstd -u ioc
#
# Every shorthand can show the command it stands for instead of running it, so nothing here
# is a black box and anything can be copied into a real deployment:
#
#     run_in lab-manager as admin --show pvxcert -l
#
# Several commands as one person, when the sequence is the point:
#
#     run_in lab-manager as admin <<'EOF'
#         pvxcert -l
#         pvxcert -l --where "state:VALID"
#     EOF
#
# `run_in` on its own lists every place and person.

# ---------------------------------------------------------------------------- where things are
#
# A place is a machine, and it is named for what stands there. An administrator's identity
# lives beside the certificate manager, so "lab-manager" is a different place from "lab" -
# calling both of them "lab" would hide the very thing these examples are about.
#
#   lab, ml                   a workstation inside a department
#   perimeter                 a workstation outside, reaching in only across a boundary
#   lab-manager, ml-manager   a department's certificate manager
#   testioc, tstioc, ml-ioc   a controller
#   gateway, ml-gateway       a department's boundary
#
# A person is a real account on that machine:
#
#   guest, operator           ordinary users of a workstation
#   admin                     a department's certificate administrator
#   testioc, tstioc, mlioc,   the account a service runs as
#   gateway, idm

# Which laboratory is up, written by reset.sh. run_in uses it to tell "this laboratory has no
# gateway" apart from "the gateway is not running", which are different problems with
# different answers.
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
    # eval rather than ${!var}: this file is sourced by whichever shell the reader uses, and
    # indirect expansion is spelt differently in each. zsh answers ${!var} with
    # "bad substitution", which is what a person sees instead of their command running.
    local places
    places=$(eval "printf '%s' \"\${${var}-}\"")
    [ -n "${places}" ] || return 1
    printf '%s' "${places}"
}

_lab_place() {          # place -> compose service
    case "$1" in
        lab)          echo lab-client ;;
        ml)           echo ml-client ;;
        perimeter)    echo perimeter-client ;;
        lab-manager)  echo pvxs-lab-pvacms ;;
        ml-manager)   echo pvxs-lab-ml ;;
        testioc)      echo pvxs-lab-testioc ;;
        tstioc)        echo pvxs-lab-tstioc ;;
        ml-ioc)       echo pvxs-lab-ml-ioc ;;
        gateway)      echo pvxs-lab-gateway ;;
        ml-gateway)   echo pvxs-lab-ml-gateway ;;
        *) return 1 ;;
    esac
}

# Compose names a container after the project directory, so ask podman which container is
# running the service rather than assuming what it is called.
_lab_container() {
    local name
    name=$(podman ps --filter "label=com.docker.compose.service=$1" --format '{{.Names}}' 2>/dev/null | head -1)
    if [ -z "${name}" ]; then
        echo "run_in: nothing is running for '$1'. Start a laboratory with: ./reset.sh <topology>" >&2
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
#
# Minting new authorities rewrites .env, but an exported variable in a shell that is already
# open cannot be reached from outside it. Anything typed with ${LAB} or ${LAB_SKID} then names
# an authority that no longer exists, and what comes back says nothing about why: a request
# times out, because there is nothing to answer it, and a certificate manager that never saw
# the authority has nothing to say about it either.
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

    # RUN_IN_SHOW=yes turns every call into a --show, which is how a whole document's worth
    # of examples can be checked for where they would go without running any of them.
    local place="$1" who="$3" plain=no show="${RUN_IN_SHOW:-no}"
    if [ "$2" != as ] || [ -z "${who}" ]; then
        echo "run_in: say it as: run_in <place> as <person> <command...>" >&2; return 2
    fi
    shift 3

    _lab_ids_are_current || true

    # A person may be written <department>/<user>, which is the same user holding a
    # certificate from that department rather than from the one they are sitting in. It reads
    # as what it is - "ml/operator in lab" is the machine learning operator, at a lab
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
            # "without a certificate" reads as English and says exactly what is being shown:
            # the same person, presenting nothing. A made-up name like "anyone" would leave
            # the reader wondering whose credentials were used.
            without) [ "$2" = a ] && [ "$3" = certificate ] || {
                         echo "run_in: did you mean 'without a certificate'?" >&2; return 2; }
                     plain=yes; shift 3 ;;
            --show)  show=yes; shift ;;
            *)       break ;;
        esac
    done

    local service container places topology
    if ! service=$(_lab_place "${place}"); then
        echo "run_in: no place called '${place}'. Places: lab ml perimeter lab-manager ml-manager testioc tstioc ml-ioc gateway ml-gateway" >&2
        return 2
    fi

    # A real place, but one this laboratory has none of: say which laboratory is up and what
    # it does have, rather than reporting nothing is running for it.
    if places=$(_lab_topology_places); then
        case " ${places} " in
            *" ${place} "*) ;;
            *) topology=$(_lab_topology)
               echo "run_in: the ${topology} laboratory has no '${place}'." >&2
               echo "        It has: ${places}" >&2
               echo "        Another topology does: ./reset.sh <topology>" >&2
               return 2 ;;
        esac
    fi

    # The administrator is not a user of a workstation. Say why rather than quietly running
    # the command somewhere the reader was not told about.
    if [ "${who}" = admin ] && [ "${place}" != lab-manager ] && [ "${place}" != ml-manager ]; then
        echo "run_in: the administrator's identity lives on the certificate manager, not at ${place}." >&2
        case "${place}" in
            lab|ml) echo "        Write: run_in ${place}-manager as admin ..." >&2 ;;
            *)      echo "        Write: run_in lab-manager as admin ...  (or ml-manager)" >&2 ;;
        esac
        return 2
    fi

    container=$(_lab_container "${service}") || return 1

    # Keep the command exactly as it was typed. Requoting matters: a filter such as
    # --where "state:VALID and type:IOC" is one argument, and flattening it into a string
    # would hand pvxcert three.
    #
    # A terminal is handed through only when there is one on both sides. That is what lets a
    # command which asks a question - pvxcert --review-pending - be answered, and it is the
    # only case that needs it: the tools ask nothing unless they are talking to a terminal.
    #
    # Connecting standard input at any other time would do harm. A container given the
    # surrounding script's input reads it: a run_in inside a loop over a list of commands
    # would swallow the rest of the list and the loop would stop after one turn.
    local attach="podman exec"
    if [ -t 0 ] && [ -t 1 ]; then attach="podman exec -it"; fi

    # No command at a terminal opens a shell there, as that person, with everything set up
    # that a command would have had. It is how to answer something that asks a question -
    # pvxcert --review-pending puts its prompts to a terminal and reads the answers back from
    # one - and how to try things without writing run_in in front of each.
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

    # Whatever the person needs set before their command runs. Held as one string rather
    # than an array, because arrays are not written the same way in every shell and this
    # file is sourced by whichever one the reader happens to use.
    local prelude=
    [ "${plain}" = yes ] && prelude='export EPICS_PVA_TLS_KEYCHAIN=
'
    case "${who}" in
        admin)
            # The identity the certificate manager issued to itself, presented over the
            # secure port. Without both of these the manager sees no administrator and
            # refuses the decision - which is the access rule working, not a broken tool.
            #
            # The address is this machine: an administrator's tools run beside the manager
            # and have no reason to look anywhere else. Naming it here rather than in
            # compose.yaml keeps the certificate manager itself free of any address list,
            # which is right - it is a server and never searches for anything.
            prelude="export EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12
export EPICS_PVA_ADDR_LIST=127.0.0.1
export EPICS_PVA_AUTO_ADDR_LIST=NO
export EPICS_PVA_NAME_SERVERS=
" ;;
        guest|operator)
            # The login profile supplies the tool paths and the organisation, but it was
            # written for the federated laboratory and names its hosts. The container knows
            # which laboratory it is actually in, so put its own addressing back afterwards -
            # otherwise a command run on the machine learning workstation, or on the
            # perimeter, quietly talks to the lab instead.
            #
            # All three of these, not just the two lists: a laboratory that finds everything
            # by broadcast sets neither list and turns automatic discovery on, and leaving the
            # profile's "NO" in place would leave it with nowhere to search at all.
            prelude="_addr_was=\${EPICS_PVA_ADDR_LIST+set}; _addr=\${EPICS_PVA_ADDR_LIST-}
_ns_was=\${EPICS_PVA_NAME_SERVERS+set}; _ns=\${EPICS_PVA_NAME_SERVERS-}
_auto_was=\${EPICS_PVA_AUTO_ADDR_LIST+set}; _auto=\${EPICS_PVA_AUTO_ADDR_LIST-}
source ~/.${who}_bashrc 2>/dev/null
if [ -n \"\${_addr_was}\" ]; then export EPICS_PVA_ADDR_LIST=\"\${_addr}\"; else unset EPICS_PVA_ADDR_LIST; fi
if [ -n \"\${_ns_was}\" ]; then export EPICS_PVA_NAME_SERVERS=\"\${_ns}\"; else unset EPICS_PVA_NAME_SERVERS; fi
if [ -n \"\${_auto_was}\" ]; then export EPICS_PVA_AUTO_ADDR_LIST=\"\${_auto}\"; else unset EPICS_PVA_AUTO_ADDR_LIST; fi
export EPICS_PVA_TLS_KEYCHAIN=\${HOME}/.config/pva/1.5/${keychain_name}.p12
${prelude}" ;;
        *)
            # A service acting as itself, through its own login, which is where its keychain
            # path and its department's addressing come from.
            prelude="source ~/.${who}_bashrc 2>/dev/null
${prelude}" ;;
    esac
    script="
${prelude}export PVXS_LOG=\${PVXS_LOG:-none}
${script}"

    # Showing rather than running: print it the way a person would type it, with the script
    # left as written instead of escaped, so it can be read and pasted back.
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

# ------------------------------------------------------------------------------- conveniences

# This laboratory's issuer identifiers, as bootstrap.sh recorded them, so an example can
# say CERT:LIST:${LAB}:ALL rather than a forty-character string.
lab_ids() {
    local env_file="${LAB_HELPERS_DIR:-.}/.env"
    if [ ! -r "${env_file}" ]; then
        echo "no ${env_file} yet - run ./reset.sh <topology> first" >&2; return 1
    fi
    # Two forms, wanted in different places. The short one names an authority in a process
    # variable name, such as CERT:LIST:${LAB}:ALL. The whole one is what establishes trust in
    # it, and is what --issuer wants on a first request.
    LAB=$(sed -n 's/^LAB_ISSUER=//p' "${env_file}")
    ML=$(sed -n 's/^ML_ISSUER=//p'  "${env_file}")
    LAB_SKID=$(sed -n 's/^LAB_ISSUER_SKID=//p' "${env_file}")
    ML_SKID=$(sed -n 's/^ML_ISSUER_SKID=//p'  "${env_file}")
    # A laboratory with one authority names it $ROOT, and has no departments.
    ROOT=$(sed -n 's/^ROOT_ISSUER=//p' "${env_file}")
    ROOT_SKID=$(sed -n 's/^ROOT_ISSUER_SKID=//p' "${env_file}")
    export LAB ML LAB_SKID ML_SKID ROOT ROOT_SKID
    # Silent: this is also run when the file is sourced, and sourcing should say nothing.
    # Use lab_ids_show to see them.
}

# Shows the authorities under the names a shell uses for them.
#
# The file holds LAB_ISSUER and the rest, which is what compose substitutes and what the
# containers are given. A shell uses shorter names for the same values. Printing the file
# as it stands would name variables that lab_ids does not set, so it is printed the way it will
# be typed, and this is the only place that knows both spellings.
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
# no status channel, and an answer carried over a connection it underwrites would be worth
# nothing. It names a responder instead, and each certificate manager asks that responder
# whether the root still stands.
#
# The responder reads its answer at start, so each of these rewrites the file and restarts it.
authority_says() {
    local index="${LAB_HELPERS_DIR:-.}/ocsp/index.txt"
    [ -r "${index}" ] || { echo "no ${index} yet - run ./bootstrap.sh first" >&2; return 1; }
    case "$(cut -f1 "${index}")" in
        R) echo "the facility root is REVOKED" ;;
        V) echo "the facility root stands" ;;
        *) echo "the responder's index says something this does not understand" ;;
    esac
}

# Revoke the facility root, as its own authority would.
authority_revoke() {
    local index="${LAB_HELPERS_DIR:-.}/ocsp/index.txt"
    [ -r "${index}" ] || { echo "no ${index} yet - run ./bootstrap.sh first" >&2; return 1; }
    # The revocation time is the two-digit-year form the index uses throughout; the four-digit
    # form makes the responder answer with an internal error rather than a status.
    awk -F'\t' -v when="$(date -u +%y%m%d%H%M%SZ)" 'BEGIN{OFS="\t"}
        {print "R", $2, when, $4, $5, $6}' "${index}" > "${index}.new" && mv "${index}.new" "${index}"
    (cd "${LAB_HELPERS_DIR:-.}" && podman-compose restart pvxs-lab-authority-status) >/dev/null 2>&1
    authority_says
}

# Put the facility root back, so a demonstration can be run again.
authority_restore() {
    local index="${LAB_HELPERS_DIR:-.}/ocsp/index.txt"
    [ -r "${index}" ] || { echo "no ${index} yet - run ./bootstrap.sh first" >&2; return 1; }
    awk -F'\t' 'BEGIN{OFS="\t"} {print "V", $2, "", $4, $5, $6}' "${index}" > "${index}.new" \
        && mv "${index}.new" "${index}"
    (cd "${LAB_HELPERS_DIR:-.}" && podman-compose restart pvxs-lab-authority-status) >/dev/null 2>&1
    authority_says
}

# Take the responder away without changing what it would have said, which is the other thing
# that can happen to it.
authority_unreachable() {
    (cd "${LAB_HELPERS_DIR:-.}" && podman-compose stop pvxs-lab-authority-status) >/dev/null 2>&1
    echo "the responder is stopped; nothing can be learned about the root"
}

authority_reachable() {
    (cd "${LAB_HELPERS_DIR:-.}" && podman-compose start pvxs-lab-authority-status) >/dev/null 2>&1
    echo "the responder is running again"
    authority_says
}

# Which parts of the laboratory are up, named the way run_in names them.
lab_status() {
    local place service
    printf '%-12s %-18s %-10s %s\n' PLACE SERVICE STATE CONTAINER
    local all="lab-manager testioc tstioc gateway ml-manager ml-ioc ml-gateway lab ml perimeter"
    local places; places=$(_lab_topology_places) || places="${all}"
    for place in ${places}; do
        service=$(_lab_place "${place}")
        printf '%-12s %-18s %-10s %s\n' "${place}" "${service}" \
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
