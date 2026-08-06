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
#   perimeter                 a workstation outside both, reaching only the two gateways
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
        echo "run_in: nothing is running for '$1'. Start the laboratory with: podman-compose up -d" >&2
        return 1
    fi
    printf '%s' "${name}"
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

run_in() {
    if [ "$#" -eq 0 ] || [ "$1" = --help ]; then
        sed -n '/^# ----* where things are/,/^_lab_place/p' "${LAB_HELPERS_DIR:-.}/helpers.sh" \
            | sed -e '$d' -e 's/^# \{0,1\}//'
        echo "usage: run_in <place> as <person> [without a certificate] [--show] <command...>"
        return 2
    fi

    # RUN_IN_SHOW=yes turns every call into a --show, which is how a whole document's worth
    # of examples can be checked for where they would go without running any of them.
    local place="$1" who="$3" plain=no show="${RUN_IN_SHOW:-no}"
    if [ "$2" != as ] || [ -z "${who}" ]; then
        echo "run_in: say it as: run_in <place> as <person> <command...>" >&2; return 2
    fi
    shift 3

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

    local service container
    if ! service=$(_lab_place "${place}"); then
        echo "run_in: no place called '${place}'. Places: lab ml perimeter lab-manager ml-manager testioc tstioc ml-ioc gateway ml-gateway" >&2
        return 2
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
    local script
    if [ "$#" -gt 0 ]; then
        script=$(_lab_quote "$@")
    elif [ -t 0 ]; then
        echo "run_in: no command given, and nothing on standard input to read one from." >&2
        return 2
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
            prelude="export EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12
export EPICS_PVA_NAME_SERVERS=pvas://localhost:5076
" ;;
        guest|operator)
            # The login profile supplies the tool paths and the organisation, but it was
            # written for the lab department and names the lab's hosts. The container knows
            # which department it is actually in, so put its own addressing back afterwards -
            # otherwise a command run on the machine learning workstation, or on the
            # perimeter, quietly talks to the lab instead.
            prelude="_addr_was=\${EPICS_PVA_ADDR_LIST+set}; _addr=\${EPICS_PVA_ADDR_LIST-}
_ns_was=\${EPICS_PVA_NAME_SERVERS+set}; _ns=\${EPICS_PVA_NAME_SERVERS-}
source ~/.${who}_bashrc 2>/dev/null
if [ -n \"\${_addr_was}\" ]; then export EPICS_PVA_ADDR_LIST=\"\${_addr}\"; else unset EPICS_PVA_ADDR_LIST; fi
if [ -n \"\${_ns_was}\" ]; then export EPICS_PVA_NAME_SERVERS=\"\${_ns}\"; else unset EPICS_PVA_NAME_SERVERS; fi
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
            guest|operator) echo "podman exec --user ${who} ${container} bash -lc ${quoted}" ;;
            admin)          echo "podman exec ${container} bash -lc ${quoted}" ;;
            *)              echo "podman exec ${container} su - ${who} -c ${quoted}" ;;
        esac
        return 0
    fi

    case "${who}" in
        guest|operator) podman exec --user "${who}" "${container}" bash -lc "${script}" ;;
        admin)          podman exec "${container}" bash -lc "${script}" ;;
        *)              podman exec "${container}" su - "${who}" -c "${script}" ;;
    esac
}

# ------------------------------------------------------------------------------- conveniences

# The two departments' issuer identifiers, as bootstrap.sh recorded them, so an example can
# say CERT:LIST:${LAB}:ALL rather than a forty-character string.
lab_ids() {
    local env_file="${LAB_HELPERS_DIR:-.}/.env"
    if [ ! -r "${env_file}" ]; then
        echo "no ${env_file} yet - run ./bootstrap.sh first" >&2; return 1
    fi
    LAB=$(sed -n 's/^LAB_ISSUER=//p' "${env_file}")
    ML=$(sed -n 's/^ML_ISSUER=//p'  "${env_file}")
    export LAB ML
}

# Which parts of the laboratory are up, named the way run_in names them.
lab_status() {
    local place service
    printf '%-12s %-18s %-10s %s\n' PLACE SERVICE STATE CONTAINER
    for place in lab-manager testioc tstioc gateway ml-manager ml-ioc ml-gateway lab ml perimeter; do
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
