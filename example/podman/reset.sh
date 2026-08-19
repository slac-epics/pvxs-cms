#!/bin/bash
# Return the laboratory to the state it is in immediately after a fresh build, so a
# demonstration can be run from the top - and prove it before handing it back.
#
# The route is deliberately the blunt one: every container, every volume and every network
# the laboratory owns is destroyed and made again from the compose file. Nothing here knows
# which service keeps what where, so nothing here goes stale when a service changes. The
# certificates are then issued, and the whole laboratory is made again a second time so that
# every service starts already holding what it was issued - which is why no service is
# restarted individually anywhere in this script.
#
# It ends by trying the things a demonstration depends on. If any of them fails, this exits
# non-zero and says where to look, rather than handing back a laboratory that looks up.
#
#   ./reset.sh <topology>                discard the certificates, keep the authorities
#   ./reset.sh --authorities <topology>  mint new authorities as well; the issuer ids change
#
# The topology names, and what each one is, are in topologies/topologies.env. Whichever one
# you name is the laboratory you get, and the walkthrough section of the same name is the one
# that applies to it.
#
set -euo pipefail
cd "$(dirname "$0")"

. topologies/topologies.env

_usage() {
    echo "usage: ./reset.sh [--authorities] <topology>" >&2
    echo >&2
    echo "topologies:" >&2
    local t var
    for t in ${TOPOLOGY_NAMES}; do
        var="TOPOLOGY_${t//-/_}_TITLE"
        printf '    %-28s %s\n' "${t}" "${!var}" >&2
        [ -e "topologies/${t}/.stub" ] && printf '    %-28s %s\n' "" "(not built yet)" >&2
    done
    exit 2
}

new_authorities=no
topology=
for arg in "$@"; do
    case "${arg}" in
        --authorities) new_authorities=yes ;;
        -h|--help)     _usage ;;
        -*)            echo "./reset.sh: no option '${arg}'" >&2; _usage ;;
        *)             [ -z "${topology}" ] || { echo "./reset.sh: one topology at a time" >&2; _usage; }
                       topology="${arg}" ;;
    esac
done
[ -n "${topology}" ] || { echo "./reset.sh: name a topology" >&2; _usage; }

case " ${TOPOLOGY_NAMES} " in
    *" ${topology} "*) ;;
    *) echo "./reset.sh: no topology called '${topology}'" >&2; _usage ;;
esac

if [ -e "topologies/${topology}/.stub" ]; then
    echo "'${topology}' is drawn but not built yet." >&2
    echo >&2
    echo "Its picture is topology/topology-${topology}.svg, and what building it needs is" >&2
    echo "written at the top of topologies/${topology}/compose.yaml." >&2
    echo >&2
    echo "Built today: federated-shared-root." >&2
    exit 2
fi

# podman-compose names everything it makes after the directory this file sits in. The name is
# pinned rather than taken from the compose file's own directory, so every topology makes and
# destroys the same set and switching between them leaves nothing of the last one behind.
project=$(basename "$(pwd)")
compose_file="topologies/${topology}/compose.yaml"
_compose() { podman-compose -p "${project}" -f "${compose_file}" "$@"; }

# What is up, for helpers.sh to read: it decides from this which places run_in will accept.
printf '%s\n' "${topology}" > .topology

# A laboratory with more than one certificate manager has to be told which authority each one
# signs with, and the issuer ids have to exist before anything starts, so those topologies
# mint beside their own compose file. A laboratory with one certificate manager needs none of
# that: pvacms creates its own self-signed authority the first time it starts, and with only
# one of them the unqualified CERT:CREATE is unambiguous.
topology_dir="topologies/${topology}"
if [ -x "${topology_dir}/mint.sh" ]; then
    if [ "${new_authorities}" = yes ] || [ ! -s "${topology_dir}/issuer_ids.env" ]; then
        "${topology_dir}/mint.sh"
    else
        echo "==> keeping the existing certificate authorities"
    fi
    # compose substitutes ${LAB_ISSUER} and the rest in the file itself, and reads .env from
    # the directory it is run from, which is this one whichever topology is up.
    cp "${topology_dir}/issuer_ids.env" .env
else
    echo "==> the certificate manager will create its own authority when it starts"
    : > .env
fi

# ---------------------------------------------------------------- the blunt instrument
# Everything below works from what podman reports, filtered by the project name, so a
# service added to or removed from compose.yaml needs no change here.

_containers() { podman ps -aq --filter "label=io.podman.compose.project=${project}"; }
_volumes()    { podman volume ls -q 2>/dev/null | grep -E "^${project}_" || true; }
_networks()   { podman network ls --format '{{.Name}}' 2>/dev/null | grep -E "^${project}_" || true; }

_destroy_containers() {
    _compose down >/dev/null 2>&1 || true
    local ids; ids=$(_containers)
    [ -n "${ids}" ] && podman rm -f ${ids} >/dev/null 2>&1 || true
}

_destroy_everything() {
    _destroy_containers
    local vols nets
    vols=$(_volumes); [ -n "${vols}" ] && podman volume rm -f ${vols} >/dev/null 2>&1 || true
    nets=$(_networks); [ -n "${nets}" ] && podman network rm -f ${nets} >/dev/null 2>&1 || true
}

_bring_up() {
    # podman-compose reports failures per service on stdout rather than in its exit code, so
    # the count of running containers is what says whether this worked.
    _compose up -d >/dev/null 2>&1 || true
    local want got
    want=$(_compose config --services 2>/dev/null | grep -c . || echo 0)
    for _ in $(seq 1 30); do
        got=$(_containers | wc -l | tr -d ' ')
        [ "${got}" -ge "${want}" ] && [ "${want}" -gt 0 ] && return 0
        sleep 2
        _compose up -d >/dev/null 2>&1 || true
    done
    echo "    only ${got} of ${want} containers started. Look at:" >&2
    echo "        cd $(pwd) && podman-compose -p ${project} -f ${compose_file} up -d" >&2
    return 1
}

# ---------------------------------------------------------------- checks
# Each laboratory is checked for what it has. A responder, a second department and a
# perimeter are not universal, and asking about one a topology lacks would report a fault
# where there is none.
_places=$(eval "printf '%s' \"\${TOPOLOGY_${topology//-/_}_PLACES}\"")
_has() { case " ${_places} " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# Each returns non-zero and says where to look. They ask the laboratory the same questions a
# person would, rather than inspecting anything's insides.

_check_responder() {
    # The authority has to be establishable before anything can be issued. A laboratory that
    # looks up but cannot establish it is the worst state to hand back: every certificate is
    # reported unusable, administration stops with them, and the tools that would show you
    # why have stopped too.
    local c; c=$(podman ps --format '{{.Names}}' | grep -- '-authority-status' | head -1)
    [ -n "${c}" ] || { echo "    no responder container is running" >&2; return 1; }
    for _ in $(seq 1 12); do
        if podman exec "${c}" timeout 8 openssl ocsp \
                -issuer /ocsp/ca.pem -cert /ocsp/ca.pem \
                -url http://127.0.0.1:8888 -CAfile /ocsp/ca.pem 2>/dev/null \
                | grep -q ': good'; then
            return 0
        fi
        sleep 5
    done
    echo "    the responder for the facility root is not answering 'good'." >&2
    echo "    Nothing can be issued until it does. Look at:" >&2
    echo "        podman logs ${c}" >&2
    return 1
}

_check_managers() {
    # Each manager answering its own administrator is the first thing a demonstration needs,
    # and the thing that fails when the facility root cannot be established.
    local ok=no
    for _ in $(seq 1 18); do
        if run_in lab-manager as admin pvxcert -l >/dev/null 2>&1 \
        && { ! _has ml-manager || run_in ml-manager as admin pvxcert -l >/dev/null 2>&1; }; then
            ok=yes; break
        fi
        sleep 5
    done
    [ "${ok}" = yes ] && return 0
    echo "    a certificate manager will not answer its administrator." >&2
    echo "    That is what a facility root nobody can establish looks like. Look at:" >&2
    echo "        podman logs \$(podman ps --format '{{.Names}}' | grep pvacms)" >&2
    return 1
}

_check_reads() {
    local ok=no
    for _ in $(seq 1 18); do
        # Each line is guarded by what it needs, which is a place to ask from AND a
        # controller to answer. ml:aiExample needs the machine learning controller however
        # many other places a laboratory has.
        if run_in lab as guest without a certificate pvxget test:aiExample >/dev/null 2>&1 \
        && { ! _has ml-ioc    || run_in ml        as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1; } \
        && { ! _has perimeter || run_in perimeter as guest without a certificate pvxget test:aiExample >/dev/null 2>&1; } \
        && { ! _has perimeter || ! _has ml-ioc \
                              || run_in perimeter as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1; }; then
            ok=yes; break
        fi
        sleep 5
    done
    [ "${ok}" = yes ] && return 0
    echo "    reading does not work from everywhere yet." >&2
    echo "    Try them one at a time to see which:" >&2
    echo "        run_in lab as guest without a certificate pvxget test:aiExample" >&2
    _has perimeter && echo "        run_in perimeter as guest without a certificate pvxget test:aiExample" >&2
    return 1
}

_says() { # _says <expected text> <command...>   - true when the output contains the text
    # The output is captured before it is searched: these commands are expected to fail, and
    # under 'set -o pipefail' their failure would sink the pipeline even when the text matched.
    local want="$1"; shift
    local out; out=$("$@" 2>&1 || true)
    printf '%s' "${out}" | grep -q -- "${want}"
}

_check_refusals() {
    # Nothing holds a certificate at this point, so what can be checked is that the laboratory
    # refuses a write, and refuses it in the right place: by the controller in its own
    # department, and at the boundary from outside it.
    if ! _says 'Put not permitted' \
         run_in lab as guest without a certificate pvxput test:stringExample hello; then
        echo "    a request with no certificate was not refused by the controller." >&2
        return 1
    fi
    if _has perimeter && ! _says 'denied by gateway' \
         run_in perimeter as guest without a certificate pvxput test:stringExample hello; then
        echo "    a request with no certificate was not refused at the boundary." >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------- do it
echo "==> destroying the laboratory: containers, volumes, networks"
_destroy_everything

# A demonstration may have left the facility root revoked, and a laboratory that starts with a
# revoked authority issues nothing. Put it back. Only a laboratory with a responder has one.
_ocsp="${topology_dir}/ocsp/index.txt"
if [ -s "${_ocsp}" ] && [ "$(cut -f1 "${_ocsp}")" != V ]; then
    echo "==> putting the facility root back"
    awk -F'\t' 'BEGIN{OFS="\t"} {print "V", $2, "", $4, $5, $6}' "${_ocsp}" > "${_ocsp}.new"
    mv "${_ocsp}.new" "${_ocsp}"
fi

echo "==> building the laboratory"
_bring_up

# A laboratory whose certificate manager mints its own authority does not know its issuer id
# until that has happened. Nothing may trust an authority it was told about over the channel
# it is trying to establish, so a client refuses to ask until it has been given the id out of
# band - which is what this does, once the authority exists.
if [ ! -x "${topology_dir}/mint.sh" ]; then
    echo "==> reading the issuer id from the authority the certificate manager made"
    _mgr=$(podman ps --filter "label=com.docker.compose.service=pvxs-lab-pvacms" --format '{{.Names}}' | head -1)
    _skid=
    for _ in $(seq 1 18); do
        _skid=$(podman exec "${_mgr}" bash -c '
            k=$(dirname "${EPICS_PVACMS_DB}")/cert_auth.p12
            [ -s "$k" ] || exit 1
            openssl pkcs12 -in "$k" -nokeys -passin pass: 2>/dev/null               | openssl x509 -noout -ext subjectKeyIdentifier 2>/dev/null               | tail -1 | tr -d " :" | tr "A-F" "a-f"' 2>/dev/null || true)
        [ -n "${_skid}" ] && break
        sleep 5
    done
    [ -n "${_skid}" ] || { echo "    the certificate manager has not written an authority yet." >&2
                           echo "    Look at: podman logs ${_mgr}" >&2; exit 1; }
    { printf 'ROOT_ISSUER=%s\n' "${_skid:0:8}"
      printf 'ROOT_ISSUER_SKID=%s\n' "${_skid}"; } > "${topology_dir}/issuer_ids.env"
    cp "${topology_dir}/issuer_ids.env" .env

    # Every place that may ask for a certificate needs it, and a login shell resets the
    # environment, so the images read it back from this file rather than from the environment.
    for _svc in $(_compose config --services 2>/dev/null); do
        _c=$(podman ps --filter "label=com.docker.compose.service=${_svc}" --format '{{.Names}}' | head -1)
        [ -n "${_c}" ] || continue
        # As root: the images run their shells as an unprivileged user, and /etc is root's.
        podman exec --user root "${_c}" \
            bash -c 'mkdir -p /etc/epics && printf "%s" "$1" > /etc/epics/issuer' _ "${_skid}" \
            || echo "    could not give ${_svc} the issuer id" >&2
    done
fi

# shellcheck source=helpers.sh
. ./helpers.sh
lab_ids >/dev/null 2>&1 || true

if _has ml-manager; then
    echo "==> checking the facility root can be established"
    _check_responder
fi

echo "==> checking each certificate manager answers its administrator"
_check_managers

echo "==> checking reading works from everywhere"
_check_reads

echo "==> checking a write with no certificate is refused"
_check_refusals

echo
echo "The laboratory is running with no certificates issued."
# Named the way a shell names them, which is not how the file spells them.
# shellcheck source=helpers.sh
. ./helpers.sh
lab_ids_show
echo
if [ "${new_authorities}" = yes ]; then
    # A shell that read the old ones still holds them, and nothing here can reach into it.
    echo "These are new. A shell that already read the old ones still holds them, so in each"
    echo "one that has, run:"
    echo "    lab_ids"
    echo
fi
echo "The ${topology} laboratory is up with no certificates issued, and this much was just"
echo "checked:"
_has ml-manager && echo "    the responder answers for the facility root"
echo "    each certificate manager answers its administrator"
if _has perimeter; then
    echo "    reading works, from every department and from outside"
    echo "    a write with no certificate is refused, by the controller and at the boundary"
else
    echo "    reading works"
    echo "    a write with no certificate is refused by the controller"
fi
echo
echo "Follow 'Issue the certificates' to go on."
