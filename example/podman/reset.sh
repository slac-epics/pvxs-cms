#!/bin/bash
# Return the laboratory to the state it is in immediately after a fresh build, so a
# demonstration can be run from the top - and prove it before handing it back.
#
# The route is deliberately the blunt one: every container, every volume and every network
# the laboratory owns is destroyed and made again from the compose file. Nothing here knows
# which service keeps what where, so nothing here goes stale when a service changes.
#
# It ends by trying the things a demonstration depends on. If any of them fails, this exits
# non-zero and says where to look, rather than handing back a laboratory that looks up.
#
#   reset_topology <topology>                discard the certificates, keep the authorities
#   reset_topology --authorities <topology>  mint new authorities as well; the issuer ids change
#
# The topology names, and what each one is, are in topologies/topologies.env. Whichever one
# you name is the laboratory you get, and the walkthrough section of the same name is the one
# that applies to it.
#
set -euo pipefail
cd "$(dirname "$0")"

. topologies/topologies.env

_usage() {
    echo "usage: reset_topology [--authorities] <topology>" >&2
    echo "       reset_topology clear                  take the laboratory away, build nothing" >&2
    echo >&2
    echo "topologies:" >&2
    local t var
    for t in ${TOPOLOGY_NAMES}; do
        var="TOPOLOGY_${t//-/_}_TITLE"
        printf '    %-28s %s\n' "${t}" "${!var}" >&2
    done
    exit 2
}

new_authorities=no
topology=
for arg in "$@"; do
    case "${arg}" in
        --authorities) new_authorities=yes ;;
        -h|--help)     _usage ;;
        -*)            echo "reset_topology: no option '${arg}'" >&2; _usage ;;
        *)             [ -z "${topology}" ] || { echo "reset_topology: one topology at a time" >&2; _usage; }
                       topology="${arg}" ;;
    esac
done
[ -n "${topology}" ] || { echo "reset_topology: name a topology" >&2; _usage; }

# 'clear' is not a laboratory. It is the word for taking whichever one is up away and putting
# nothing in its place, for when the machine is wanted for something else - the Kubernetes
# laboratory runs on the same podman machine as this one and they are not small.
case " ${TOPOLOGY_NAMES} clear " in
    *" ${topology} "*) ;;
    *) echo "reset_topology: no topology called '${topology}'" >&2; _usage ;;
esac

# podman-compose names everything it makes after the directory this file sits in. The name is
# pinned rather than taken from the compose file's own directory, so every topology makes and
# destroys the same set and switching between them leaves nothing of the last one behind.
project=$(basename "$(pwd)")
compose_file="topologies/${topology}/compose.yaml"
if [ "${topology}" = clear ]; then
    _last=$(cat .topology 2>/dev/null || true)
    compose_file="topologies/${_last:-simple}/compose.yaml"
    [ -f "${compose_file}" ] || compose_file="topologies/simple/compose.yaml"
fi
_compose() { podman-compose -p "${project}" -f "${compose_file}" "$@"; }

# What is up, for helpers.sh to read: it decides from this which places run_in will accept.
[ "${topology}" = clear ] || printf '%s\n' "${topology}" > .topology

# A laboratory with more than one PVACMS has to be told which authority each one signs with,
# and the issuer ids have to exist before anything starts, so those topologies mint beside
# their own compose file. A laboratory with one PVACMS needs none of that: pvacms creates its
# own self-signed authority the first time it starts, and with only one of them the
# unqualified CERT:CREATE is unambiguous.
topology_dir="topologies/${topology}"
if [ "${topology}" = clear ]; then
    :   # nothing is being built, so nothing needs an authority
elif [ -x "${topology_dir}/mint.sh" ]; then
    if [ "${new_authorities}" = yes ] || [ ! -s "${topology_dir}/issuer_ids.env" ]; then
        "${topology_dir}/mint.sh"
    else
        echo "==> keeping the existing certificate authorities"
    fi
    # compose substitutes ${LAB_ISSUER} and the rest in the file itself, and reads .env from
    # the directory the compose file is in - not the one it is run from, whatever the run
    # command says. Without the second copy every substitution comes out empty, and an IOC
    # starts with no issuer to trust and can ask for nothing.
    cp "${topology_dir}/issuer_ids.env" .env
    cp "${topology_dir}/issuer_ids.env" "${topology_dir}/.env"
else
    echo "==> PVACMS will create its own authority when it starts"
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
    # Two things make this a loop over one container at a time rather than one command over
    # all of them:
    #
    #   depends_on makes a podman dependency, and 'podman rm -f' refuses a container another
    #   still depends on - so a single pass leaves behind exactly the services the others
    #   depend on, which for a laboratory being switched away from are its certificate
    #   PVACMS and its responder. Those then answer the next laboratory's searches, which
    #   looks like the new one misbehaving. --depend takes the dependents with it.
    #
    #   Removing one that way removes others named later in the same command, and podman
    #   stops at the first name that has gone rather than passing over it.
    local pass ids id
    for pass in 1 2 3; do
        ids=$(_containers)
        [ -n "${ids}" ] || return 0
        for id in ${ids}; do
            podman rm -f --depend "${id}" >/dev/null 2>&1 || true
        done
    done
}

_destroy_everything() {
    _destroy_containers
    # Said rather than assumed. Everything above hides its output, because most of what it
    # reports is a container that was already gone, and a laboratory built on top of another
    # one's leftovers fails later in ways that point at the wrong thing.
    local left; left=$(_containers)
    if [ -n "${left}" ]; then
        echo "    these containers could not be removed:" >&2
        podman ps -a --filter "label=io.podman.compose.project=${project}" \
                     --format '        {{.Names}}  {{.Status}}' >&2
        echo "    Remove them and run this again:" >&2
        echo "        podman rm -f --depend \$(podman ps -aq --filter label=io.podman.compose.project=${project})" >&2
        return 1
    fi
    local vols nets
    # shellcheck disable=SC2086
    vols=$(_volumes); [ -n "${vols}" ] && podman volume rm -f ${vols} >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    nets=$(_networks); [ -n "${nets}" ] && podman network rm -f ${nets} >/dev/null 2>&1 || true
    return 0
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
# Each laboratory is checked for what it has: a responder, a second department and an
# internet belong to some topologies only.
_places=$(eval "printf '%s' \"\${TOPOLOGY_${topology//-/_}_PLACES:-}\"")
_has() { case " ${_places} " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# A responder answers for a root that names one, and only a laboratory with a facility root
# has one to answer for. Asked of the compose file rather than of a list kept in step by hand,
# because the compose file is what decides whether the container exists.
_has_responder() { _compose config --services 2>/dev/null | grep -q -- '-authority-status'; }

# Whether the boundary carries TLS and nothing else, which changes what a workstation outside it
# can do before anything has been handed to it: with no plaintext listener to answer, it cannot
# read, and it cannot be refused a write either, because it cannot get far enough to be told no.
# Asked of the gateway configuration rather than of a list kept in step by hand, for the same
# reason as the responder above: that file is what decides the answer.
_boundary_is_tls_only() {
    grep -q '"EPICS_PVAS_SERVER_PORT"[[:space:]]*:[[:space:]]*"\(NO\|no\|off\|false\|disabled\)"' \
         "topologies/${topology}/config/gateway.conf" 2>/dev/null
}

# Each returns non-zero and says where to look. They ask the laboratory the same questions a
# person would, rather than inspecting anything's insides.

_check_responder() {
    # The authority has to be establishable before anything can be issued. A laboratory that
    # looks up but cannot establish it is the worst state to hand back.
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
    # Each PVACMS answering its own administrator is the first thing a demonstration needs,
    # and the thing that fails when the facility root cannot be established.
    local ok=no
    for _ in $(seq 1 18); do
        if run_in lab-pvacms as admin pvxcert -l >/dev/null 2>&1 \
        && { ! _has ml-pvacms || run_in ml-pvacms as admin pvxcert -l >/dev/null 2>&1; }; then
            ok=yes; break
        fi
        sleep 5
    done
    [ "${ok}" = yes ] && return 0
    echo "    a PVACMS will not answer its administrator." >&2
    echo "    That is what a facility root nobody can establish looks like. Look at:" >&2
    echo "        podman logs \$(podman ps --format '{{.Names}}' | grep pvacms)" >&2
    return 1
}

_check_reads() {
    local ok=no
    for _ in $(seq 1 18); do
        # Each line is guarded by what it needs, which is a place to ask from AND a
        # an IOC to answer. ml:aiExample needs the ML department's IOC however many other
        # places a laboratory has. The two that cross departments are here
        # because they are the ones nothing else covers: a workstation reaches the peer
        # department by the facility address, and that name has to be answerable where it
        # is asked as well as reachable, which are two different things to get wrong.
        if run_in lab as guest without a certificate pvxget test:aiExample >/dev/null 2>&1 \
        && { ! _has ml-ioc    || run_in ml        as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1; } \
        && { ! _has ml-ioc    || run_in lab       as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1; } \
        && { ! _has ml        || run_in ml        as guest without a certificate pvxget test:aiExample >/dev/null 2>&1; } \
        && { ! _has internet || _boundary_is_tls_only \
                              || run_in internet as guest without a certificate pvxget test:aiExample >/dev/null 2>&1; } \
        && { ! _has internet || _boundary_is_tls_only || ! _has ml-ioc \
                              || run_in internet as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1; }; then
            ok=yes; break
        fi
        sleep 5
    done
    [ "${ok}" = yes ] && return 0
    echo "    reading does not work from everywhere yet." >&2
    echo "    Try them one at a time to see which:" >&2
    echo "        run_in lab as guest without a certificate pvxget test:aiExample" >&2
    _has ml-ioc    && echo "        run_in ml        as guest without a certificate pvxget ml:aiExample" >&2
    _has ml-ioc    && echo "        run_in lab       as guest without a certificate pvxget ml:aiExample" >&2
    _has ml        && echo "        run_in ml        as guest without a certificate pvxget test:aiExample" >&2
    _has internet && ! _boundary_is_tls_only \
                   && echo "        run_in internet as guest without a certificate pvxget test:aiExample" >&2
    _has internet && ! _boundary_is_tls_only && _has ml-ioc \
                   && echo "        run_in internet as guest without a certificate pvxget ml:aiExample" >&2
    return 1
}

_says() { # _says <expected text> <command...>   - true when the output contains the text
    # The output is captured before it is searched: these commands are expected to fail.
    local want="$1"; shift
    local out; out=$("$@" 2>&1 || true)
    printf '%s' "${out}" | grep -q -- "${want}"
}

_check_refusals() {
    # Nothing holds a certificate at this point, so what can be checked is that the laboratory
    # refuses a write, and refuses it in the right place: by the IOC in its own department,
    # and at the boundary from outside it.
    if ! _says 'Put not permitted' \
         run_in lab as guest without a certificate pvxput test:stringExample hello; then
        echo "    a request with no certificate was not refused by the IOC." >&2
        return 1
    fi
    # A boundary carrying TLS alone refuses earlier and more bluntly: a workstation that has been
    # handed nothing cannot verify what answers, so it never gets far enough to be told no about
    # a particular variable. What is checked there is that it cannot get in at all, which is the
    # state the walkthrough starts from before the authority is carried across.
    if _has internet && _boundary_is_tls_only; then
        if run_in internet as guest without a certificate pvxget test:aiExample >/dev/null 2>&1; then
            echo "    the boundary carries TLS alone, but a workstation holding nothing read across it." >&2
            return 1
        fi
        return 0
    fi
    if _has internet && ! _says 'denied by gateway' \
         run_in internet as guest without a certificate pvxput test:stringExample hello; then
        echo "    a request with no certificate was not refused at the boundary." >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------- do it
echo "==> destroying the laboratory: containers, volumes, networks"
_destroy_everything

if [ "${topology}" = clear ]; then
    rm -f .topology .env
    echo "    every container, volume and network this laboratory made is gone."
    echo "    The Kubernetes laboratory, if it is up, is not: it runs inside its own"
    echo "    container on the same podman machine. Take it away with 'kreset_topology clear'."
    exit 0
fi

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

# A laboratory whose PVACMS mints its own authority does not know its issuer id
# until that has happened. Nothing may trust an authority it was told about over the channel
# it is trying to establish, so a client refuses to ask until it has been given the id out of
# band - which is what this does, once the authority exists.
if [ ! -x "${topology_dir}/mint.sh" ]; then
    echo "==> reading the issuer id from the authority PVACMS made"
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
    [ -n "${_skid}" ] || { echo "    PVACMS has not written an authority yet." >&2
                           echo "    Look at: podman logs ${_mgr}" >&2; exit 1; }
    { printf 'ROOT_ISSUER=%s\n' "${_skid:0:8}"
      printf 'ROOT_ISSUER_SKID=%s\n' "${_skid}"; } > "${topology_dir}/issuer_ids.env"
    cp "${topology_dir}/issuer_ids.env" .env

    # Every place that may ask for a certificate needs it, and a login shell resets the
    # environment, so the images read it back from this file rather than from the environment.
    for _svc in $(_compose config --services 2>/dev/null); do
        _c=$(podman ps --filter "label=com.docker.compose.service=${_svc}" --format '{{.Names}}' | head -1)
        [ -n "${_c}" ] || continue
        # As root, because the images run their shells as an unprivileged user and /etc is
        # root's. sh, and only where EPICS is installed.
        podman exec --user root "${_c}" sh -c '
            [ -d /opt/epics ] || exit 0
            mkdir -p /etc/epics && printf "%s" "$1" > /etc/epics/issuer' _ "${_skid}" \
            || echo "    could not give ${_svc} the issuer id" >&2
    done
fi

# shellcheck source=helpers.sh
. ./helpers.sh
lab_ids >/dev/null 2>&1 || true

# A gateway makes its upstream connections when it starts and does not retry the ones it
# could not make, so one that came up before the IOCs were serving forwards nothing
# until it is restarted. Everything is up by now, so this is where that is put right.
_gateways=$(podman ps --format '{{.Names}}' | grep -- '-gateway' || true)
if [ -n "${_gateways}" ]; then
    echo "==> restarting the gateways, now that the IOCs are serving"
    # shellcheck disable=SC2086
    podman restart ${_gateways} >/dev/null 2>&1 || true
    sleep 8
fi

if _has_responder; then
    echo "==> checking the facility root can be established"
    _check_responder
fi

echo "==> checking each PVACMS answers its administrator"
_check_managers

echo "==> checking reading works from everywhere"
_check_reads

echo "==> checking a write with no certificate is refused"
_check_refusals

echo
lab_ids_show
echo
if [ "${new_authorities}" = yes ]; then
    # The shell that ran reset_topology has them already, because reset_topology reads them as
    # soon as this returns. Any other shell that read the old ones still holds them, and nothing
    # here can reach into one of those.
    echo "These are new. run:"
    echo "    lab_ids"
    echo
fi
echo "The ${topology} topology is up:"
echo "    one laboratory with two IOCs and its own PVACMS,"
if _has internet; then
  if _boundary_is_tls_only; then
      echo "    internet zone connects via a tls-only gateway,"
      echo "    one root CA"
  else
      echo "    one ML center with one ML IOC and its own PVACMS,"
      if _has_responder ; then
      echo "    internet zone connects via facility name and port,"
      echo "    ports 5075-5076 map to laboratory gateway and 5175-5176 map to ML gateway,"
      echo "    inter-department traffic via peer's facility port mapping,"
      echo "    one shared root CA referencing an external OCSP responder,"
      echo "    separate intermediate CA for each department"
      else
      echo "    internet zone connects directly to laboratory and ML gateways on 5075-5076,"
      echo "    inter-department traffic via peer gateway,"
      echo "    separate independent root CA for each department,"
      echo "    one intermediate CA for laboratory"
      fi
  fi
else
    echo "    one root CA"
fi
echo
# Each laboratory has one part of the README to itself, and the walkthrough in another part
# names places this one may not have.
case "${topology}" in
    simple)                    _part="Part 1 - simple" ;;
    simple-with-gateway)       _part="Part 2 - simple, with a gateway" ;;
    federated-shared-root)     _part="Part 3 - federated, one facility root" ;;
    federated-non-shared-root) _part="Part 4 - federated, two independent roots" ;;
    *)                         _part="the part of README.md named after this laboratory" ;;
esac
echo "See '${_part}' in README.md"
