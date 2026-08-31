# Shorthands for the demonstration laboratory:
#
#     source ./khelpers.sh
#
# Then:
#
#     krun_in lab         as guest    pvxget test:aiExample
#     krun_in lab-pvacms  as admin    pvxcert -l --where "state:VALID and type:IOC"
#     krun_in ml          as operator pvxput ml:aiExample 42
#     krun_in internet    as guest without a certificate  pvxget test:aiExample
#     krun_in testioc     as testioc  authnstd -u ioc
#
# Every shorthand can show the command it stands for instead of running it:
#
#     krun_in lab-pvacms as admin --show pvxcert -l
#
# Several commands as one person:
#
#     krun_in lab-pvacms as admin <<'EOF'
#         pvxcert -l
#         pvxcert -l --where "state:VALID"
#     EOF
#
# `krun_in` on its own lists every place and person.

# ------------------------------------------------------------------------ where things are
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

KLAB_NS="${KLAB_NS:-spva-lab}"
KLAB_RELEASE="${KLAB_RELEASE:-spva-lab}"
KLAB_CLUSTER="${KLAB_CLUSTER:-spva-lab}"
KLAB_CONTEXT="${KLAB_CONTEXT:-kind-${KLAB_CLUSTER}}"
KLAB_CILIUM="${KLAB_CILIUM:-1.16.5}"

KLAB_DIR="${KLAB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]:-${(%):-%x}}")" 2>/dev/null && pwd)}"

_k() { kubectl --context "${KLAB_CONTEXT}" -n "${KLAB_NS}" "$@"; }

# Which container runtime kind builds the cluster on.
#
# Docker is preferred where a real daemon is running.
_klab_pick_runtime() {
    KLAB_DOCKER=; KLAB_RUNTIME=
    # Wherever a docker command may be, whichever platform this is. The one on PATH is
    # tried first.
    local d=
    for d in "$(command -v docker 2>/dev/null)" \
             /usr/local/bin/docker "${HOME}/.docker/bin/docker" \
             /Applications/Docker.app/Contents/Resources/bin/docker; do
        [ -n "${d}" ] && [ -x "${d}" ] || continue
        # podman reports "docker version" through a docker symlink, so ask the daemon for a
        # field only Docker has. kind runs whichever docker is first on PATH, so put this one there.
        if "${d}" info --format '{{.DockerRootDir}}' >/dev/null 2>&1; then
            KLAB_DOCKER="${d}"; KLAB_RUNTIME=docker
            [ "$(command -v docker 2>/dev/null)" = "${d}" ] || { PATH="$(dirname "${d}"):${PATH}"; export PATH; }
            unset KIND_EXPERIMENTAL_PROVIDER
            return 0
        fi
    done
    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        KLAB_RUNTIME=podman
        KIND_EXPERIMENTAL_PROVIDER=podman; export KIND_EXPERIMENTAL_PROVIDER
        return 0
    fi
    echo "no container runtime: neither a Docker daemon nor podman answered" >&2
    return 1
}
_klab_pick_runtime >/dev/null 2>&1 || true

# --------------------------------------------------------------------------------- the cluster

kind_create() {
    command -v kind >/dev/null 2>&1 || { echo "kind not found. brew install kind" >&2; return 1; }
    if kind get nodes --name "${KLAB_CLUSTER}" 2>/dev/null | grep -q .; then
        echo "==> cluster ${KLAB_CLUSTER} is already there"
    else
        echo "==> creating the cluster on ${KLAB_RUNTIME}, with the default CNI turned off"
        kind create cluster --config "${KLAB_DIR}/kind-cluster.yaml" || return 1
    fi
    # The segments in this laboratory are NetworkPolicy. Use cilium CNI rather than Calico
    if ! kubectl --context "${KLAB_CONTEXT}" get daemonset cilium -n kube-system >/dev/null 2>&1; then
        echo "==> installing Cilium ${KLAB_CILIUM}"
        helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
        helm repo update >/dev/null 2>&1 || true
        helm --kube-context "${KLAB_CONTEXT}" install cilium cilium/cilium \
            --version "${KLAB_CILIUM}" --namespace kube-system \
            --set image.pullPolicy=IfNotPresent \
            --set ipam.mode=kubernetes \
            --set operator.replicas=1 \
            --set hubble.relay.enabled=true \
            --set hubble.ui.enabled=true >/dev/null || return 1
    fi
    kubectl --context "${KLAB_CONTEXT}" rollout status daemonset/cilium -n kube-system --timeout=300s || return 1
    echo "==> the cluster is ready"
}

kind_delete() { kind delete cluster --name "${KLAB_CLUSTER}"; }

# Build the images every laboratory is made from. The script is shared with the podman
# laboratory and lives one directory up; after building, kload_images carries them into
# the cluster.
kbuild_images() {
    JOBS="${JOBS:-}" CONTAINER_ENGINE="${KLAB_RUNTIME:-docker}" "${KLAB_DIR}/../bootstrap.sh" "$@"
}

# Carries the built images into the cluster.
kload_images() {
    local reg="${DOCKER_REGISTRY:-localhost}" usr="${DOCKER_USERNAME:-spva}" tag="${KLAB_TAG:-latest}"
    local role tar ref
    # Pulled dependencies:
    # the facility load balancer, and
    # the kubectl that the minting job packages its output with.
    local externals="docker.io/library/haproxy:lts-alpine docker.io/bitnami/kubectl:latest"

    if [ "${KLAB_RUNTIME}" = docker ]; then
        # The cluster runs on Docker, and kind reads the Docker daemon directly
        for role in idm ml testioc tstioc ml-ioc lab gateway internet; do
            printf '    %-10s' "${role}"
            if err=$(kind load docker-image --name "${KLAB_CLUSTER}" "${reg}/${usr}/${role}:${tag}" 2>&1); then
                echo "loaded"
            else
                echo "FAILED: $(printf '%s' "${err}" | grep -v '^enabling' | tail -1)"
            fi
        done
        echo "    externals ($(echo ${externals} | wc -w | tr -d ' ')): pulled by the cluster on first use"
        return 0
    fi

    # The cluster runs on podman.
    for role in idm ml testioc tstioc ml-ioc lab gateway internet; do
        tar="${TMPDIR:-/tmp}/klab-${role}.tar"
        printf '    %-10s' "${role}"
        if err=$( { podman save "${reg}/${usr}/${role}:${tag}" -o "${tar}" \
                    && kind load image-archive --name "${KLAB_CLUSTER}" "${tar}"; } 2>&1 ); then
            echo "loaded"
        else
            echo "FAILED: $(printf '%s' "${err}" | grep -v '^enabling' | tail -1)"
        fi
        rm -f "${tar}"
    done
    for ref in ${externals}; do
        tar="${TMPDIR:-/tmp}/klab-ext.tar"
        printf '    %-14s' "$(basename "${ref}")"
        podman pull "${ref}" >/dev/null 2>&1 || true
        if podman save "${ref}" -o "${tar}" >/dev/null 2>&1 \
           && kind load image-archive --name "${KLAB_CLUSTER}" "${tar}" >/dev/null 2>&1; then
            echo "loaded"
        else
            echo "not loaded - the cluster will try to pull it"
        fi
        rm -f "${tar}"
    done
}

# ---------------------------------------------------------------------------------- the places

# Which laboratory is up.
_klab_topology() { cat "${KLAB_DIR}/.ktopology" 2>/dev/null; }

_klab_place() {         # place -> deployment
    case "$1" in
        lab)                echo lab-client ;;
        ml)                 echo ml-client ;;
        internet)           echo internet-client ;;
        lab-pvacms)         echo pvxs-lab-pvacms ;;
        ml-pvacms)          echo pvxs-lab-ml-pvacms ;;
        testioc)            echo pvxs-lab-testioc ;;
        tstioc)             echo pvxs-lab-tstioc ;;
        ml-ioc)             echo pvxs-lab-ml-ioc ;;
        gateway)            echo pvxs-lab-gateway ;;
        ml-gateway)         echo pvxs-lab-ml-gateway ;;
        responder)          echo pvxs-lab-ocsp-responder ;;
        facility)           echo pvxs-facility-lb ;;
        *) return 1 ;;
    esac
}

_klab_app() {           # place -> the app label, which is what selects a pod
    case "$1" in
        lab)                echo lab-client ;;
        ml)                 echo ml-client ;;
        internet)           echo internet-client ;;
        lab-pvacms)         echo pvacms ;;
        ml-pvacms)          echo ml ;;
        testioc)            echo testioc ;;
        tstioc)             echo tstioc ;;
        ml-ioc)             echo ml-ioc ;;
        gateway)            echo gateway ;;
        ml-gateway)         echo ml-gateway ;;
        responder)          echo ocsp-responder ;;
        facility)           echo facility ;;
        *) return 1 ;;
    esac
}

_klab_places() {
    case "$(_klab_topology)" in
        simple)                    echo "lab lab-pvacms testioc tstioc" ;;
        simple-with-gateway)       echo "lab internet lab-pvacms testioc tstioc gateway facility" ;;
        federated-shared-root)     echo "lab ml internet lab-pvacms ml-pvacms testioc tstioc ml-ioc gateway ml-gateway responder facility" ;;
        federated-non-shared-root) echo "lab ml internet lab-pvacms ml-pvacms testioc tstioc ml-ioc gateway ml-gateway" ;;
        *) return 1 ;;
    esac
}

# The program supervisord runs, for the restart that puts back only the program.
_klab_program() {
    case "$1" in
        testioc) echo testioc ;;
        tstioc)  echo tstioc ;;
        *) return 1 ;;
    esac
}

# --------------------------------------------------------------------------------- krun_in

krun_in() {
    if [ "$#" -eq 0 ] || [ "$1" = --help ]; then
        echo "usage: krun_in <place> as <person> [without a certificate] [--show] <command...>"
        echo "       krun_in <place> as <person>            with no command, opens a shell there"
        return 2
    fi

    local place="$1" who="$3" plain=no show="${KRUN_IN_SHOW:-no}"
    if [ "$2" != as ] || [ -z "${who}" ]; then
        echo "krun_in: say it as: krun_in <place> as <person> <command...>" >&2; return 2
    fi
    shift 3

    # A person may be written <department>/<user>, which is the same user holding a
    # certificate from that department rather than from the one they are sitting in. It
    # reads as what it is - "ml/operator in lab" is the ML operator, at a lab
    # workstation - and it needs a keychain of its own, since the two certificates cannot
    # share one file. Anything without a slash is unchanged.
    local from_dept= keychain_name=client
    case "${who}" in
        */*) from_dept="${who%%/*}"; who="${who##*/}"; keychain_name="${from_dept}" ;;
    esac
    if [ -n "${from_dept}" ] && [ "${from_dept}" != lab ] && [ "${from_dept}" != ml ]; then
        echo "krun_in: no department called '${from_dept}'. Write lab/<user> or ml/<user>." >&2
        return 2
    fi

    while [ "$#" -gt 0 ]; do
        case "$1" in
            without) [ "$2" = a ] && [ "$3" = certificate ] || {
                         echo "krun_in: did you mean 'without a certificate'?" >&2; return 2; }
                     plain=yes; shift 3 ;;
            --show)  show=yes; shift ;;
            *)       break ;;
        esac
    done

    local deploy places
    if ! deploy=$(_klab_place "${place}"); then
        echo "krun_in: no place called '${place}'." >&2
        echo "        Places: lab ml internet lab-pvacms ml-pvacms testioc tstioc ml-ioc gateway ml-gateway" >&2
        return 2
    fi

    # A real place, but one this laboratory has none of: say which is up and what it does have.
    if places=$(_klab_places); then
        case " ${places} " in
            *" ${place} "*) ;;
            *) echo "krun_in: the $(_klab_topology) laboratory has no '${place}'." >&2
               echo "        It has: ${places}" >&2
               echo "        Another one does: kreset_topology <topology>" >&2
               return 2 ;;
        esac
    fi

    # The administrator must run in a pvacms node in this demo.
    if [ "${who}" = admin ] && [ "${place}" != lab-pvacms ] && [ "${place}" != ml-pvacms ]; then
        echo "krun_in: the administrator's identity lives on the PVACMS node, not at ${place}" >&2
        case "${place}" in
            lab|ml) echo "        Write: run_in ${place}-pvacms as admin ..." >&2 ;;
            *)      echo "        Write: run_in lab-pvacms as admin ...  (or ml-pvacms)" >&2 ;;
        esac
        return 2
    fi

    local script
    if [ "$#" -gt 0 ]; then
        script=$(printf '%q ' "$@")
    else
        script='exec bash -i'
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
source ~/.${who}_bashrc 2>/dev/null
unset EPICS_PVA_ADDR_LIST EPICS_PVA_AUTO_ADDR_LIST EPICS_PVA_NAME_SERVERS EPICS_PVA_TLS_OPTIONS
[ -r /tmp/.pva-pod-env ] && . /tmp/.pva-pod-env
export EPICS_PVA_TLS_KEYCHAIN=\${HOME}/.config/pva/1.5/${keychain_name}.p12
${prelude}
" ;;
        *)
            prelude="
source ~/.${who}_bashrc 2>/dev/null
unset EPICS_PVA_ADDR_LIST EPICS_PVA_AUTO_ADDR_LIST EPICS_PVA_NAME_SERVERS EPICS_PVA_TLS_OPTIONS
[ -r /tmp/.pva-pod-env ] && . /tmp/.pva-pod-env
${prelude}
" ;;
    esac

    script="${prelude}export PVXS_LOG=\${PVXS_LOG:-none}
${script}"

    # A terminal.
    local tty=
    [ -t 0 ] && [ -t 1 ] && tty=-it

    if [ "${show}" = yes ]; then
        case "${who}" in
            admin) echo "kubectl -n ${KLAB_NS} exec ${tty} deploy/${deploy} -- bash -lc '${script}'" ;;
            *)     echo "kubectl -n ${KLAB_NS} exec ${tty} deploy/${deploy} -- su - ${who} -c '${script}'" ;;
        esac
        return 0
    fi

    # The pods run as root then `su` to given person. The administrator is the
    # exception.
    case "${who}" in
        admin) _k exec ${tty} "deploy/${deploy}" -- bash -lc "${script}" ;;
        *)     _k exec ${tty} "deploy/${deploy}" -- bash -c \
                   'export -p | grep -E "EPICS_PVA" > /tmp/.pva-pod-env 2>/dev/null
                    chmod 0644 /tmp/.pva-pod-env 2>/dev/null
                    exec su - "$1" -c "$2"' _ "${who}" "${script}" ;;
    esac
}

# --------------------------------------------------------------------------------- krestart
#

krestart() {
    local place="$1" what="${2:-program}"
    if [ -z "${place}" ]; then
        echo "usage: krestart <place> [pod|service]" >&2
        echo "       krestart testioc          the softIoc alone, inside the running pod" >&2
        echo "       krestart testioc pod      delete the pod and let it be replaced" >&2
        echo "       krestart testioc service  roll the deployment behind the Service" >&2
        return 2
    fi

    local deploy app
    deploy=$(_klab_place "${place}") || { echo "krestart: no place called '${place}'." >&2; return 2; }
    app=$(_klab_app "${place}")

    case "${what}" in
        pod)
            echo "==> deleting the ${place} pod"
            _k delete pod -l "app=${app}" --wait=false || return 1
            _k rollout status "deploy/${deploy}" --timeout=180s
            ;;
        service)
            echo "==> rolling the ${place} deployment"
            _k rollout restart "deploy/${deploy}" || return 1
            _k rollout status "deploy/${deploy}" --timeout=180s
            ;;
        program|ioc|softioc)
            local program
            if ! program=$(_klab_program "${place}"); then
                echo "krestart: ${place} runs no program that can be restarted on its own." >&2
                echo "        Try: krestart ${place} pod" >&2
                return 2
            fi
            echo "==> restarting the ${program} softIoc"
            _k exec "deploy/${deploy}" -- supervisorctl restart "${program}"
            ;;
        *)
            echo "krestart: '${what}' is not one of pod, service, or nothing at all." >&2
            return 2 ;;
    esac
}

# ---------------------------------------------------------------------------- kreset_topology

# The laboratories, and which of them are built here. One list, so the usage text and the
# check below cannot disagree about what exists.
KLAB_TOPOLOGIES="simple simple-with-gateway federated-shared-root federated-non-shared-root"

_kreset_usage() {
    echo "usage: kreset_topology <topology>" >&2
    echo "       kreset_topology clear [--cluster]   take the laboratory away, build nothing" >&2
    echo >&2
    echo "topologies:" >&2
    echo "    simple                  one department, two IOCs and a workstation, and" >&2
    echo "                            nothing between them" >&2
    echo "    simple-with-gateway     one department, a gateway on a TLS-only boundary," >&2
    echo "                            and a workstation outside it" >&2
    echo "    federated-shared-root   two departments under one facility root, each with its" >&2
    echo "                            own certificate manager, IOCs and gateway" >&2
    echo "    federated-non-shared-root  two departments under two independent roots, with" >&2
    echo "                            both roots held as trust anchors in every keychain" >&2
    return 2
}

kreset_topology() {
    if [ "$#" -eq 0 ] || [ "$1" = -h ] || [ "$1" = --help ]; then
        _kreset_usage; return 2
    fi
    local topology="$1"

    if [ "${topology}" = clear ]; then
        echo "==> destroying the laboratory"
        helm --kube-context "${KLAB_CONTEXT}" -n "${KLAB_NS}" uninstall "${KLAB_RELEASE}" >/dev/null 2>&1 || true
        kubectl --context "${KLAB_CONTEXT}" delete namespace "${KLAB_NS}" --wait=true >/dev/null 2>&1 || true
        if [ "${2:-}" = --cluster ] || [ "${2:-}" = cluster ]; then
            echo "==> deleting the cluster"
            kind_delete
            echo "    the cluster is gone. Building again needs kind_create and kload_images."
        else
            echo "    the laboratory is gone. The cluster is still there, which is one container"
            echo "    on the docker machine: 'kreset_topology clear --cluster' takes that too."
        fi
        return 0
    fi

    case " ${KLAB_TOPOLOGIES} " in
        *" ${topology} "*) ;;
        *) echo "kreset_topology: no topology called '${topology}' is built here." >&2
           _kreset_usage; return 2 ;;
    esac
    local chart="${KLAB_DIR}/helm/${topology}"

    echo "==> destroying the laboratory"
    helm --kube-context "${KLAB_CONTEXT}" -n "${KLAB_NS}" uninstall "${KLAB_RELEASE}" >/dev/null 2>&1 || true
    # The workloads are taken down explicitly.
    _k delete deploy,job --all --wait=false >/dev/null 2>&1 || true
    _k wait --for=delete pod --all --timeout=180s >/dev/null 2>&1 || true
    _k delete pvc --all --wait=true --timeout=120s >/dev/null 2>&1 || true
    _k delete configmap lab-issuer lab-issuer-ids ocsp-index-seed >/dev/null 2>&1 || true
    _k delete secret lab-intermediate ml-intermediate ml-root trust-anchors ocsp-material >/dev/null 2>&1 || true

    echo "==> building the laboratory"
    kubectl --context "${KLAB_CONTEXT}" create namespace "${KLAB_NS}" >/dev/null 2>&1 || true
    helm --kube-context "${KLAB_CONTEXT}" -n "${KLAB_NS}" upgrade --install \
        "${KLAB_RELEASE}" "${chart}" \
        --set namespace="${KLAB_NS}" \
        --set dockerRegistry="${DOCKER_REGISTRY:-localhost}" \
        --set dockerUsername="${DOCKER_USERNAME:-spva}" \
        --wait --timeout 5m || return 1

    printf '%s\n' "${topology}" > "${KLAB_DIR}/.ktopology"

    echo "==> waiting for the certificate managers"
    _k rollout status deploy/pvxs-lab-pvacms --timeout=180s || return 1
    case "${topology}" in
      federated-*)
        _k rollout status deploy/pvxs-lab-ml-pvacms --timeout=180s || return 1 ;;
    esac
    if [ "${topology#federated-}" != "${topology}" ]; then
        :
    else
        # Only a laboratory whose PVACMS mints its own authority has an issuer id that does
        # not exist yet. The federated ones are minted before anything starts.
        _kread_issuer || return 1
    fi

    # Make sure gateway start after IOCs are started.
    echo "==> restarting the gateways, now that the IOCs are started"
    local g
    for g in $(_k get deploy -o name 2>/dev/null | grep -- '-gateway' || true); do
        _k rollout restart "${g}" >/dev/null 2>&1 || true
    done
    for g in $(_k get deploy -o name 2>/dev/null | grep -- '-gateway' || true); do
        _k rollout status "${g}" --timeout=180s >/dev/null 2>&1 || true
    done

    if [ "${topology}" = federated-non-shared-root ]; then
        _kcheck_managers_federated && _kcheck_reads_federated \
            && _kcheck_refusals_federated || return 1
        klab_ids
        printf '\n    $LAB      %s\n    $ML       %s\n' "${LAB}" "${ML}"
        printf '    $LAB_SKID %s\n    $ML_SKID  %s\n' "${LAB_SKID}" "${ML_SKID}"
    elif [ "${topology}" = federated-shared-root ]; then
        _kcheck_responder && _kcheck_managers_federated && _kcheck_reads_federated \
            && _kcheck_refusals_federated || return 1
        klab_ids
        printf '\n    $LAB      %s\n    $ML       %s\n' "${LAB}" "${ML}"
        printf '    $LAB_SKID %s\n    $ML_SKID  %s\n' "${LAB_SKID}" "${ML_SKID}"
    else
        _kcheck_manager && _kcheck_reads && _kcheck_refusals || return 1
        klab_ids
        printf '\n    $ROOT      %s\n    $ROOT_SKID %s\n' "${ROOT}" "${ROOT_SKID}"
    fi
    if [ "${topology}" = federated-non-shared-root ]; then
        cat <<'DONE'

The federated-non-shared-root laboratory is up:
    one laboratory with two IOCs and its own PVACMS,
    one ML center with one ML IOC and its own PVACMS,
    internet zone connects directly to laboratory and ML gateways on 5075-5076,
    inter-department traffic via peer gateway,
    separate independent root CA for each department,
    one intermediate CA for laboratory
DONE
    elif [ "${topology}" = federated-shared-root ]; then
        cat <<'DONE'

The federated-shared-root laboratory is up:
    one laboratory with two IOCs and its own PVACMS,
    one ML center with one ML IOC and its own PVACMS,
    internet zone connects via facility name and port,
    ports 5075-5076 map to laboratory gateway and 5175-5176 map to ML gateway,
    inter-department traffic via peer's facility port mapping,
    one shared root CA referencing an external OCSP responder,
    separate intermediate CA for each department
DONE
    elif [ "${topology}" = simple ]; then
        cat <<'DONE'

The simple laboratory is up:
    one laboratory with two IOCs and its own PVACMS,
DONE
    else
        cat <<'DONE'

The simple-with-gateway laboratory is up:
    one laboratory with two IOCs and its own PVACMS,
    internet zone connects via a tls-only gateway,
    one root CA
DONE
    fi
}

# The issuer ID does not exist until the certificate manager has minted its authority,
# so it is read back afterwards and handed to every pod. A login shell resets the environment,
# so the images read it from a file rather than from the environment.
_kread_issuer() {
    echo "==> reading the issuer id from the authority the certificate manager made"
    local skid= i
    for i in $(seq 1 18); do
        skid=$(_k exec deploy/pvxs-lab-pvacms -- bash -c '
            # Beside the database when the manager minted its own authority, under
            # /etc/pvacms when one was installed at start.
            k=$(dirname "${EPICS_PVACMS_DB}")/cert_auth.p12
            [ -s "$k" ] || k=/etc/pvacms/cert_auth.p12
            [ -s "$k" ] || exit 1
            openssl pkcs12 -in "$k" -nokeys -passin pass: 2>/dev/null \
              | openssl x509 -noout -ext subjectKeyIdentifier 2>/dev/null \
              | tail -1 | tr -d " :" | tr "A-F" "a-f"' 2>/dev/null) && [ -n "${skid}" ] && break
        sleep 5
    done
    if [ -z "${skid}" ]; then
        echo "    the certificate manager has not minted an authority." >&2
        echo "        kubectl -n ${KLAB_NS} logs deploy/pvxs-lab-pvacms" >&2
        return 1
    fi
    _k create configmap lab-issuer --from-literal=issuer="${skid}" \
        --dry-run=client -o yaml | _k apply -f - >/dev/null

    # The pods mount that ConfigMap at /etc/epics, but it did not exist when they started, so
    # they are rolled onto it
    echo "==> handing the issuer id to every pod"
    local d=
    _k get deploy -o name 2>/dev/null | while read -r d; do
        [ -n "${d}" ] && _k rollout restart "${d}" >/dev/null 2>&1 || true
    done
    _k get deploy -o name 2>/dev/null | while read -r d; do
        [ -n "${d}" ] || continue
        _k rollout status "${d}" --timeout=180s >/dev/null 2>&1 \
            || echo "    ${d} did not come back" >&2
    done
    local i=0 seen=
    for i in $(seq 1 12); do
        seen=$(_k exec deploy/lab-client -- cat /etc/epics/issuer 2>/dev/null || true)
        [ "${seen}" = "${skid}" ] && break
        sleep 5
    done
    if [ "${seen}" != "${skid}" ]; then
        echo "    the issuer id has not reached the workstation yet." >&2
        echo "    Expected ${skid}, found ${seen:-nothing}." >&2
        return 1
    fi

    KLAB_ROOT_ISSUER="${skid:0:8}"; KLAB_ROOT_ISSUER_SKID="${skid}"
    export KLAB_ROOT_ISSUER KLAB_ROOT_ISSUER_SKID
}

# This laboratory's issuer identifiers.
klab_ids() {
    LAB=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.LAB_ISSUER}' 2>/dev/null)
    ML=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.ML_ISSUER}' 2>/dev/null)
    LAB_SKID=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.LAB_ISSUER_SKID}' 2>/dev/null)
    ML_SKID=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.ML_ISSUER_SKID}' 2>/dev/null)
    # A laboratory with one authority names it $ROOT, and has no departments.
    ROOT_SKID=$(_k get configmap lab-issuer -o jsonpath='{.data.issuer}' 2>/dev/null)
    ROOT="${ROOT_SKID:0:8}"
    export LAB ML LAB_SKID ML_SKID ROOT ROOT_SKID
    [ -n "${LAB}${ROOT}" ] || { echo "no issuer identifiers yet - run kreset_topology <topology> first" >&2; return 1; }
}

# ------------------------------------------------------------------------------- the checks
#

_kcheck_manager() {
    echo "==> checking the certificate manager answers its administrator"
    local i=0
    for i in $(seq 1 18); do
        krun_in lab-pvacms as admin pvxcert -l >/dev/null 2>&1 && return 0
        sleep 5
    done
    echo "    the certificate manager will not answer its administrator." >&2
    echo "        kubectl -n ${KLAB_NS} logs deploy/pvxs-lab-pvacms" >&2
    return 1
}

_kcheck_reads() {
    echo "==> checking reading works inside the laboratory"
    local i=0
    for i in $(seq 1 18); do
        krun_in lab as guest without a certificate pvxget test:aiExample >/dev/null 2>&1 && return 0
        sleep 5
    done
    echo "    reading does not work yet. Try it on its own:" >&2
    echo "        krun_in lab as guest without a certificate pvxget test:aiExample" >&2
    return 1
}

_kcheck_refusals() {
    echo "==> checking a write with no certificate is refused"
    local out
    out=$(krun_in lab as guest without a certificate pvxput test:stringExample hello 2>&1 || true)
    if ! printf '%s' "${out}" | grep -q 'Put not permitted'; then
        echo "    a request with no certificate was not refused by the IOC." >&2
        return 1
    fi
    # A laboratory with nothing outside it has no boundary to check.
    case " $(_klab_places) " in *" internet "*) ;; *) return 0 ;; esac
    # A boundary carrying TLS alone refuses bluntly.
    echo "==> checking the boundary lets nothing in yet"
    if krun_in internet as guest without a certificate pvxget test:aiExample >/dev/null 2>&1; then
        echo "    the boundary carries TLS alone, so read won't work without a trust anchor." >&2
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------------------ certificates
#
_kask() {
    local place="$1" who="$2"; shift 2
    # Named place/person: two people in one place each hold their own certificate.
    local label="${place}/${who}"
    local out; out=$(krun_in "${place}" as "${who}" "$@" 2>&1 || true)
    if printf '%s' "${out}" | grep -q "Certificate identifier"; then
        printf '    %-22s %s\n' "${label}" "$(printf '%s' "${out}" | grep 'Certificate identifier' | sed 's/.*: //')"
    elif printf '%s' "${out}" | grep -q "Valid certificate found"; then
        printf '    %-22s already holds one\n' "${label}"
    else
        printf '    %-22s FAILED\n' "${label}"
        printf '%s\n' "${out}" | tail -3 | sed 's/^/        /'
    fi
}

kgo_tls() {
    # Which places exist is the laboratory's to say, so the federated ones get their ML
    # department served too, and each department approves what it issued.
    local places has_ml=no has_gateway=no has_internet=no
    places=" $(_klab_places) "
    case "${places}" in *" ml "*) has_ml=yes ;; esac
    case "${places}" in *" gateway "*) has_gateway=yes ;; esac
    case "${places}" in *" internet "*) has_internet=yes ;; esac

    echo "==> asking for certificates inside the laboratory"
    _kask lab     guest    authnstd -u client
    _kask lab     operator authnstd -u client
    _kask testioc testioc  authnstd -u ioc
    _kask tstioc  tstioc   authnstd -u ioc
    [ "${has_gateway}" = yes ] && _kask gateway gateway authnstd -u ioc
    if [ "${has_ml}" = yes ]; then
        _kask ml         guest   authnstd -u client
        _kask ml-ioc     mlioc   authnstd -u ioc
        _kask ml-gateway gateway authnstd -u ioc
    fi

    echo "==> approving them"
    krun_in lab-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
        | grep -E "done|No certificates" || true
    if [ "${has_ml}" = yes ]; then
        krun_in ml-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
            | grep -E "done|No certificates" || true
    fi

    echo "==> restarting services"
    _k exec deploy/pvxs-lab-testioc -- supervisorctl restart testioc >/dev/null 2>&1 || true
    _k exec deploy/pvxs-lab-tstioc  -- supervisorctl restart tstioc  >/dev/null 2>&1 || true
    if [ "${has_ml}" = yes ]; then
        _k exec deploy/pvxs-lab-ml-ioc -- supervisorctl restart mlioc >/dev/null 2>&1 || true
        _k rollout restart deploy/pvxs-lab-ml-gateway >/dev/null 2>&1
    fi
    if [ "${has_gateway}" = yes ]; then
        _k rollout restart deploy/pvxs-lab-gateway >/dev/null 2>&1
        _k rollout status  deploy/pvxs-lab-gateway --timeout=180s >/dev/null 2>&1
    fi
    [ "${has_ml}" = yes ] && _k rollout status deploy/pvxs-lab-ml-gateway --timeout=180s >/dev/null 2>&1

    # A laboratory with nothing outside it is provisioned already: no anchor to carry,
    # no boundary to cross.
    if [ "${has_internet}" != yes ]; then
        echo "==> no workstation outside this laboratory; done"
        return 0
    fi

    kcopy_anchor || return 1

    echo "==> waiting for the gateway to serve the internet"
    local i=0
    for i in $(seq 1 24); do
        _k exec deploy/pvxs-lab-gateway -- sh -c 'ss -lnt 2>/dev/null | grep -q 507' 2>/dev/null && break
        sleep 5
    done

    echo "==> asking for a certificate from the internet, across the gateway"
    local _last=
    for i in $(seq 1 6); do
        # An explicit branch, not a conditional expansion: zsh hands
        # ${X:+--issuer "${X}"} to the command as a single word.
        if [ -n "${LAB_SKID:-}" ]; then
            _last=$(krun_in internet as guest authnstd -u client -n remote --issuer "${LAB_SKID}" 2>&1)
        else
            _last=$(krun_in internet as guest authnstd -u client -n remote 2>&1)
        fi
        printf '%s\n' "${_last}" | grep -E 'Certificate identifier|Valid certificate found' && break
        sleep 5
    done
    # Every attempt failed: show the last error, because a silence here cannot be told
    # apart from success by anything that follows.
    if ! printf '%s\n' "${_last}" | grep -qE 'Certificate identifier|Valid certificate found'; then
        printf '%s\n' "${_last}" | tail -3 | sed 's/^/    /' >&2
    fi
    krun_in lab-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
        | grep -E 'done|No certificates' || true
    sleep 3

    echo "==> reading across the gateway"
    local ok=no
    for i in $(seq 1 12); do
        if krun_in internet as guest pvxget test:aiExample >/dev/null 2>&1; then ok=yes; break; fi
        sleep 5
    done
    if [ "${ok}" = yes ]; then
        # A read alone proves reachability, not identity: a gateway forwards anonymous
        # TLS reads, so an empty keychain passes it. Say which one this was.
        if krun_in internet as guest pvxcert -f /home/guest/.config/pva/1.5/client.p12 2>/dev/null \
               | grep -q "^Entity Subject"; then
            echo "    the gateway is open to a holder with a valid certificate"
        else
            echo "    reading works, but the workstation outside holds no identity:" >&2
            echo "    the certificate request across the gateway did not succeed." >&2
            return 1
        fi
    else
        echo "    it still will not read. Look at the gateway:" >&2
        echo "        kubectl -n ${KLAB_NS} logs deploy/pvxs-lab-gateway" >&2
        return 1
    fi
}

# The trust anchor, copied to the workstation outside by hand.
#
kcopy_anchor() {
    local tmp="${TMPDIR:-/tmp}/trust_anchor.p12"
    echo "==> copying the trust anchor to the workstation outside"
    # Beside the CA keychain, wherever that is: /etc/pvacms when the authority is
    # installed at start, beside the database when the manager minted its own.
    _k exec deploy/pvxs-lab-pvacms -- sh -c "
        for f in /etc/pvacms/trust_anchor.p12 \
                 \"\$(dirname \"\${EPICS_PVACMS_DB}\")/trust_anchor.p12\"; do
            [ -s \"\${f}\" ] && exec cat \"\${f}\"
        done; exit 1" > "${tmp}" 2>/dev/null
    if [ ! -s "${tmp}" ]; then
        echo "    the certificate manager has not written a trust anchor." >&2
        rm -f "${tmp}"; return 1
    fi
    local pod
    pod=$(_k get pod -l app=internet-client -o jsonpath='{.items[0].metadata.name}') || return 1

    [ "$#" -eq 0 ] && set -- guest operator
    local who
    for who in "$@"; do
        _k exec "${pod}" -- install -d -o "${who}" -g "${who}" -m 0700 \
            "/home/${who}/.config/pva/1.5" 2>/dev/null || true

        if _k exec "${pod}" -- sh -c \
              'openssl pkcs12 -in "/home/'"${who}"'/.config/pva/1.5/client.p12" -nocerts -passin pass: -passout pass:x 2>/dev/null | grep -q "PRIVATE KEY"' 2>/dev/null; then
            echo "    ${who} already holds an identity, left alone"
            continue
        fi

        if _k cp "${tmp}" "${pod}:/home/${who}/.config/pva/1.5/client.p12" >/dev/null 2>&1; then
            _k exec "${pod}" -- chown "${who}" "/home/${who}/.config/pva/1.5/client.p12" 2>/dev/null || true
            echo "    copied to ${who}"
        else
            echo "    could not copy it to ${who}" >&2
        fi
    done
    rm -f "${tmp}"
}

# ------------------------------------------------- the checks for federated-shared-root
#
_kcheck_responder() {
    echo "==> checking the responder answers for the facility root"
    local i=0
    for i in $(seq 1 12); do
        if _k exec deploy/pvxs-lab-ocsp-responder -c responder -- sh -c \
            'openssl ocsp -issuer /ocsp/ca.pem -cert /ocsp/ca.pem -url http://127.0.0.1:8888 -CAfile /ocsp/ca.pem' \
            2>/dev/null | grep -q 'ca.pem: good'; then return 0; fi
        sleep 5
    done
    echo "    the responder will not answer." >&2
    echo "        kubectl -n ${KLAB_NS} logs deploy/pvxs-lab-ocsp-responder" >&2
    return 1
}

_kcheck_managers_federated() {
    echo "==> checking each PVACMS answers its administrator"
    local i=0
    for i in $(seq 1 18); do
        if krun_in lab-pvacms as admin pvxcert -l >/dev/null 2>&1 \
        && krun_in ml-pvacms  as admin pvxcert -l >/dev/null 2>&1; then return 0; fi
        sleep 5
    done
    echo "    a PVACMS will not answer its administrator." >&2
    return 1
}

_kcheck_reads_federated() {
    echo "==> checking reading works from each department and from the internet"
    local i=0
    for i in $(seq 1 18); do
        if krun_in lab      as guest without a certificate pvxget test:aiExample >/dev/null 2>&1 \
        && krun_in ml       as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1 \
        && krun_in lab      as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1 \
        && krun_in ml       as guest without a certificate pvxget test:aiExample >/dev/null 2>&1 \
        && krun_in internet as guest without a certificate pvxget test:aiExample >/dev/null 2>&1 \
        && krun_in internet as guest without a certificate pvxget ml:aiExample   >/dev/null 2>&1; then
            return 0
        fi
        sleep 5
    done
    echo "    reading does not work from everywhere yet. Try them one at a time:" >&2
    echo "        krun_in lab      as guest without a certificate pvxget test:aiExample" >&2
    echo "        krun_in ml       as guest without a certificate pvxget ml:aiExample" >&2
    echo "        krun_in lab      as guest without a certificate pvxget ml:aiExample" >&2
    echo "        krun_in ml       as guest without a certificate pvxget test:aiExample" >&2
    echo "        krun_in internet as guest without a certificate pvxget test:aiExample" >&2
    echo "        krun_in internet as guest without a certificate pvxget ml:aiExample" >&2
    return 1
}

_kcheck_refusals_federated() {
    echo "==> checking a write with no certificate is refused"
    local out
    out=$(krun_in lab as guest without a certificate pvxput test:stringExample hello 2>&1 || true)
    if ! printf '%s' "${out}" | grep -q 'Put not permitted'; then
        echo "    a request with no certificate was not refused by the IOC." >&2
        return 1
    fi

    out=$(krun_in internet as guest without a certificate pvxput test:stringExample hello 2>&1 || true)
    if ! printf '%s' "${out}" | grep -q 'denied by gateway'; then
        echo "    a request with no certificate was not refused at the gateway." >&2
        printf '%s\n' "${out}" | tail -3 | sed 's/^/        /' >&2
        return 1
    fi
    return 0
}



# ----------------------------------------------------------------------- the facility root
#
# The status is stored on a tab-separated line in an index file.

_kindex() { _k exec deploy/pvxs-lab-ocsp-responder -c responder -- cat /ocsp/index.txt 2>/dev/null; }

# The OCSP responder that answers for the facility root's revocation status:
#
#     kocsp_responder                  what it currently says about the root
#     kocsp_responder unreachable      make it unresponsive (the deployment scales to zero)
#     kocsp_responder reachable        make it responsive
#     kocsp_responder revoke root      respond that the facility root is REVOKED
#
kocsp_responder() {
    case "${1:-says}" in
        says)
            if ! _k get deploy/pvxs-lab-ocsp-responder >/dev/null 2>&1; then
                echo "no OCSP responder here"; return 0
            fi
            # readyReplicas is absent, not zero, while nothing is ready.
            if [ -z "$(_k get deploy/pvxs-lab-ocsp-responder \
                        -o jsonpath="{.status.readyReplicas}" 2>/dev/null)" ]; then
                echo "the status of the facility root is UNKNOWN"; return 0
            fi
            case "$(_kindex | cut -f1)" in
                R) echo "the facility root is REVOKED" ;;
                V) echo "the facility root is VALID" ;;
                *) echo "internal error in the OCSP responder" ;;
            esac ;;
        unreachable)
            _k scale deploy/pvxs-lab-ocsp-responder --replicas=0 >/dev/null 2>&1 || return 1
            _k wait --for=delete pod -l app=ocsp-responder --timeout=120s >/dev/null 2>&1 || true
            echo "the responder is stopped" ;;
        reachable)
            _k scale deploy/pvxs-lab-ocsp-responder --replicas=1 >/dev/null 2>&1 || return 1
            _k rollout status deploy/pvxs-lab-ocsp-responder --timeout=120s >/dev/null 2>&1
            echo "the responder is running"
            kocsp_responder says ;;
        revoke)
            [ "${2:-}" = root ] || { echo "usage: kocsp_responder revoke root" >&2; return 2; }
            # The revocation time is the two-digit-year form the index uses throughout; the
            # four-digit form makes the responder answer with an internal error.
            _k exec deploy/pvxs-lab-ocsp-responder -c responder -- sh -c '
                awk -F"\t" -v when="$(date -u +%y%m%d%H%M%SZ)" "BEGIN{OFS=\"\t\"}
                    {print \"R\", \$2, when, \$4, \$5, \$6}" /ocsp/index.txt > /tmp/ix.new \
                && cat /tmp/ix.new > /ocsp/index.txt' || return 1
            _k rollout restart deploy/pvxs-lab-ocsp-responder >/dev/null 2>&1
            _k rollout status deploy/pvxs-lab-ocsp-responder --timeout=120s >/dev/null 2>&1
            kocsp_responder says ;;
        *)
            echo "kocsp_responder: no subcommand '${1}'." >&2
            echo "usage: kocsp_responder [unreachable|reachable|revoke root]" >&2
            return 2 ;;
    esac
}

# What is up, place by place: the deployment behind each place, its readiness, and the pod
# currently playing it. The Kubernetes rendering of lab_status.
klab_status() {
    local place deploy app pod ready
    printf '%-12s %-26s %-8s %s\n' PLACE DEPLOYMENT READY POD
    local all="lab-pvacms testioc tstioc gateway ml-pvacms ml-ioc ml-gateway lab ml internet responder facility"
    local places; places=$(_klab_places) || places="${all}"
    # Split through a pipe rather than by expansion: zsh does not word-split ${places},
    # and this file is sourced by whichever shell the reader uses.
    echo "${places}" | tr ' ' '\n' | while read -r place; do
        [ -n "${place}" ] || continue
        deploy=$(_klab_place "${place}") || continue
        app=$(_klab_app "${place}")
        ready=$(_k get deploy "${deploy}" -o jsonpath='{.status.readyReplicas}/{.spec.replicas}' 2>/dev/null)
        pod=$(_k get pod -l "app=${app}" -o jsonpath='{.items[0].metadata.name} {.items[0].status.phase}' 2>/dev/null)
        printf '%-12s %-26s %-8s %s\n' "${place}" "${deploy}" "${ready:--}" "${pod:-(no pod)}"
    done
}

klab_ids 2>/dev/null || true
