# The laboratory, run on Kubernetes. Source this file; do not execute it.
#
#     . ./khelpers.sh
#     kind_create                       once, to make the cluster
#     kreset_topology simple-with-gateway
#     krun_in internet as operator pvxget test:spec
#
# These are the same commands as the podman laboratory's, with a k in front, and they take the
# same words in the same order. Where the two laboratories differ they differ for a reason that
# is written down at the point it applies, in values.yaml and networkpolicy.yaml.
#
# ------------------------------------------------------------------------ where things are
#
#   lab                       a workstation inside the laboratory
#   internet                  the workstation outside the boundary
#   lab-pvacms                the certificate manager
#   testioc, tstioc           the two IOCs, each behind a Service
#   gateway                   the gateway on the boundary
#
#   guest, operator           ordinary users of a workstation
#   admin                     the administrator, whose identity lives on the certificate manager

KLAB_NS="${KLAB_NS:-spva-lab}"
KLAB_RELEASE="${KLAB_RELEASE:-spva-lab}"
KLAB_CLUSTER="${KLAB_CLUSTER:-spva-lab}"
KLAB_CONTEXT="${KLAB_CONTEXT:-kind-${KLAB_CLUSTER}}"
KLAB_CILIUM="${KLAB_CILIUM:-1.16.5}"

KLAB_DIR="${KLAB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]:-${(%):-%x}}")" 2>/dev/null && pwd)}"

_k() { kubectl --context "${KLAB_CONTEXT}" -n "${KLAB_NS}" "$@"; }

# Which container runtime kind builds the cluster on.
#
# Docker is preferred where a real daemon is running: it is what kind supports without the
# experimental flag, and the podman provider has its own faults - with podman 6 the label query
# behind `kind get clusters` fails outright, so kind cannot tell whether a cluster exists.
#
# The catch is that a homebrew 'docker' may be a symlink to podman and sits earlier on PATH than
# Docker Desktop, so the name cannot be trusted. The link is resolved before the binary is used.
_klab_pick_runtime() {
    KLAB_DOCKER=; KLAB_RUNTIME=
    # Wherever a docker command may be, whichever platform this is. The one on PATH is
    # tried first, which is what makes this work on Linux, where Docker lives in
    # /usr/bin and none of the fixed paths below exist.
    local d
    for d in "$(command -v docker 2>/dev/null)" \
             /usr/local/bin/docker "${HOME}/.docker/bin/docker" \
             /Applications/Docker.app/Contents/Resources/bin/docker; do
        [ -n "${d}" ] && [ -x "${d}" ] || continue
        # A docker that is really podman announces itself; the symlink test alone misses
        # a shim that is a wrapper script rather than a link.
        case "$("${d}" --version 2>/dev/null)" in *podman*|*Podman*) continue ;; esac
        if "${d}" info >/dev/null 2>&1; then
            KLAB_DOCKER="${d}"; KLAB_RUNTIME=docker
            # kind runs `docker`, so the real one has to WIN on PATH, not merely be on it.
            # The homebrew symlink to podman is usually earlier, so this prepends
            # unconditionally rather than checking for presence.
            PATH="$(dirname "${d}"):${PATH}"; export PATH
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
    # `kind get nodes` rather than `kind get clusters`: the latter's label query fails against
    # podman 6, so the guard would never fire and creation would be attempted every time.
    if kind get nodes --name "${KLAB_CLUSTER}" 2>/dev/null | grep -q .; then
        echo "==> cluster ${KLAB_CLUSTER} is already there"
    else
        echo "==> creating the cluster on ${KLAB_RUNTIME}, with the default CNI turned off"
        kind create cluster --config "${KLAB_DIR}/kind-cluster.yaml" || return 1
    fi
    # The segments in this laboratory are NetworkPolicy. Kind's default CNI does not enforce
    # it, so without a policy-enforcing CNI the boundaries are open and the laboratory
    # demonstrates nothing while appearing to work.
    #
    # Cilium rather than Calico, for what it shows as much as what it enforces: Hubble reports
    # flows with pod identity, which is how you see that a client went straight to a pod
    # instead of through the Service in front of it.
    if ! kubectl --context "${KLAB_CONTEXT}" get daemonset cilium -n kube-system >/dev/null 2>&1; then
        echo "==> installing Cilium ${KLAB_CILIUM}, which is what enforces the segments"
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
# the cluster, which has no access to the host image store.
kbuild_images() {
    JOBS="${JOBS:-}" CONTAINER_ENGINE="${KLAB_RUNTIME:-docker}" "${KLAB_DIR}/../bootstrap.sh" "$@"
}

# Carries the built images into the cluster, which has no access to the host image store.
kload_images() {
    local reg="${DOCKER_REGISTRY:-localhost}" usr="${DOCKER_USERNAME:-spva}" tag="${KLAB_TAG:-latest}"
    local role tar ref
    # The externals are pulled rather than built: the facility load balancer, and the
    # kubectl the minting job packages its output with.
    local externals="docker.io/library/haproxy:lts-alpine docker.io/bitnami/kubectl:latest"

    if [ "${KLAB_RUNTIME}" = docker ]; then
        # The cluster runs on Docker, and kind reads the Docker daemon directly: no
        # archive, no second image store.
        for role in idm ml testioc tstioc ml-ioc lab gateway internet; do
            printf '    %-10s' "${role}"
            if kind load docker-image --name "${KLAB_CLUSTER}" "${reg}/${usr}/${role}:${tag}" >/dev/null 2>&1; then
                echo "loaded"
            else
                echo "FAILED - is ${reg}/${usr}/${role}:${tag} built? Run kbuild_images."
            fi
        done
        # The externals are not preloaded here. Docker's image store exports pulled
        # images as their full multi-platform index, and the node's import then demands
        # blobs the store never had, so both load paths refuse them. The nodes pull the
        # two images from the registry on first use instead.
        echo "    externals ($(echo ${externals} | wc -w | tr -d ' ')): pulled by the cluster on first use"
        return 0
    fi

    # The cluster runs on podman, whose provider cannot read an image store directly:
    # the images go through an archive.
    for role in idm ml testioc tstioc ml-ioc lab gateway internet; do
        tar="${TMPDIR:-/tmp}/klab-${role}.tar"
        printf '    %-10s' "${role}"
        if podman save "${reg}/${usr}/${role}:${tag}" -o "${tar}" >/dev/null 2>&1 \
           && kind load image-archive --name "${KLAB_CLUSTER}" "${tar}" >/dev/null 2>&1; then
            echo "loaded"
        else
            echo "FAILED - is ${reg}/${usr}/${role}:${tag} built? Run kbuild_images."
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
        responder)          echo pvxs-lab-authority-status ;;
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
        responder)          echo authority-status ;;
        facility)           echo facility ;;
        *) return 1 ;;
    esac
}

# Which laboratory is up, and what it has. A place that exists but not here should say so
# rather than report that nothing is running for it.
_klab_topology() { cat "${KLAB_DIR}/.ktopology" 2>/dev/null; }

_klab_places() {
    case "$(_klab_topology)" in
        simple)                echo "lab lab-pvacms testioc tstioc" ;;
        simple-with-gateway)   echo "lab internet lab-pvacms testioc tstioc gateway facility" ;;
        federated-shared-root) echo "lab ml internet lab-pvacms ml-pvacms testioc tstioc ml-ioc gateway ml-gateway responder facility" ;;
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
        echo "places: lab internet lab-pvacms testioc tstioc gateway"
        return 2
    fi

    local place="$1" who="$3" plain=no show="${KRUN_IN_SHOW:-no}"
    # Older names, still accepted: the walkthroughs moved to the truthful ones.
    case "${place}" in
        perimeter)              place=internet ;;
        lab-manager|lab_pvacms) place=lab-pvacms ;;
        ml-manager|ml_pvacms)   place=ml-pvacms ;;
    esac
    if [ "$2" != as ] || [ -z "${who}" ]; then
        echo "krun_in: say it as: krun_in <place> as <person> <command...>" >&2; return 2
    fi
    shift 3

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

    # The administrator is not a user of a workstation. Say so rather than quietly running the
    # command somewhere the reader was not told about.
    if [ "${who}" = admin ] && [ "${place}" != lab-pvacms ] && [ "${place}" != ml-pvacms ]; then
        echo "krun_in: the administrator's identity lives on a certificate manager, not at a" >&2
        echo "        workstation. Write: krun_in lab-pvacms as admin ...  (or ml-pvacms)" >&2
        return 2
    fi

    local script
    if [ "$#" -gt 0 ]; then
        # Keep the command as it was typed. Requoting matters: --where "state:VALID and
        # type:IOC" is one argument, and flattening it would hand pvxcert three.
        script=$(printf '%q ' "$@")
    else
        script='exec bash -i'
    fi

    local prelude=
    [ "${plain}" = yes ] && prelude='export EPICS_PVA_TLS_KEYCHAIN=
'
    case "${who}" in
        admin)
            # The identity the certificate manager issued to itself, presented over the secure
            # port. The address is this pod: an administrator's tools run beside PVACMS and
            # have no reason to look anywhere else.
            prelude="export EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12
export EPICS_PVA_ADDR_LIST=127.0.0.1
export EPICS_PVA_AUTO_ADDR_LIST=NO
export EPICS_PVA_NAME_SERVERS=
" ;;
        guest|operator)
            # The login profile supplies the tool paths, but it was written for the federated
            # laboratory and names its hosts. The pod knows which laboratory it is actually in,
            # so put its own addressing back afterwards - otherwise a command run on the
            # workstation outside quietly talks to the laboratory instead.
            #
            # THE DIFFERENCE: podman runs this with `podman exec --user`, which keeps the
            # container's environment. kubectl has no such flag, so a person is became with
            # `su -`, and that is a login shell: it discards the environment the Deployment
            # set. The pod's own EPICS_PVA settings are written out by the root shell before
            # the su and read back here, after the profile has had its say.
            #
            # All four are unset before they are read back, not just overwritten. The profile
            # names the federated laboratory's hosts, and a setting this laboratory does not
            # make - a name server, here - would otherwise survive and be searched.
            prelude="source ~/.${who}_bashrc 2>/dev/null
unset EPICS_PVA_ADDR_LIST EPICS_PVA_AUTO_ADDR_LIST EPICS_PVA_NAME_SERVERS EPICS_PVA_TLS_OPTIONS
[ -r /tmp/.pva-pod-env ] && . /tmp/.pva-pod-env
export EPICS_PVA_TLS_KEYCHAIN=\${HOME}/.config/pva/1.5/client.p12
${prelude}" ;;
        *)
            prelude="source ~/.${who}_bashrc 2>/dev/null
unset EPICS_PVA_ADDR_LIST EPICS_PVA_AUTO_ADDR_LIST EPICS_PVA_NAME_SERVERS EPICS_PVA_TLS_OPTIONS
[ -r /tmp/.pva-pod-env ] && . /tmp/.pva-pod-env
${prelude}" ;;
    esac

    script="${prelude}export PVXS_LOG=\${PVXS_LOG:-none}
${script}"

    # A terminal is handed through only when there is one on both sides, which is what lets a
    # command that asks a question be answered. Connecting standard input at any other time
    # does harm: a krun_in inside a loop would swallow the rest of the loop's input.
    local tty=
    [ -t 0 ] && [ -t 1 ] && tty=-it

    if [ "${show}" = yes ]; then
        case "${who}" in
            admin) echo "kubectl -n ${KLAB_NS} exec ${tty} deploy/${deploy} -- bash -lc '${script}'" ;;
            *)     echo "kubectl -n ${KLAB_NS} exec ${tty} deploy/${deploy} -- su - ${who} -c '${script}'" ;;
        esac
        return 0
    fi

    # The pods run as root so that a person can be became by name. The administrator is the
    # exception: podman runs that one as the pod's own user, and the keychain path above is
    # named absolutely, so a login shell is all that is needed.
    #
    # `export -p` rather than `env`, because it quotes: EPICS_PVA_ADDR_LIST holds a list
    # separated by spaces, and `env` output cannot be sourced back without splitting it.
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
# Three different things are called a restart, and they are not interchangeable. Say which.

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
            # The pod goes; the Deployment puts another in its place. The Service keeps its
            # address, so a client sees the endpoint disappear and come back. Keychains are on
            # a claim, so the new pod is the same holder as the old one.
            echo "==> deleting the ${place} pod"
            _k delete pod -l "app=${app}" --wait=false || return 1
            _k rollout status "deploy/${deploy}" --timeout=180s
            ;;
        service)
            # The whole deployment is rolled. Kubernetes brings the replacement up before it
            # takes the old one out, so the Service is never without an endpoint.
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
            echo "==> restarting the ${program} softIoc, leaving the pod alone"
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
    # Naming nothing is not a request to build the only one that exists. It is almost always
    # a half-typed command, and building takes minutes and destroys what is already up.
    if [ "$#" -eq 0 ] || [ "$1" = -h ] || [ "$1" = --help ]; then
        _kreset_usage; return 2
    fi
    local topology="$1"

    # 'clear' is not a laboratory. It takes whichever one is up away and puts nothing in its
    # place, for when the machine is wanted for something else. That matters here more than it
    # looks: this laboratory and the podman one share a podman machine, and the cluster is
    # itself a container on it, so the two together are not small.
    #
    # The laboratory goes by default and the cluster stays, because rebuilding the cluster
    # means loading every image into it again. Say --cluster to take that as well.
    if [ "${topology}" = clear ]; then
        echo "==> destroying the laboratory"
        helm --kube-context "${KLAB_CONTEXT}" -n "${KLAB_NS}" uninstall "${KLAB_RELEASE}" >/dev/null 2>&1 || true
        # The namespace takes the claims, the config maps and the issuer id with it. Without
        # this the authority survives, and a laboratory built next would issue certificates
        # under an authority its own certificate manager never minted.
        kubectl --context "${KLAB_CONTEXT}" delete namespace "${KLAB_NS}" --wait=true >/dev/null 2>&1 || true
        if [ "${2:-}" = --cluster ] || [ "${2:-}" = cluster ]; then
            echo "==> deleting the cluster"
            kind_delete
            echo "    the cluster is gone. Building again needs kind_create and kload_images."
        else
            echo "    the laboratory is gone. The cluster is still there, which is one container"
            echo "    on the podman machine: 'kreset_topology clear --cluster' takes that too."
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
    # The workloads are taken down explicitly, not left to helm alone. An interrupted uninstall
    # deletes the release record before the resources are gone, and on the next reset helm has
    # nothing to act on while the pods run on. A PVC cannot finish deleting while a running pod
    # mounts it, so deleting the claims before the pods deadlocks, silently and forever.
    _k delete deploy,job --all --wait=false >/dev/null 2>&1 || true
    _k wait --for=delete pod --all --timeout=180s >/dev/null 2>&1 || true
    # The claims are not helm's, and the authority lives on one of them. Leaving them would
    # carry the old certificate manager's authority into the new laboratory, and every
    # certificate issued under it would be signed by something nothing can establish. Bounded,
    # so a claim that cannot go yet fails loudly rather than hanging the reset.
    _k delete pvc --all --wait=true --timeout=120s >/dev/null 2>&1 || true
    _k delete configmap lab-issuer lab-issuer-ids ocsp-index-seed >/dev/null 2>&1 || true
    _k delete secret lab-intermediate ml-intermediate ml-root trust-anchors ocsp-material >/dev/null 2>&1 || true

    echo "==> building the laboratory"
    kubectl --context "${KLAB_CONTEXT}" create namespace "${KLAB_NS}" >/dev/null 2>&1 || true
    # The same two variables the podman example uses to name its images, so one laboratory's
    # images are the other's without anything being rebuilt or retagged.
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
        # Only a laboratory whose manager mints its own authority has an issuer id that does
        # not exist yet. The federated one is minted before anything starts.
        _kread_issuer || return 1
    fi

    # A gateway makes its upstream connections when it starts and does not retry the ones it
    # could not make, so one that came up before the IOCs were serving forwards nothing until
    # it is restarted. Everything is up by now, so this is where that is put right.
    echo "==> restarting the gateways, now that the IOCs are serving"
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
        klab_ids_federated
    elif [ "${topology}" = federated-shared-root ]; then
        _kcheck_responder && _kcheck_managers_federated && _kcheck_reads_federated \
            && _kcheck_refusals_federated || return 1
        klab_ids_federated
    else
        _kcheck_manager && _kcheck_reads && _kcheck_refusals || return 1
        klab_ids
    fi
    if [ "${topology}" = federated-non-shared-root ]; then
        cat <<'DONE'

The federated-non-shared-root laboratory is up with no certificates issued, and this much was
just checked:
    each certificate manager answers its administrator
    reading works, from each department and from outside
    a write with no certificate is refused, by the IOC and at the boundary
DONE
    elif [ "${topology}" = federated-shared-root ]; then
        cat <<'DONE'

The federated-shared-root laboratory is up with no certificates issued, and this much was
just checked:
    the responder answers for the facility root
    each certificate manager answers its administrator
    reading works, from each department and from outside
    a write with no certificate is refused, by the IOC and at the boundary
DONE
    elif [ "${topology}" = simple ]; then
        cat <<'DONE'

The simple laboratory is up with no certificates issued:
    one lab, two IOCs, one pvacms
DONE
    else
        cat <<'DONE'

The simple-with-gateway laboratory is up with no certificates issued:
    one lab, two IOCs, one pvacms
    one gateway, one internet
DONE
    fi
}

# The issuer identifier does not exist until the certificate manager has minted its authority,
# so it is read back afterwards and handed to every pod. A login shell resets the environment,
# so the images read it from a file rather than from the environment.
_kread_issuer() {
    echo "==> reading the issuer id from the authority the certificate manager made"
    local skid= i
    for i in $(seq 1 18); do
        skid=$(_k exec deploy/pvxs-lab-pvacms -- bash -c '
            k=$(dirname "${EPICS_PVACMS_DB}")/cert_auth.p12
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
    # they are rolled onto it. Waiting for the kubelet to notice would work too and is not
    # worth the uncertainty: everything below this line depends on the issuer being readable.
    echo "==> handing the issuer id to every pod"
    # Asked of the cluster rather than listed here: the laboratories do not all have the same
    # things in them, and a list written down goes stale the moment one of them changes.
    # Read line by line. An unquoted expansion does not word-split in zsh, and this file is
    # sourced by whichever shell the reader uses, so a list held in one string arrives as one
    # word there and as many in bash.
    local d
    _k get deploy -o name 2>/dev/null | while read -r d; do
        [ -n "${d}" ] && _k rollout restart "${d}" >/dev/null 2>&1 || true
    done
    _k get deploy -o name 2>/dev/null | while read -r d; do
        [ -n "${d}" ] || continue
        _k rollout status "${d}" --timeout=180s >/dev/null 2>&1 \
            || echo "    ${d} did not come back" >&2
    done
    # Confirmed rather than assumed. A rollout reporting finished means the new pod is
    # running, not that the ConfigMap it mounts has reached it, and everything after this
    # asks for a certificate from an authority named by that file. Getting it wrong reports
    # "no certificate manager answered", which points nowhere near the cause.
    local i seen=
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

klab_ids() {
    [ -n "${KLAB_ROOT_ISSUER}" ] || return 0
    printf '\n    $ROOT      %s\n    $ROOT_SKID %s\n' "${KLAB_ROOT_ISSUER}" "${KLAB_ROOT_ISSUER_SKID}"
    ROOT="${KLAB_ROOT_ISSUER}"; ROOT_SKID="${KLAB_ROOT_ISSUER_SKID}"; export ROOT ROOT_SKID
}

# ------------------------------------------------------------------------------- the checks
#
# The same four assertions the podman laboratory makes after a reset. They are the acceptance
# criteria, not a smoke test: the fourth one is a negative, and a laboratory that passes the
# first three and fails it has an open boundary.

_kcheck_manager() {
    echo "==> checking the certificate manager answers its administrator"
    local i
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
    local i
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
    # A boundary carrying TLS alone refuses bluntly: a workstation that has been handed nothing
    # cannot verify what answers, so it never gets far enough to be told no about a particular
    # variable. What is checked is that it cannot get in at all.
    echo "==> checking the boundary lets nothing in yet"
    if krun_in internet as guest without a certificate pvxget test:aiExample >/dev/null 2>&1; then
        echo "    the boundary carries TLS alone, but a workstation holding nothing read across it." >&2
        echo "    If the cluster has no policy-enforcing CNI, every NetworkPolicy is ignored." >&2
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------------------ certificates
#
# Everything the walkthrough does by hand, in the order it has to be done in.
#
# The order is not a preference. The IOCs are given certificates first and the gateway last,
# because a gateway with EPICS_PVAS_SERVER_PORT closed serves nothing at all until it holds
# one, and it makes its upstream connections when it starts and does not retry them. The
# workstation outside comes last of all, because it cannot ask for a certificate until it has
# been handed something to verify the answer with.
# One request, with its outcome reported. "Valid certificate found" is not a failure: it is
# what an already-provisioned laboratory says, and kgo_tls is meant to be safe to run twice.
_kask() {
    local place="$1" who="$2"; shift 2
    local out; out=$(krun_in "${place}" as "${who}" "$@" 2>&1 || true)
    if printf '%s' "${out}" | grep -q "Certificate identifier"; then
        printf '    %-8s %s\n' "${place}" "$(printf '%s' "${out}" | grep 'Certificate identifier' | sed 's/.*: //')"
    elif printf '%s' "${out}" | grep -q "Valid certificate found"; then
        printf '    %-8s already holds one\n' "${place}"
    else
        printf '    %-8s FAILED\n' "${place}"
        printf '%s\n' "${out}" | tail -3 | sed 's/^/        /'
    fi
}

kgo_tls() {
    # Not silenced. A request that fails here is the whole reason the laboratory will not
    # work afterwards, and hiding it turns one clear error into a mystery three steps later.
    echo "==> asking for certificates inside the laboratory"
    _kask lab     guest    authnstd -u client
    _kask lab     operator authnstd -u client
    _kask testioc testioc  authnstd -u ioc
    _kask tstioc  tstioc   authnstd -u ioc
    _kask gateway gateway  authnstd -u ioc

    echo "==> approving them"
    krun_in lab-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
        | grep -E "done|No certificates" || true

    echo "==> restarting what now holds one"
    _k exec deploy/pvxs-lab-testioc -- supervisorctl restart testioc >/dev/null 2>&1 || true
    _k exec deploy/pvxs-lab-tstioc  -- supervisorctl restart tstioc  >/dev/null 2>&1 || true
    _k rollout restart deploy/pvxs-lab-gateway >/dev/null 2>&1
    _k rollout status  deploy/pvxs-lab-gateway --timeout=180s >/dev/null 2>&1

    kcarry_anchor || return 1

    # The gateway was restarted a moment ago and makes its listener when it starts. Asking
    # before it is up reports that no certificate manager answered, which is true and says
    # nothing about why. Wait for it to be there, then ask.
    echo "==> waiting for the gateway to serve the boundary"
    local i
    for i in $(seq 1 24); do
        _k exec deploy/pvxs-lab-gateway -- sh -c 'ss -lnt 2>/dev/null | grep -q 507' 2>/dev/null && break
        sleep 5
    done

    echo "==> asking for a certificate from outside, across the boundary"
    for i in $(seq 1 6); do
        krun_in internet as guest authnstd -u client -n remote 2>&1 \
            | grep -E 'Certificate identifier|Valid certificate found' && break
        sleep 5
    done
    krun_in lab-pvacms as admin pvxcert --review-pending --all approve --yes 2>&1 \
        | grep -E 'done|No certificates' || true
    sleep 3

    # Retried, like the checks after a reset. The gateway has just been restarted and makes
    # its upstream connections as it starts; asking the instant the rollout reports finished
    # asks before it is listening, and reports a closed boundary that is merely a slow one.
    echo "==> reading across the boundary"
    local ok=no
    for i in $(seq 1 12); do
        if krun_in internet as guest pvxget test:aiExample >/dev/null 2>&1; then ok=yes; break; fi
        sleep 5
    done
    if [ "${ok}" = yes ]; then
        echo "    the boundary is open to a holder with a valid certificate"
    else
        echo "    it still will not read. Look at the gateway:" >&2
        echo "        kubectl -n ${KLAB_NS} logs deploy/pvxs-lab-gateway" >&2
        return 1
    fi
}

# The authority, carried to the workstation outside by hand.
#
# It is carried rather than mounted, and that is the point of it: the workstation outside starts
# holding nothing, and cannot read, cannot ask for a certificate, and stays that way until a
# person takes the root across. Mounting it as a Secret at pod start would answer the question
# the laboratory is asking.
kcarry_anchor() {
    local tmp="${TMPDIR:-/tmp}/trust_anchor.p12"
    echo "==> carrying the authority to the workstation outside"
    _k exec deploy/pvxs-lab-pvacms -- \
        cat /home/idm/.local/share/pva/1.5/trust_anchor.p12 > "${tmp}" 2>/dev/null
    if [ ! -s "${tmp}" ]; then
        echo "    the certificate manager has not written a trust anchor." >&2
        rm -f "${tmp}"; return 1
    fi
    local pod
    pod=$(_k get pod -l app=internet-client -o jsonpath='{.items[0].metadata.name}') || return 1
    # Both people who sit at that workstation, so either can be named. The podman walkthrough
    # carries it to guest alone, which is enough to tell the story but means `as operator`
    # times out for a reason that has nothing to do with the boundary.
    # set -- rather than a defaulted expansion: this file is sourced by whichever shell the
    # reader happens to use, and zsh does not word-split an unquoted expansion the way bash
    # does, so ${*:-guest operator} arrives as one name in zsh and two in bash.
    [ "$#" -eq 0 ] && set -- guest operator
    local who
    for who in "$@"; do
        _k exec "${pod}" -- install -d -o "${who}" -g "${who}" -m 0700 \
            "/home/${who}/.config/pva/1.5" 2>/dev/null || true
        # Never over an identity. The anchor and the identity share one file: the anchor is
        # carried first, and authnstd then adds the identity beside it. Copying the anchor over
        # a file that already holds one throws the identity away, and the holder silently
        # becomes anonymous - it still reads, because a gateway forwards reads, and every write
        # is refused for a reason that looks nothing like the cause.
        if _k exec "${pod}" -- sh -c \
              'openssl pkcs12 -in "/home/'"${who}"'/.config/pva/1.5/client.p12" -nocerts -passin pass: -passout pass:x 2>/dev/null | grep -q "PRIVATE KEY"' 2>/dev/null; then
            echo "    ${who} already holds an identity, left alone"
            continue
        fi
        # It lands as that person's own keychain file. authnstd later adds the identity to the
        # same file, beside the anchor: one file carries both.
        if _k cp "${tmp}" "${pod}:/home/${who}/.config/pva/1.5/client.p12" >/dev/null 2>&1; then
            _k exec "${pod}" -- chown "${who}" "/home/${who}/.config/pva/1.5/client.p12" 2>/dev/null || true
            echo "    carried to ${who}"
        else
            echo "    could not carry it to ${who}" >&2
        fi
    done
    rm -f "${tmp}"
}

# ------------------------------------------------- the checks for federated-shared-root
#
# The same assertions reset.sh makes for this topology. The two that cross departments are
# here because they are the ones nothing else covers: a workstation reaches the peer
# department by the facility address, and that name has to be answerable where it is asked as
# well as reachable, which are two different things to get wrong.

_kcheck_responder() {
    echo "==> checking the responder answers for the facility root"
    local i
    for i in $(seq 1 12); do
        if _k exec deploy/pvxs-lab-authority-status -c responder -- sh -c \
            'openssl ocsp -issuer /ocsp/ca.pem -cert /ocsp/ca.pem -url http://127.0.0.1:8888 -CAfile /ocsp/ca.pem' \
            2>/dev/null | grep -q 'ca.pem: good'; then return 0; fi
        sleep 5
    done
    echo "    the responder will not answer. Nothing beneath the facility root can be" >&2
    echo "    established while that is true:" >&2
    echo "        kubectl -n ${KLAB_NS} logs deploy/pvxs-lab-authority-status" >&2
    return 1
}

_kcheck_managers_federated() {
    echo "==> checking each certificate manager answers its administrator"
    local i
    for i in $(seq 1 18); do
        if krun_in lab-pvacms as admin pvxcert -l >/dev/null 2>&1 \
        && krun_in ml-pvacms  as admin pvxcert -l >/dev/null 2>&1; then return 0; fi
        sleep 5
    done
    echo "    a certificate manager will not answer its administrator." >&2
    echo "    That is what a facility root nobody can establish looks like." >&2
    return 1
}

_kcheck_reads_federated() {
    echo "==> checking reading works from each department and from outside"
    local i
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
    # This boundary keeps a plaintext listener, unlike Part 2's, so a workstation outside gets
    # far enough to be told no about a particular name rather than being unable to get in.
    out=$(krun_in internet as guest without a certificate pvxput test:stringExample hello 2>&1 || true)
    if ! printf '%s' "${out}" | grep -q 'denied by gateway'; then
        echo "    a request with no certificate was not refused at the boundary." >&2
        printf '%s\n' "${out}" | tail -3 | sed 's/^/        /' >&2
        return 1
    fi
    return 0
}

klab_ids_federated() {
    local lab ml
    lab=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.LAB_ISSUER}' 2>/dev/null)
    ml=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.ML_ISSUER}' 2>/dev/null)
    [ -n "${lab}" ] || return 0
    printf '\n    $LAB      %s\n    $ML       %s\n' "${lab}" "${ml}"
    LAB="${lab}"; ML="${ml}"; export LAB ML
    LAB_SKID=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.LAB_ISSUER_SKID}' 2>/dev/null)
    ML_SKID=$(_k get configmap lab-issuer-ids -o jsonpath='{.data.ML_ISSUER_SKID}' 2>/dev/null)
    export LAB_SKID ML_SKID
    printf '    $LAB_SKID %s\n    $ML_SKID  %s\n' "${LAB_SKID}" "${ML_SKID}"
}

# ----------------------------------------------------------------------- the facility root
#
# The root has no status process variable of its own; the responder answers for it from one
# tab-separated line in an index file. These rewrite that line the way podman's
# authority_revoke does, and restart the responder so it reads it back.
# The index lives on the ocsp-state claim, so it survives the restart - which is the point:
# revoking is exactly a rewrite plus a restart.

_kindex() { _k exec deploy/pvxs-lab-authority-status -c responder -- cat /ocsp/index.txt 2>/dev/null; }

# The responder that answers for the facility root, spoken to by what it is:
#
#     kocsp_responder                   what it currently says about the root
#     kocsp_responder unreachable      stop it answering (the deployment scales to zero)
#     kocsp_responder reachable        answer again
#     kocsp_responder revoke root      the index says revoked
#
# The index lives on the ocsp-state claim, so what revoke and restore write survives the
# responder pod coming and going - which is the point: they are exactly a rewrite plus a
# restart.
kocsp_responder() {
    case "${1:-says}" in
        says)
            if ! _k get deploy/pvxs-lab-authority-status >/dev/null 2>&1; then
                echo "no responder here"; return 0
            fi
            # readyReplicas is absent, not zero, while nothing is ready.
            if [ -z "$(_k get deploy/pvxs-lab-authority-status \
                        -o jsonpath="{.status.readyReplicas}" 2>/dev/null)" ]; then
                echo "the facility root is UNKNOWN: the responder is unreachable"; return 0
            fi
            case "$(_kindex | cut -f1)" in
                R) echo "the facility root is REVOKED" ;;
                V) echo "the facility root is VALID" ;;
                *) echo "the responder's index says something this does not understand" ;;
            esac ;;
        unreachable)
            _k scale deploy/pvxs-lab-authority-status --replicas=0 >/dev/null 2>&1 || return 1
            _k wait --for=delete pod -l app=authority-status --timeout=120s >/dev/null 2>&1 || true
            echo "the responder is gone; nothing can be learned about the root" ;;
        reachable)
            _k scale deploy/pvxs-lab-authority-status --replicas=1 >/dev/null 2>&1 || return 1
            _k rollout status deploy/pvxs-lab-authority-status --timeout=120s >/dev/null 2>&1
            echo "the responder is running again"
            kocsp_responder says ;;
        revoke)
            [ "${2:-}" = root ] || { echo "usage: kocsp_responder revoke root" >&2; return 2; }
            # The revocation time is the two-digit-year form the index uses throughout; the
            # four-digit form makes the responder answer with an internal error.
            _k exec deploy/pvxs-lab-authority-status -c responder -- sh -c '
                awk -F"\t" -v when="$(date -u +%y%m%d%H%M%SZ)" "BEGIN{OFS=\"\t\"}
                    {print \"R\", \$2, when, \$4, \$5, \$6}" /ocsp/index.txt > /tmp/ix.new \
                && cat /tmp/ix.new > /ocsp/index.txt' || return 1
            _k rollout restart deploy/pvxs-lab-authority-status >/dev/null 2>&1
            _k rollout status deploy/pvxs-lab-authority-status --timeout=120s >/dev/null 2>&1
            kocsp_responder says ;;
        *)
            echo "kocsp_responder: no subcommand '${1}'." >&2
            echo "usage: kocsp_responder [unreachable|reachable|revoke root]" >&2
            return 2 ;;
    esac
}

# The names these commands had before they were gathered under one word.
kauthority_says()    { kocsp_responder says; }
kauthority_revoke()  { kocsp_responder revoke root; }

# What is up, place by place: the deployment behind each place, its readiness, and the pod
# currently playing it. The Kubernetes rendering of lab_status.
klab_status() {
    local place deploy app pod ready
    printf '%-12s %-26s %-8s %s\n' PLACE DEPLOYMENT READY POD
    local all="lab-pvacms testioc tstioc gateway ml-pvacms ml-ioc ml-gateway lab ml internet responder facility"
    local places; places=$(_klab_places) || places="${all}"
    for place in ${places}; do
        deploy=$(_klab_place "${place}") || continue
        app=$(_klab_app "${place}")
        ready=$(_k get deploy "${deploy}" -o jsonpath='{.status.readyReplicas}/{.spec.replicas}' 2>/dev/null)
        pod=$(_k get pod -l "app=${app}" -o jsonpath='{.items[0].metadata.name} {.items[0].status.phase}' 2>/dev/null)
        printf '%-12s %-26s %-8s %s\n' "${place}" "${deploy}" "${ready:--}" "${pod:-(no pod)}"
    done
}
