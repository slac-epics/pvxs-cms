#!/usr/bin/env zsh

# ---------------------------------------------------------------------------
# Kind cluster management (macOS / Docker Desktop only)
# ---------------------------------------------------------------------------
# Docker Desktop's built-in Kubernetes does NOT enforce NetworkPolicy.
# These helpers create a Kind cluster with Calico CNI so that the network
# policies in the Helm chart are actually enforced.
#
# Usage:
#   source helpers.sh
#   gw_kind_create          # create Kind cluster + install Calico
#   gw_kind_load_images     # push local Docker images into the cluster
#   gw_deploy               # deploy Helm chart (works on both Kind and DD)
#   gw_kind_delete           # tear down the Kind cluster
# ---------------------------------------------------------------------------

GW_KIND_CLUSTER_NAME="pvxs-lab"
GW_KIND_CONTEXT="kind-${GW_KIND_CLUSTER_NAME}"
GW_CALICO_VERSION="v3.29.3"

function _gw_is_docker_desktop_mac {
    # Guard: only run on macOS with Docker Desktop
    [[ "$(uname -s)" == "Darwin" ]] || return 1
    docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'docker desktop' || return 1
    command -v kind &>/dev/null || { echo "kind not found. Install with: brew install kind" ; return 1 }
    return 0
}

function _gw_kind_config {
    # Generate Kind cluster config with Calico-compatible networking and
    # NodePort mappings that match the Helm chart (Kerberos KDC).
    cat <<'KINDEOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      # Kerberos KDC — matches idm NodePort values
      - containerPort: 30088
        hostPort: 30088
        protocol: UDP
      - containerPort: 30049
        hostPort: 30049
        protocol: TCP
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
KINDEOF
}

function gw_kind_create {
    _gw_is_docker_desktop_mac || return 1

    if kind get clusters 2>/dev/null | grep -qx "${GW_KIND_CLUSTER_NAME}"; then
        echo "Kind cluster '${GW_KIND_CLUSTER_NAME}' already exists."
        echo "Use gw_kind_delete first, or gw_kind_load_images + gw_deploy."
        return 0
    fi

    echo "==> Creating Kind cluster '${GW_KIND_CLUSTER_NAME}' (CNI disabled) ..."
    _gw_kind_config | kind create cluster \
        --name "${GW_KIND_CLUSTER_NAME}" \
        --config /dev/stdin || return 1

    echo "==> Switching kubectl context to ${GW_KIND_CONTEXT} ..."
    kubectl config use-context "${GW_KIND_CONTEXT}"

    echo "==> Installing Calico ${GW_CALICO_VERSION} ..."
    kubectl create -f "https://raw.githubusercontent.com/projectcalico/calico/${GW_CALICO_VERSION}/manifests/calico.yaml" || return 1

    echo "==> Waiting for Calico pods to be ready ..."
    kubectl rollout status daemonset/calico-node -n kube-system --timeout=120s
    kubectl rollout status deployment/calico-kube-controllers -n kube-system --timeout=120s

    echo "==> Calico installed. NetworkPolicies will be enforced."
    echo "    Next: gw_kind_load_images && gw_deploy"
}

function gw_kind_load_images {
    _gw_is_docker_desktop_mac || return 1

    # Tag selector — dev branch defaults to "dev" so it matches values.yaml,
    # but accepts "latest" (or any other tag) via --tag <tag>. The chosen tag
    # MUST match what gw_deploy passes via --set images.<svc>.tag.
    local tag="latest"
    local force=0
    while (( $# > 0 )); do
        case "$1" in
            --tag)
                tag="${2:?--tag requires a value (latest|dev)}"
                shift 2
                ;;
            --tag=*)
                tag="${1#--tag=}"
                shift
                ;;
            --force|-f)
                force=1
                shift
                ;;
            *)
                break
                ;;
        esac
    done

    if ! kind get clusters 2>/dev/null | grep -qx "${GW_KIND_CLUSTER_NAME}"; then
        echo "Kind cluster '${GW_KIND_CLUSTER_NAME}' not found. Run gw_kind_create first."
        return 1
    fi

    local registry="${DOCKER_REGISTRY:-docker.io}"
    local username="${DOCKER_USERNAME:-georgeleveln}"

    # Unique image names used by the Helm chart
    local -a image_names=(
        idm gateway testioc tstioc lab internet ml ml-ioc cs-studio
    )

    # Also need bitnami/kubectl for the ca-keygen job
    local -a extra_images=(
        "docker.io/bitnami/kubectl:latest"
    )

    echo "==> Loading ${#image_names[@]} app images (tag=${tag}) + ${#extra_images[@]} utility images into Kind ..."

    local -a full_refs=()
    for name in "${image_names[@]}"; do
        full_refs+=("${registry}/${username}/${name}:${tag}")
    done
    for img in "${extra_images[@]}"; do
        full_refs+=("${img}")
    done

    local node="${GW_KIND_CLUSTER_NAME}-control-plane"
    local -A node_digests
    local _tag _digest
    while read -r _tag _digest; do
        [[ -n "${_tag}" ]] && node_digests[${_tag}]=${_digest}
    done < <(docker exec "${node}" ctr --namespace=k8s.io images ls 2>/dev/null \
        | awk 'NR>1 {print $1, $3}')

    # Load images one at a time — batch loading triggers containerd digest errors
    # Record every image actually (re)loaded in GW_KIND_RELOADED_IMAGES so
    # gw_deploy can restart the deployments that run them: with a fixed tag
    # like "latest", helm sees an unchanged manifest and restarts nothing.
    typeset -ga GW_KIND_RELOADED_IMAGES=()
    local failed=0 skipped=0 local_id
    for ref in "${full_refs[@]}"; do
        if ! docker image inspect "${ref}" &>/dev/null; then
            echo "    Pulling ${ref} ..."
            docker pull "${ref}" || { echo "    WARNING: could not pull ${ref}"; continue; }
        fi

        local_id=$(docker image inspect "${ref}" --format '{{.Id}}' 2>/dev/null)
        if (( ! force )) && [[ "${node_digests[${ref}]}" == "${local_id}" ]]; then
            echo "    Skipping ${ref} (unchanged)"
            (( skipped++ ))
            continue
        fi

        echo "    Loading ${ref} ..."
        if ! kind load docker-image --name "${GW_KIND_CLUSTER_NAME}" "${ref}" 2>/dev/null; then
            echo "    Retrying via docker save (multi-platform image workaround) ..."
            if ! docker save "${ref}" | docker exec --privileged -i "${node}" \
                    ctr --namespace=k8s.io images import --snapshotter=overlayfs -; then
                echo "    WARNING: failed to load ${ref}"
                (( failed++ ))
                continue
            fi
        fi
        GW_KIND_RELOADED_IMAGES+=("${ref}")
    done

    (( skipped > 0 )) && echo "==> Skipped ${skipped} already-loaded image(s)."

    if (( failed > 0 )); then
        echo "==> ${failed} image(s) failed to load."
        return 1
    fi
    echo "==> All images loaded."
}

function gw_kind_delete {
    _gw_is_docker_desktop_mac || return 1

    if ! kind get clusters 2>/dev/null | grep -qx "${GW_KIND_CLUSTER_NAME}"; then
        echo "Kind cluster '${GW_KIND_CLUSTER_NAME}' not found."
        return 0
    fi

    echo "==> Deleting Kind cluster '${GW_KIND_CLUSTER_NAME}' ..."
    kind delete cluster --name "${GW_KIND_CLUSTER_NAME}"
    echo "    Done. Docker Desktop's built-in Kubernetes (if enabled) is unaffected."
}

function gw_kind_status {
    _gw_is_docker_desktop_mac || return 1

    if ! kind get clusters 2>/dev/null | grep -qx "${GW_KIND_CLUSTER_NAME}"; then
        echo "Kind cluster '${GW_KIND_CLUSTER_NAME}' not found."
        return 1
    fi

    echo "==> Cluster: ${GW_KIND_CLUSTER_NAME}"
    echo "    Context: ${GW_KIND_CONTEXT}"
    echo ""
    echo "==> Calico status:"
    kubectl get pods -n kube-system -l k8s-app=calico-node -o wide 2>/dev/null
    kubectl get pods -n kube-system -l k8s-app=calico-kube-controllers -o wide 2>/dev/null
    echo ""
    echo "==> NetworkPolicies in pvxs-lab:"
    kubectl get networkpolicies -n pvxs-lab 2>/dev/null || echo "    (namespace not yet created)"
}

# ---------------------------------------------------------------------------
# Existing helpers — work on both Docker Desktop K8s and Kind
# ---------------------------------------------------------------------------

# Build the foundation images: epics-base:latest and pvxs:latest.
# These are the base layers consumed by cms_build_images.
# Runs pvxs/example/docker/build.sh which invokes both build_docker.sh scripts
# in order (epics-base → pvxs).  All arguments (e.g. --no-cache) are forwarded.
# Requires: PVXS_CMS to be set in the environment.
# Runs in a subshell so the directory change is contained, the build script's
# exit code is the function's exit code, and Ctrl-C aborts instead of being
# swallowed. The old trap/cd pattern returned the cd's success even when the
# build failed, letting `a && b` chains carry on past a failed build.
function spva_build_images {
    ( cd "${PVXS_CMS}/../pvxs/example/docker" && ./build.sh "$@" )
}

# Build the pvxs-cms image (pvxs-cms:dev) which sits on top of pvxs:latest.
# Runs pvxs-cms/example/docker/build.sh.
# All arguments (e.g. --no-cache) are forwarded.
# Requires: PVXS_CMS to be set in the environment.
function cms_build_images {
    ( cd "${PVXS_CMS}/example/docker" && ./build.sh "$@" )
}

function gw_build_images {
    (
        cd "${PVXS_CMS}/example/kubernetes/docker" || return 1
        local builder="./build.sh"
        if [[ "$1" == "gateway" || "$1" == "lab" || "$1" == "lab_tools" || "$1" == "lab_base" || "$1" == "idm" || "$1" == "testioc" || "$1" == "tstioc" || "$1" == "internet" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "cs-studio" ]]; then
            cd "$1" || return 1
            builder="./build_docker.sh"
            shift
        fi
        $builder "$@"
    )
}

# Runs in a subshell (like the build helpers): directory change contained,
# real exit code propagated, Ctrl-C aborts instead of being swallowed.
function gw_deploy {
    (
    cd "${PVXS_CMS}/example/kubernetes/helm" || return 1

    # Tag selector — dev branch defaults to "dev" (matches values.yaml). Pass
    # --tag latest to deploy the latest-tagged images instead. This MUST stay
    # in sync with the tag loaded by gw_kind_load_images on Kind clusters.
    local tag="latest"
    local reinstall=0
    local -a passthrough=()
    while (( $# > 0 )); do
        case "$1" in
            -r)
                reinstall=1
                shift
                ;;
            --tag)
                tag="${2:?--tag requires a value (latest|dev)}"
                shift 2
                ;;
            --tag=*)
                tag="${1#--tag=}"
                shift
                ;;
            *)
                passthrough+=("$1")
                shift
                ;;
        esac
    done

    if (( reinstall )); then
        kubectl delete jobs -n pvxs-lab -l app.kubernetes.io/instance=pvxs-lab --ignore-not-found
        helm uninstall pvxs-lab -n pvxs-lab
        while kubectl get pods -n pvxs-lab -l release=pvxs-lab --no-headers 2>/dev/null | grep -q .; do
            sleep 1
        done
        while kubectl get jobs -n pvxs-lab -l app.kubernetes.io/instance=pvxs-lab --no-headers 2>/dev/null | grep -q .; do
            sleep 1
        done
        gw_delete_cert_authority_state
    fi
    if [[ "$(kubectl config current-context 2>/dev/null)" == "${GW_KIND_CONTEXT}" ]]; then
        gw_kind_load_images --tag "${tag}" || return 1
    fi

    # Override every per-image tag in values.yaml. Keys must match the
    # `images.<key>.tag` paths defined there (see helm/pvxs-lab/values.yaml).
    local -a tag_overrides=(
        --set "images.idm.tag=${tag}"
        --set "images.internet.tag=${tag}"
        --set "images.testioc.tag=${tag}"
        --set "images.tstioc.tag=${tag}"
        --set "images.ml.tag=${tag}"
        --set "images.mlIoc.tag=${tag}"
        --set "images.gateway.tag=${tag}"
        --set "images.lab.tag=${tag}"
        --set "images.csStudio.tag=${tag}"
        --set "lab.image=lab:${tag}"
    )

    helm upgrade --install pvxs-lab pvxs-lab -n pvxs-lab --create-namespace \
        --set dockerRegistry=${DOCKER_REGISTRY} \
        --set dockerUsername=${DOCKER_USERNAME} \
        "${tag_overrides[@]}" "${passthrough[@]}" || return 1

    # Fixed tags like "latest" mean helm sees an unchanged manifest and leaves
    # running pods on the old image even after a newer one was loaded into the
    # node. Restart exactly the deployments whose image was just reloaded.
    if (( ${#GW_KIND_RELOADED_IMAGES[@]} )); then
        local _dep _img
        while read -r _dep _img; do
            if (( ${GW_KIND_RELOADED_IMAGES[(Ie)${_img}]} )); then
                echo "==> Restarting ${_dep} (image reloaded)"
                kubectl -n pvxs-lab rollout restart "deployment/${_dep}"
            fi
        done < <(kubectl -n pvxs-lab get deploy -o jsonpath='{range .items[*]}{.metadata.name} {.spec.template.spec.containers[0].image}{"\n"}{end}')
    fi
    )
}

function gw_undeploy {
  kubectl delete jobs -n pvxs-lab -l app.kubernetes.io/instance=pvxs-lab --ignore-not-found
  helm uninstall pvxs-lab -n pvxs-lab
  gw_delete_cert_authority_state
}

# The ca-keygen hook job creates the certificate authority secrets and the
# issuer-ids configmap with kubectl rather than helm, so helm uninstall leaves
# them behind and the next install sees them and keeps the old certificate
# authority. Delete them so a redeploy mints a fresh authority.
function gw_delete_cert_authority_state {
  kubectl delete secret -n pvxs-lab \
      pvxs-lab-ca-keychain pvxs-lab-lab-intermediate pvxs-lab-ml-intermediate \
      --ignore-not-found
  kubectl delete configmap -n pvxs-lab pvxs-lab-issuer-ids --ignore-not-found
}


function go_in_to {
  if [[ "$1" == "lab" ||  "$1" == "idm" ||  "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" || "$1" == "internet" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "ml-gateway" || "$1" == "cs-studio-lab" || "$1" == "cs-studio-ml" || "$1" == "cs-studio-internet" || "$1" == "cert-admin-lab" || "$1" == "cert-admin-ml" || "$1" == "cert-admin-internet" ]] ; then
   kubectl -n pvxs-lab exec -it deploy/pvxs-lab-$1 -- /bin/bash
  else
   echo "No such lab system: $1"
   false
  fi
}

function login_to_lab {
 if [[ "$1" == "guest" || "$1" == "operator" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-lab -- su - $1
 elif [[ "$1" == "admin" || "$1" == "idm" ]] ;  then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-idm -- su - $1
 elif [[ "$1" == "testioc" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-testioc -- su - $1
 elif [[ "$1" == "tstioc" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-tstioc -- su - $1
 elif [[ "$1" == "gateway" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-gateway -- su - $1
 else
  echo "No such lab user: $1"
  false
 fi
}

function login_from_internet() {
    local user="${1}"
    case "${user}" in
        guest|operator)
            kubectl -n pvxs-lab exec -it deployment/pvxs-lab-internet -- su - "${user}"
            ;;
        *)
            echo "Unknown internet user: ${user}. Valid: guest, operator"
            return 1
            ;;
    esac
}

function login_to_ml() {
    local user="${1}"
    case "${user}" in
        mloperator|mlsystem)
            kubectl -n pvxs-lab exec -it deployment/pvxs-lab-ml -- su - "${user}"
            ;;
        ml-gateway)
            kubectl -n pvxs-lab exec -it deployment/pvxs-lab-ml-gateway -- su - gateway
            ;;
        ml-ioc)
            kubectl -n pvxs-lab exec -it deployment/pvxs-lab-ml-ioc -- su - mlioc
            ;;
        *)
            echo "Unknown ML user: ${user}. Valid: mloperator, mlsystem, ml-gateway, ml-ioc"
            return 1
            ;;
    esac
}

function gw_cp {
  emulate -L zsh
  setopt local_options

  if (( $# < 3 || $# > 4 )); then
    echo "usage: gw_cp <sys> <user> <src> [dest]"
    echo "You gave $#"
    return 1
  fi

  local sys=$1
  local user=$2
  local src=$3
  local dst=${4:-./${src:t}}

  case "${sys}:${user}" in
    (gateway:gateway|idm:idm|testioc:testioc|tstioc:tstioc|idm:admin|lab:guest|lab:operator|internet:guest|internet:operator|ml:mloperator|ml:mlsystem|ml-ioc:mlioc|ml-gateway:gateway)
      ;;
    (*)
      echo "usage: gw_cp <sys> <user> <src> [dest]"
      echo "sys: gateway|idm|testioc|tstioc|lab|internet|ml|ml-ioc|ml-gateway"
      echo "user: gateway|idm|testioc|tstioc|admin|guest|operator|mloperator|mlsystem|mlioc"
      return 1
      ;;
  esac

  local POD
  POD=$(kubectl -n pvxs-lab get pod -l "app=$sys" -o jsonpath='{.items[0].metadata.name}') || return 1

  kubectl -n pvxs-lab exec -i "$POD" -- bash -lc \
    'su - "$1" -c "cat -- \"$2\""' _ "$user" "$src" > "$dst"
}

function gw_cp_in {
  emulate -L zsh
  setopt local_options

  if (( $# < 3 || $# > 4 )); then
    echo "usage: gw_cp <sys> <user> <src> [dest]"
    echo "You gave $#"
    return 1
  fi

  local sys=$1
  local user=$2
  local src=$3
  local dst=$4

  case "${sys}:${user}" in
    (gateway:gateway|idm:idm|testioc:testioc|tstioc:tstioc|idm:admin|lab:guest|lab:operator|internet:guest|internet:operator|ml:mloperator|ml:mlsystem|ml-ioc:mlioc|ml-gateway:gateway)
      ;;
    (*)
      echo "usage: gw_cp <sys> <user> <src> [dest]"
      echo "sys: gateway|idm|testioc|tstioc|lab|internet|ml|ml-ioc|ml-gateway"
      echo "user: gateway|idm|testioc|tstioc|admin|guest|operator|mloperator|mlsystem|mlioc"
      return 1
      ;;
  esac

  local POD
  POD=$(kubectl -n pvxs-lab get pod -l "app=$sys" -o jsonpath='{.items[0].metadata.name}') || return 1

  kubectl -n pvxs-lab cp $src "$POD:$dst"
}

function gw_log {
  if [[ "$1" == "lab" || "$1" == "idm" || "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" || "$1" == "internet" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "ml-gateway" || "$1" == "cs-studio-lab" || "$1" == "cs-studio-ml" || "$1" == "cs-studio-internet" || "$1" == "cert-admin-lab" || "$1" == "cert-admin-ml" || "$1" == "cert-admin-internet" ]] ; then
   kubectl logs -n pvxs-lab deployment/pvxs-lab-$1  -f
  else
   echo "No such lab system: $1"
   false
  fi
}

function cs_studio_lab() {
    kubectl port-forward deploy/pvxs-lab-cs-studio-lab 8080:8080 -n pvxs-lab
}

function cs_studio_ml() {
    kubectl port-forward deploy/pvxs-lab-cs-studio-ml 8081:8080 -n pvxs-lab
}

function cs_studio_internet() {
    kubectl port-forward deploy/pvxs-lab-cs-studio-internet 8082:8080 -n pvxs-lab
}

# The three certificate administration desktops. Separate ports from the control room
# displays, so an administrator desktop and the control room can be open at the same time.
function cert_admin_lab() {
    kubectl port-forward deploy/pvxs-lab-cert-admin-lab 8083:8080 -n pvxs-lab
}

function cert_admin_ml() {
    kubectl port-forward deploy/pvxs-lab-cert-admin-ml 8084:8080 -n pvxs-lab
}

function cert_admin_internet() {
    kubectl port-forward deploy/pvxs-lab-cert-admin-internet 8085:8080 -n pvxs-lab
}

function login_to_cert_admin_in_lab() {
    kubectl exec -it deploy/pvxs-lab-cert-admin-lab -n pvxs-lab -- su - ${1:-certadmin}
}

function login_to_cert_admin_in_ml() {
    kubectl exec -it deploy/pvxs-lab-cert-admin-ml -n pvxs-lab -- su - ${1:-mlcertadmin}
}

# The internet zone desktop carries no administrator: every view it shows is open to
# everyone, so it holds the ordinary internet zone viewer and nothing more.
function login_to_cert_admin_from_internet() {
    kubectl exec -it deploy/pvxs-lab-cert-admin-internet -n pvxs-lab -- su - ${1:-operator}
}

function login_to_cs_studio_in_lab() {
    kubectl exec -it deploy/pvxs-lab-cs-studio-lab -n pvxs-lab -- su - ${1:?Usage: login_to_cs_studio_lab <user>}
}

function login_to_cs_studio_in_ml() {
    kubectl exec -it deploy/pvxs-lab-cs-studio-ml -n pvxs-lab -- su - ${1:?Usage: login_to_cs_studio_ml <user>}
}

function login_to_cs_studio_from_internet() {
    kubectl exec -it deploy/pvxs-lab-cs-studio-internet -n pvxs-lab -- su - ${1:?Usage: login_to_cs_studio_internet <user>}
}

# ---------------------------------------------------------------------------
# go_tls — Provision and approve all TLS certificates for the lab cluster
# ---------------------------------------------------------------------------
# Idempotent: checks cert status via pvxcert before creating/approving.
# If a cert exists and is VALID, the step is skipped.
# If a cert exists but is REVOKED/EXPIRED, it is deleted and recreated.
# If a cert exists but is PENDING_APPROVAL, it is approved (not recreated).
#
# Order (critical — gateways must be approved BEFORE restart):
#   1. Kerberos client certs (lab + ml zones) — auto-approved
#   2. Standard client certs (internet zone) — create, approve
#   3. IOC server certs — create, approve, restart IOCs
#   4. Gateway ioc certs — create ALL, approve ALL, restart ALL
# ---------------------------------------------------------------------------
function go_tls() {
    emulate -L zsh
    setopt local_options err_return

    local NS="pvxs-lab"
    local -a CERT_IDS_TO_APPROVE=()
    local -i CHANGES=0

    _tls_exec() {
        local app=$1 user=$2; shift 2
        kubectl -n $NS exec deploy/pvxs-lab-$app -- bash -c "su - $user -c 'source ~/.${user}_bashrc 2>/dev/null; $*'"
    }

    _tls_cert_status() {
        local app=$1 user=$2 p12=${3:-}
        local pvxcert_args=""
        if [[ -n "$p12" ]]; then pvxcert_args="-f $p12"; fi
        local output
        output=$(_tls_exec $app $user "pvxcert $pvxcert_args 2>&1") 2>/dev/null || true
        local cstatus=$(echo "$output" | awk '/^Status/ {sub(/^Status *: */, ""); print; exit}')
        local cid=$(echo "$output" | awk '/^Certificate ID/ {sub(/^Certificate ID *: */, ""); print; exit}')
        echo "${cstatus:-NONE}|${cid:-NONE}"
    }

    _tls_delete_cert() {
        local app=$1 user=$2
        echo "  [delete] stale cert on $app/$user"
        _tls_exec $app $user "rm -f ~/.config/pva/1.5/client.p12 ~/.config/pva/1.5/server.p12" 2>/dev/null || true
        local keychain=$(_tls_exec $app $user 'echo ${EPICS_PVAS_TLS_KEYCHAIN:-}' 2>/dev/null || true)
        if [[ -n "$keychain" ]]; then
            _tls_exec $app $user "rm -f $keychain" 2>/dev/null || true
        fi
    }

    _tls_ensure_krb_cert() {
        local app=$1 user=$2 principal=$3 authn_flags=${4:-}
        local info=$(_tls_cert_status $app $user "~/.config/pva/1.5/client.p12")
        local cstatus=${info%%|*}
        local cert_id=${info#*|}

        case "$cstatus" in
            VALID)
                echo "  [ok] $principal on $app/$user ($cert_id)"
                return 0 ;;
            REVOKED|EXPIRED)
                echo "  [terminal] $cstatus — deleting and recreating"
                _tls_delete_cert $app $user ;;
            PENDING_APPROVAL)
                echo "  [approve-needed] $principal on $app/$user ($cert_id)"
                CERT_IDS_TO_APPROVE+=("$cert_id")
                CHANGES+=1
                return 0 ;;
        esac

        echo "  [krb] $principal on $app/$user"
        _tls_exec $app $user "echo secret | kinit $principal && authnkrb $authn_flags"
        CHANGES+=1
    }

    _tls_ensure_std_cert() {
        local app=$1 user=$2 authn_flags=$3
        local p12="~/.config/pva/1.5/client.p12"
        case "$authn_flags" in
            *-u\ server*) p12="~/.config/pva/1.5/server.p12" ;;
            *-u\ ioc*)    p12="\${EPICS_PVAS_TLS_KEYCHAIN:-~/.config/pva/1.5/server.p12}" ;;
        esac
        local info=$(_tls_cert_status $app $user "$p12")
        local cstatus=${info%%|*}
        local cert_id=${info#*|}

        case "$cstatus" in
            VALID)
                echo "  [ok] $user on $app ($cert_id)"
                return 0 ;;
            REVOKED|EXPIRED)
                echo "  [terminal] $cstatus — deleting and recreating"
                _tls_delete_cert $app $user ;;
            PENDING_APPROVAL|PENDING)
                echo "  [approve-needed] $user on $app ($cert_id)"
                CERT_IDS_TO_APPROVE+=("$cert_id")
                CHANGES+=1
                return 0 ;;
        esac

        echo "  [std] $user on $app ${authn_flags:+($authn_flags)}"
        local output
        output=$(_tls_exec $app $user "authnstd $authn_flags")
        echo "$output"
        cert_id=$(echo "$output" | grep -oE '[a-f0-9]{8}:[0-9]+' | head -1)
        if [[ -n "$cert_id" ]]; then
            CERT_IDS_TO_APPROVE+=("$cert_id")
        fi
        CHANGES+=1
    }

    # Federated lab: a cert must be approved on the PVACMS that ISSUED it (there is
    # no cluster sync). Lab-department certs are issued by the Lab (idm) PVACMS and
    # approved there; ML-department certs are issued by the ML PVACMS and approved on
    # the ml pod via a local admin (the ml pod runs an admin user). Pass the approving
    # node: "idm" (default) or "ml".
    _tls_approve_all() {
        local node=${1:-idm}
        if (( ${#CERT_IDS_TO_APPROVE[@]} == 0 )); then return 0; fi
        local id
        for id in "${CERT_IDS_TO_APPROVE[@]}"; do
            echo "  [approve on $node] $id"
            if [[ "$node" == "ml" ]]; then
                # Approve on the ML PVACMS directly (localhost) as the admin user.
                # Secure transport, because an administrator decision requires a
                # certificate from this department's own authority presented over TLS.
                kubectl -n $NS exec deploy/pvxs-lab-ml -- bash -c \
                    "su - admin -c 'source ~/.admin_bashrc 2>/dev/null; export EPICS_PVA_NAME_SERVERS=pvas://localhost:5076; pvxcert --approve $id'" || {
                        echo "  [retry] $id on ml"; sleep 3
                        kubectl -n $NS exec deploy/pvxs-lab-ml -- bash -c \
                            "su - admin -c 'source ~/.admin_bashrc 2>/dev/null; export EPICS_PVA_NAME_SERVERS=pvas://localhost:5076; pvxcert --approve $id'"
                    }
            else
                _tls_exec idm admin "pvxcert --approve $id" || {
                    echo "  [retry] $id on idm"; sleep 3
                    _tls_exec idm admin "pvxcert --approve $id"
                }
            fi
        done
        CERT_IDS_TO_APPROVE=()
    }

    # -----------------------------------------------------------------------
    echo "\n=== Step 1: Kerberos client certs (lab zone) ==="
    # -----------------------------------------------------------------------
    _tls_ensure_krb_cert cs-studio-lab operator "operator@EPICS.ORG"
    _tls_ensure_krb_cert cs-studio-lab guest    "guest@EPICS.ORG"
    _tls_approve_all

    # -----------------------------------------------------------------------
    echo "\n=== Step 2: Kerberos client certs (ML zone) ==="
    # -----------------------------------------------------------------------
    # ML-zone client pods target the ML PVACMS (EPICS_PVA_AUTH_ISSUER=ML issuer),
    # so their certs are issued by - and approved on - the ML PVACMS.
    _tls_ensure_krb_cert cs-studio-ml mloperator "mloperator@EPICS.ORG"
    _tls_ensure_krb_cert cs-studio-ml mlsystem  "mlsystem@EPICS.ORG"
    _tls_approve_all ml

    # -----------------------------------------------------------------------
    echo "\n=== Step 3: Standard client certs (internet zone) ==="
    # -----------------------------------------------------------------------
    _tls_ensure_std_cert cs-studio-internet operator "-u client"
    _tls_ensure_std_cert cs-studio-internet guest    "-u client"
    _tls_approve_all

    # -----------------------------------------------------------------------
    echo "\n=== Step 4: IOC server certs ==="
    # -----------------------------------------------------------------------
    local pre_ioc=$CHANGES
    # Lab IOCs: issued by / approved on the Lab (idm) PVACMS.
    _tls_ensure_std_cert testioc testioc "-u server"
    _tls_ensure_std_cert tstioc  tstioc  "-u server"
    _tls_approve_all idm
    # ML IOC: issued by / approved on the ML PVACMS.
    _tls_ensure_std_cert ml-ioc  mlioc   "-u server"
    _tls_approve_all ml

    if (( CHANGES > pre_ioc )); then
        echo "  [restart] testioc, tstioc, ml-ioc"
        kubectl -n $NS exec deploy/pvxs-lab-testioc -- supervisorctl restart testioc
        kubectl -n $NS exec deploy/pvxs-lab-tstioc  -- supervisorctl restart tstioc
        kubectl -n $NS exec deploy/pvxs-lab-ml-ioc  -- supervisorctl restart mlioc
    else
        echo "  [skip restart] IOCs (all certs already valid)"
    fi

    # -----------------------------------------------------------------------
    echo "\n=== Step 5: Gateway certs (each approved on its own department's PVACMS, restart ALL) ==="
    # -----------------------------------------------------------------------
    # No cluster sync in the federated lab: the lab gateway cert is issued by /
    # approved on the Lab (idm) PVACMS; the ml-gateway cert is issued by / approved
    # on the ML PVACMS. Each is valid on its own CMS immediately (no sync wait).
    local pre_gw=$CHANGES
    _tls_ensure_std_cert gateway    gateway "-u ioc"
    _tls_approve_all idm
    _tls_ensure_std_cert ml-gateway gateway "-u ioc -n ml-gateway"
    _tls_approve_all ml

    if (( CHANGES > pre_gw )); then
        echo "  [restart] gateway, ml-gateway"
        kubectl -n $NS exec deploy/pvxs-lab-gateway    -c gateway    -- supervisorctl restart gateway
        kubectl -n $NS exec deploy/pvxs-lab-ml-gateway -c ml-gateway -- supervisorctl restart gateway
    else
        echo "  [skip restart] gateways (all certs already valid)"
    fi

    # -----------------------------------------------------------------------
    echo "\n\n=== TLS setup complete ($CHANGES changes) ==="
    if (( CHANGES == 0 )); then
        echo "All certs already valid. No changes made."
    else
        echo "Certs provisioned/approved. Services restarted."
    fi
    echo "Verify: login_to_cs_studio_in_lab operator → pvxinfo -v test:spec"
}
