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

    local force=0
    if [[ "$1" == "--force" || "$1" == "-f" ]]; then
        force=1
        shift
    fi

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

    echo "==> Loading ${#image_names[@]} app images + ${#extra_images[@]} utility images into Kind ..."

    local -a full_refs=()
    for name in "${image_names[@]}"; do
        full_refs+=("${registry}/${username}/${name}:latest")
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
            fi
        fi
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

function gw_build_images {
 pushd $PVXS_CMS/example/kubernetes/docker
 builder="./build.sh"
  if [[ "$1" == "gateway" || "$1" == "lab" || "$1" == "lab_base" || "$1" == "idm" || "$1" == "testioc" || "$1" == "tstioc" || "$1" == "internet" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "cs-studio" ]]
 then
 	cd $1
 	builder="./build_docker.sh"
 	shift
 fi
 $builder $*
 popd
}

function gw_deploy {
 pushd $PVXS_CMS/example/kubernetes/helm
 if [[ "$1" == "-r" ]] ; then
   kubectl delete jobs -n pvxs-lab -l app.kubernetes.io/instance=pvxs-lab --ignore-not-found
    helm uninstall pvxs-lab -n pvxs-lab
    while kubectl get pods -n pvxs-lab -l release=pvxs-lab --no-headers 2>/dev/null | grep -q .; do
      sleep 1
    done
    while kubectl get jobs -n pvxs-lab -l app.kubernetes.io/instance=pvxs-lab --no-headers 2>/dev/null | grep -q .; do
      sleep 1
    done
    shift
  fi
 if [[ "$(kubectl config current-context 2>/dev/null)" == "${GW_KIND_CONTEXT}" ]]; then
    gw_kind_load_images || { popd; return 1; }
 fi
 helm upgrade --install pvxs-lab pvxs-lab -n pvxs-lab --create-namespace \
  --set dockerRegistry=${DOCKER_REGISTRY} \
  --set dockerUsername=${DOCKER_USERNAME} ${*}
 popd
}

function gw_undeploy {
  kubectl delete jobs -n pvxs-lab -l app.kubernetes.io/instance=pvxs-lab --ignore-not-found
  helm uninstall pvxs-lab -n pvxs-lab
}


function go_in_to {
  if [[ "$1" == "lab" ||  "$1" == "idm" ||  "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" || "$1" == "internet" || "$1" == "it" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "ml-gateway" || "$1" == "cs-studio-lab" || "$1" == "cs-studio-ml" || "$1" == "cs-studio-internet" ]] ; then
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
 elif [[ "$1" == "it" ]] ; then
  kubectl -n pvxs-lab exec -it deploy/pvxs-lab-it -- su - idm
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
    (gateway:gateway|idm:idm|testioc:testioc|tstioc:tstioc|idm:admin|lab:guest|lab:operator|internet:guest|internet:operator|it:idm|it:admin|ml:mloperator|ml:mlsystem|ml-ioc:mlioc|ml-gateway:gateway)
      ;;
    (*)
      echo "usage: gw_cp <sys> <user> <src> [dest]"
      echo "sys: gateway|idm|testioc|tstioc|lab|internet|it|ml|ml-ioc|ml-gateway"
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
    (gateway:gateway|idm:idm|testioc:testioc|tstioc:tstioc|idm:admin|lab:guest|lab:operator|internet:guest|internet:operator|it:idm|it:admin|ml:mloperator|ml:mlsystem|ml-ioc:mlioc|ml-gateway:gateway)
      ;;
    (*)
      echo "usage: gw_cp <sys> <user> <src> [dest]"
      echo "sys: gateway|idm|testioc|tstioc|lab|internet|it|ml|ml-ioc|ml-gateway"
      echo "user: gateway|idm|testioc|tstioc|admin|guest|operator|mloperator|mlsystem|mlioc"
      return 1
      ;;
  esac

  local POD
  POD=$(kubectl -n pvxs-lab get pod -l "app=$sys" -o jsonpath='{.items[0].metadata.name}') || return 1

  kubectl -n pvxs-lab cp $src "$POD:$dst"
}

function gw_log {
  if [[ "$1" == "lab" || "$1" == "idm" || "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" || "$1" == "internet" || "$1" == "it" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "ml-gateway" || "$1" == "cs-studio-lab" || "$1" == "cs-studio-ml" || "$1" == "cs-studio-internet" ]] ; then
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
# Creates certs in the correct order so that gateway certs are approved
# BEFORE the gateways are restarted, avoiding the chicken-and-egg deadlock
# where an unapproved gateway cert breaks cluster sync.
#
# Order:
#   1. Kerberos-authenticated client certs (lab + ml zones)
#   2. Standard-authenticated client certs (internet zone)
#   3. IOC server certs (testioc, tstioc, ml-ioc) + restart IOCs
#   4. Gateway ioc certs (lab gateway, ml gateway) + restart gateways
# ---------------------------------------------------------------------------
function go_tls() {
    emulate -L zsh
    setopt local_options err_return

    local NS="pvxs-lab"
    local -a CERT_IDS_TO_APPROVE=()

    _tls_exec() {
        local app=$1 user=$2; shift 2
        kubectl -n $NS exec deploy/pvxs-lab-$app -- bash -c "su - $user -c 'source ~/.${user}_bashrc 2>/dev/null; $*'"
    }

    _tls_has_cert() {
        local app=$1 user=$2 p12=$3
        kubectl -n $NS exec deploy/pvxs-lab-$app -- bash -c "su - $user -c 'test -f $p12'" 2>/dev/null
    }

    _tls_krb_cert() {
        local app=$1 user=$2 principal=$3 authn_flags=${4:-}
        local p12="\$HOME/.config/pva/1.5/client.p12"
        if _tls_has_cert $app $user "$p12"; then
            echo "  [skip] $principal on $app/$user (cert exists)"
            return 0
        fi
        echo "  [krb] $principal on $app/$user ${authn_flags:+($authn_flags)}"
        _tls_exec $app $user "echo secret | kinit $principal && authnkrb $authn_flags"
    }

    _tls_std_cert() {
        local app=$1 user=$2 authn_flags=$3
        local p12
        case "$authn_flags" in
            *-u\ server*) p12="\$HOME/.config/pva/1.5/server.p12" ;;
            *-u\ ioc*)    p12="\$(source ~/.${user}_bashrc 2>/dev/null; echo \${EPICS_PVAS_TLS_KEYCHAIN:-\$HOME/.config/pva/1.5/server.p12})" ;;
            *)            p12="\$HOME/.config/pva/1.5/client.p12" ;;
        esac
        if _tls_has_cert $app $user "$p12"; then
            echo "  [skip] $user on $app (cert exists)"
            return 0
        fi
        echo "  [std] $user on $app ${authn_flags:+($authn_flags)}"
        local output
        output=$(_tls_exec $app $user "authnstd $authn_flags")
        echo "$output"
        local cert_id
        cert_id=$(echo "$output" | grep -oE '[a-f0-9]{8}:[0-9]+' | head -1)
        if [[ -n "$cert_id" ]]; then
            CERT_IDS_TO_APPROVE+=("$cert_id")
        fi
    }

    _tls_approve_all() {
        if (( ${#CERT_IDS_TO_APPROVE[@]} == 0 )); then
            return 0
        fi
        local id
        for id in "${CERT_IDS_TO_APPROVE[@]}"; do
            echo "  [approve] $id"
            _tls_exec idm admin "pvxcert --approve $id" || {
                echo "  [retry after sync delay] $id"
                sleep 5
                _tls_exec idm admin "pvxcert --approve $id"
            }
        done
        CERT_IDS_TO_APPROVE=()
    }

    # -----------------------------------------------------------------------
    echo "=== Step 1: Kerberos client certs (lab zone) ==="
    # -----------------------------------------------------------------------
    _tls_krb_cert cs-studio-lab operator "operator@EPICS.ORG"
    _tls_krb_cert cs-studio-lab guest    "guest@EPICS.ORG"

    # -----------------------------------------------------------------------
    echo "=== Step 2: Kerberos client certs (ML zone) ==="
    # -----------------------------------------------------------------------
    _tls_krb_cert cs-studio-ml mloperator "mloperator@EPICS.ORG"
    _tls_krb_cert cs-studio-ml mlsystem  "mlsystem@EPICS.ORG"

    # -----------------------------------------------------------------------
    echo "=== Step 3: Standard client certs (internet zone) — need approval ==="
    # -----------------------------------------------------------------------
    _tls_std_cert cs-studio-internet operator "-u client"
    _tls_std_cert cs-studio-internet guest    "-u client"
    _tls_approve_all

    # -----------------------------------------------------------------------
    echo "=== Step 4: IOC server certs — need approval + restart ==="
    # -----------------------------------------------------------------------
    _tls_std_cert testioc testioc "-u server"
    _tls_std_cert tstioc  tstioc  "-u server"
    _tls_std_cert ml-ioc  mlioc   "-u server"
    local ioc_new=${#CERT_IDS_TO_APPROVE[@]}
    _tls_approve_all

    if (( ioc_new > 0 )); then
        echo "  [restart] testioc, tstioc, ml-ioc"
        kubectl -n $NS exec deploy/pvxs-lab-testioc -- supervisorctl restart testioc
        kubectl -n $NS exec deploy/pvxs-lab-tstioc  -- supervisorctl restart tstioc
        kubectl -n $NS exec deploy/pvxs-lab-ml-ioc  -- supervisorctl restart mlioc
    else
        echo "  [skip restart] IOCs (no new certs)"
    fi

    # -----------------------------------------------------------------------
    echo "=== Step 5: Gateway ioc certs — need approval + restart ==="
    # -----------------------------------------------------------------------
    _tls_std_cert gateway    gateway "-u ioc"
    _tls_std_cert ml-gateway gateway "-u ioc -n ml-gateway"
    local gw_new=${#CERT_IDS_TO_APPROVE[@]}
    _tls_approve_all

    if (( gw_new > 0 )); then
        echo "  [restart] gateway, ml-gateway"
        kubectl -n $NS exec deploy/pvxs-lab-gateway    -c gateway    -- supervisorctl restart gateway
        kubectl -n $NS exec deploy/pvxs-lab-ml-gateway -c ml-gateway -- supervisorctl restart gateway
    else
        echo "  [skip restart] gateways (no new certs)"
    fi

    # -----------------------------------------------------------------------
    echo ""
    echo "=== TLS setup complete ==="
    echo "All certs provisioned and approved. Gateways and IOCs restarted."
    echo "Verify: login_to_cs_studio_in_lab operator → pvxinfo -v test:spec"
}
