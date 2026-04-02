#!/usr/bin/env zsh

function gw_build_images {
 pushd $PVXS_CMS/example/kubernetes/docker
 builder="./build.sh"
 if [[ "$1" == "gateway" || "$1" == "lab" || "$1" == "lab_base" || "$1" == "idm" || "$1" == "testioc" || "$1" == "tstioc" || "$1" == "internet" || "$1" == "ml" || "$1" == "ml-ioc" ]]
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
 if [[ "$1" == "lab" ||  "$1" == "idm" ||  "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" || "$1" == "internet" || "$1" == "it" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "ml-gateway" ]] ; then
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
 if [[ "$1" == "lab" || "$1" == "idm" || "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" || "$1" == "internet" || "$1" == "it" || "$1" == "ml" || "$1" == "ml-ioc" || "$1" == "ml-gateway" ]] ; then
  kubectl logs -n pvxs-lab deployment/pvxs-lab-$1  -f
 else
  echo "No such lab system: $1"
  false
 fi
}
