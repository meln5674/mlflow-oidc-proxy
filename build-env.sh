#!/bin/bash -xeu

GOPATH=${GOPATH:-~/go}

BOOTSTRAP_GO_IMAGE=docker.io/library/golang:1.19

run_flags=(
    --rm
    --network=host
    --dns-opt='options single-request'
    -e GOPATH
    -e HOME
    -e GOPRIVATE
    -e GONOSUMDB
    -e GOPROXY
    -v ${HOME}:${HOME}
    -v ${GOPATH}:${GOPATH}
    -v ${PWD}:${PWD}
    -v /var/run/docker.sock:/var/run/docker.sock
    -w ${PWD} 
    -u $(id -u):$(id -g) --group-add $(getent group docker | awk -F ':' '{ print $3 }')
)


GO_ARCH=$(docker run "${run_flags[@]}" "${BOOTSTRAP_GO_IMAGE}" go env GOARCH)
GO_OS=$(docker run "${run_flags[@]}" "${BOOTSTRAP_GO_IMAGE}" go env GOOS)
GINKGO_VERSION=$(docker run "${run_flags[@]}" "${BOOTSTRAP_GO_IMAGE}" go mod edit -print | grep ginkgo | cut -d ' ' -f2)

build_flags=( 
    -f make-env.Dockerfile 
    --build-arg GO_ARCH="${GO_ARCH}" 
    --build-arg GO_OS="${GO_OS}" 
    --build-arg GINKGO_VERSION="${GINKGO_VERSION}"
    --build-arg MAKE_ENV_CURL='curl -4'
)

docker build "${build_flags[@]}" .

build_flags+=( -q )
image=$(docker build "${build_flags[@]}" .)

run_flags+=( -i )

if [ -t 1 ] ; then
    run_flags+=( -t )
fi

cmd=( "$@" )

if [ -z "${1:-}" ]; then
    cmd=( bash )
fi

docker run "${run_flags[@]}" "${image}" "${cmd[@]}"

