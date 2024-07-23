
ARG DOCKER_ARCH=x86_64
ARG GO_ARCH=$(shell go env GOARCH)
ARG GO_OS=$(shell go env GOOS)
ARG MAKE_ENV_BASE64=base64
ARG MAKE_ENV_CHMOD=chmod
ARG MAKE_ENV_CURL=curl
ARG MAKE_ENV_GO=go
ARG MAKE_ENV_LN=ln
ARG MAKE_ENV_MKDIR=mkdir
ARG MAKE_ENV_MV=mv
ARG MAKE_ENV_RM=rm
ARG MAKE_ENV_TAR=tar
ARG MAKE_ENV_TOUCH=touch
ARG MAKE_ENV_UNZIP=unzip
FROM docker.io/alpine/curl:8.8.0 AS make-env-docker
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS
ARG DOCKER_MIRROR=https://download.docker.com/linux/static/stable
ARG DOCKER_VERSION=27.1.0

ARG DOCKER_URL=${DOCKER_MIRROR}/${DOCKER_ARCH}/docker-${DOCKER_VERSION}.tgz
RUN ${MAKE_ENV_MKDIR} -p /opt/make-env/download /opt/make-env/bin \
 && ${MAKE_ENV_CURL} -vfL ${DOCKER_URL} | tar -x -z  -C /opt/make-env/download docker/docker \
 && ${MAKE_ENV_MV} /opt/make-env/download/docker/docker /opt/make-env/bin/docker \
 && ${MAKE_ENV_CHMOD} +x /opt/make-env/bin/docker
FROM docker.io/alpine/curl:8.8.0 AS make-env-docker-buildx
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS
ARG DOCKER_BUILDX_MIRROR=https://github.com/docker/buildx/releases/download
ARG DOCKER_BUILDX_VERSION=v0.16.1

ARG DOCKER_BUILDX_URL=${DOCKER_BUILDX_MIRROR}/${DOCKER_BUILDX_VERSION}/buildx-${DOCKER_BUILDX_VERSION}.${GO_OS}-${GO_ARCH} 

RUN ${MAKE_ENV_MKDIR} -p /opt/make-env/download /opt/make-env/bin \
 && ${MAKE_ENV_CURL} -vfL ${DOCKER_BUILDX_URL} -o /opt/make-env/bin/docker-buildx \
 && ${MAKE_ENV_CHMOD} +x /opt/make-env/bin/docker-buildx
FROM docker.io/library/golang:1.19 AS make-env-ginkgo
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS
ARG GINKGO_VERSION=$(shell go mod edit -print | grep ginkgo | cut -d ' ' -f2)

RUN GOBIN=/opt/make-env/bin \
    ${MAKE_ENV_GO} install \
    	github.com/onsi/ginkgo/v2/ginkgo@${GINKGO_VERSION}
FROM docker.io/alpine/curl:8.8.0 AS make-env-helm
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS
ARG HELM_MIRROR=https://dl.k8s.io/release
ARG HELM_VERSION=v3.12.2

ARG HELM_URL=https://get.helm.sh/helm-${HELM_VERSION}-${GO_OS}-${GO_ARCH}.tar.gz
RUN ${MAKE_ENV_MKDIR} -p /opt/make-env/download /opt/make-env/bin \
 && ${MAKE_ENV_CURL} -vfL ${HELM_URL} | tar -x -z  -C /opt/make-env/download ${GO_OS}-${GO_ARCH}/helm \
 && ${MAKE_ENV_MV} /opt/make-env/download/${GO_OS}-${GO_ARCH}/helm /opt/make-env/bin/helm \
 && ${MAKE_ENV_CHMOD} +x /opt/make-env/bin/helm
FROM docker.io/library/golang:1.19 AS make-env-helm-hog
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS

RUN GOBIN=/opt/make-env/bin \
    ${MAKE_ENV_GO} install \
    	github.com/meln5674/helm-hog@3af9ec621dcc359e38e966a255571a39beefe624
FROM docker.io/alpine/curl:8.8.0 AS make-env-kind
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS
ARG KIND_MIRROR=https://github.com/kubernetes-sigs/kind/releases/download
ARG KIND_VERSION=v0.17.0

ARG KIND_URL=${KIND_MIRROR}/${KIND_VERSION}/kind-${GO_OS}-${GO_ARCH} 

RUN ${MAKE_ENV_MKDIR} -p /opt/make-env/download /opt/make-env/bin \
 && ${MAKE_ENV_CURL} -vfL ${KIND_URL} -o /opt/make-env/bin/kind \
 && ${MAKE_ENV_CHMOD} +x /opt/make-env/bin/kind
FROM docker.io/alpine/curl:8.8.0 AS make-env-kubectl
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS
ARG KUBECTL_MIRROR=https://dl.k8s.io/release
ARG KUBECTL_VERSION=v1.25.11

ARG KUBECTL_URL=${KUBECTL_MIRROR}/${KUBECTL_VERSION}/bin/${GO_OS}/${GO_ARCH}/kubectl 

RUN ${MAKE_ENV_MKDIR} -p /opt/make-env/download /opt/make-env/bin \
 && ${MAKE_ENV_CURL} -vfL ${KUBECTL_URL} -o /opt/make-env/bin/kubectl \
 && ${MAKE_ENV_CHMOD} +x /opt/make-env/bin/kubectl
FROM docker.io/alpine/curl:8.8.0 AS make-env-yq
ARG MAKE_ENV_BASE64
ARG MAKE_ENV_CHMOD
ARG MAKE_ENV_CURL
ARG MAKE_ENV_GO
ARG MAKE_ENV_LN
ARG MAKE_ENV_MKDIR
ARG MAKE_ENV_MV
ARG MAKE_ENV_RM
ARG MAKE_ENV_TAR
ARG MAKE_ENV_TOUCH
ARG MAKE_ENV_UNZIP
ARG DOCKER_ARCH
ARG GO_ARCH
ARG GO_OS
ARG YQ_MIRROR=github.com/mikefarah/yq/releases/download
ARG YQ_VERSION=v4.44.1

ARG YQ_URL=https://${YQ_MIRROR}/${YQ_VERSION}/yq_${GO_OS}_${GO_ARCH}.tar.gz
RUN ${MAKE_ENV_MKDIR} -p /opt/make-env/download /opt/make-env/bin \
 && ${MAKE_ENV_CURL} -vfL ${YQ_URL} | tar -x -z  -C /opt/make-env/download ./yq_${GO_OS}_${GO_ARCH} \
 && ${MAKE_ENV_MV} /opt/make-env/download/./yq_${GO_OS}_${GO_ARCH} /opt/make-env/bin/yq \
 && ${MAKE_ENV_CHMOD} +x /opt/make-env/bin/yq

FROM docker.io/library/golang:1.20.4
ARG LOCALBIN=/usr/bin
ENV LOCALBIN=${LOCALBIN}
ENV PATH=${PATH}:${LOCALBIN}
COPY --from=make-env-docker /opt/make-env/bin/. ${LOCALBIN}/
COPY --from=make-env-docker-buildx /opt/make-env/bin/. ${LOCALBIN}/
COPY --from=make-env-ginkgo /opt/make-env/bin/. ${LOCALBIN}/
COPY --from=make-env-helm /opt/make-env/bin/. ${LOCALBIN}/
COPY --from=make-env-helm-hog /opt/make-env/bin/. ${LOCALBIN}/
COPY --from=make-env-kind /opt/make-env/bin/. ${LOCALBIN}/
COPY --from=make-env-kubectl /opt/make-env/bin/. ${LOCALBIN}/
COPY --from=make-env-yq /opt/make-env/bin/. ${LOCALBIN}/
RUN mkdir -p /usr/lib/docker/cli-plugins \
 && ln -s ${LOCALBIN}/docker-buildx /usr/lib/docker/cli-plugins/


