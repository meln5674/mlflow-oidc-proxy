
DOCKER_ARCH ?= x86_64
GO_ARCH ?= $(shell go env GOARCH)
GO_OS ?= $(shell go env GOOS)
MAKE_ENV_BASE64 ?= $(shell command -v base64)
$(MAKE_ENV_BASE64): 
ifeq ($(MAKE_ENV_BASE64),)
	echo "MAKE_ENV_BASE64 does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_BASE64) >/dev/null
endif
MAKE_ENV_CHMOD ?= $(shell command -v chmod)
$(MAKE_ENV_CHMOD): 
ifeq ($(MAKE_ENV_CHMOD),)
	echo "MAKE_ENV_CHMOD does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_CHMOD) >/dev/null
endif
MAKE_ENV_CURL ?= $(shell command -v curl)
$(MAKE_ENV_CURL): 
ifeq ($(MAKE_ENV_CURL),)
	echo "MAKE_ENV_CURL does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_CURL) >/dev/null
endif
MAKE_ENV_GO ?= $(shell command -v go)
$(MAKE_ENV_GO): 
ifeq ($(MAKE_ENV_GO),)
	echo "MAKE_ENV_GO does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_GO) >/dev/null
endif
MAKE_ENV_LN ?= $(shell command -v ln)
$(MAKE_ENV_LN): 
ifeq ($(MAKE_ENV_LN),)
	echo "MAKE_ENV_LN does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_LN) >/dev/null
endif
MAKE_ENV_MKDIR ?= $(shell command -v mkdir)
$(MAKE_ENV_MKDIR): 
ifeq ($(MAKE_ENV_MKDIR),)
	echo "MAKE_ENV_MKDIR does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_MKDIR) >/dev/null
endif
MAKE_ENV_RM ?= $(shell command -v rm)
$(MAKE_ENV_RM): 
ifeq ($(MAKE_ENV_RM),)
	echo "MAKE_ENV_RM does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_RM) >/dev/null
endif
MAKE_ENV_TAR ?= $(shell command -v tar)
$(MAKE_ENV_TAR): 
ifeq ($(MAKE_ENV_TAR),)
	echo "MAKE_ENV_TAR does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_TAR) >/dev/null
endif
MAKE_ENV_TOUCH ?= $(shell command -v touch)
$(MAKE_ENV_TOUCH): 
ifeq ($(MAKE_ENV_TOUCH),)
	echo "MAKE_ENV_TOUCH does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_TOUCH) >/dev/null
endif
MAKE_ENV_UNZIP ?= $(shell command -v unzip)
$(MAKE_ENV_UNZIP): 
ifeq ($(MAKE_ENV_UNZIP),)
	echo "MAKE_ENV_UNZIP does not exist/is not on the path"
	exit 1
else
	stat $(MAKE_ENV_UNZIP) >/dev/null
endif
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	$(MAKE_ENV_MKDIR) -p $(LOCALBIN)
	$(MAKE_ENV_TOUCH) $(LOCALBIN)
$(LOCALBIN)/: $(LOCALBIN) 


DOCKER ?= $(LOCALBIN)/docker
DOCKER_MIRROR ?= https://download.docker.com/linux/static/stable
DOCKER_VERSION ?= 27.1.0

DOCKER_URL ?= $(DOCKER_MIRROR)/$(DOCKER_ARCH)/docker-$(DOCKER_VERSION).tgz
$(DOCKER):  	
	
	$(MAKE_ENV_MKDIR) -p $(LOCALBIN)/.make-env/http/$(shell echo $(DOCKER_URL) | base64 -w0)
	$(MAKE_ENV_CURL) -vfL $(DOCKER_URL) | tar -x -z  -C $(LOCALBIN)/.make-env/http/$(shell echo $(DOCKER_URL) | base64 -w0) docker/docker
	$(MAKE_ENV_CHMOD) +x $(LOCALBIN)/.make-env/http/$(shell echo $(DOCKER_URL) | base64 -w0)/docker/docker
	$(MAKE_ENV_RM) -f $(DOCKER)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/http/$(shell echo $(DOCKER_URL) | base64 -w0)/docker/docker $(DOCKER)

.PHONY: docker
docker: $(DOCKER)



DOCKER_BUILDX ?= $(LOCALBIN)/docker-buildx
DOCKER_BUILDX_MIRROR ?= https://github.com/docker/buildx/releases/download
DOCKER_BUILDX_VERSION ?= v0.16.1

DOCKER_BUILDX_URL ?= $(DOCKER_BUILDX_MIRROR)/$(DOCKER_BUILDX_VERSION)/buildx-$(DOCKER_BUILDX_VERSION).$(GO_OS)-$(GO_ARCH)
$(DOCKER_BUILDX):  	
	
	$(MAKE_ENV_MKDIR) -p $(LOCALBIN)/.make-env/http
	$(MAKE_ENV_CURL) -vfL $(DOCKER_BUILDX_URL) -o $(LOCALBIN)/.make-env/http$(shell echo $(DOCKER_BUILDX_URL) | base64 -w0)
	$(MAKE_ENV_CHMOD) +x $(LOCALBIN)/.make-env/http$(shell echo $(DOCKER_BUILDX_URL) | base64 -w0)
	$(MAKE_ENV_RM) -f $(DOCKER_BUILDX)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/http$(shell echo $(DOCKER_BUILDX_URL) | base64 -w0) $(DOCKER_BUILDX)

.PHONY: docker-buildx
docker-buildx: $(DOCKER_BUILDX)



GINKGO ?= $(LOCALBIN)/ginkgo
GINKGO_VERSION ?= $(shell go mod edit -print | grep ginkgo | cut -d ' ' -f2)
$(GINKGO): $(MAKE_ENV_GO) 
	GOBIN=$(LOCALBIN)/.make-env/go/github.com/onsi/ginkgo/v2/ginkgo/$(GINKGO_VERSION) \
	$(MAKE_ENV_GO) install \
		github.com/onsi/ginkgo/v2/ginkgo@$(GINKGO_VERSION)
	$(MAKE_ENV_RM) -f $(GINKGO)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/go/github.com/onsi/ginkgo/v2/ginkgo/$(GINKGO_VERSION)/ginkgo $(GINKGO)
.PHONY: ginkgo
ginkgo: $(GINKGO)



HELM ?= $(LOCALBIN)/helm
HELM_MIRROR ?= https://dl.k8s.io/release
HELM_VERSION ?= v3.12.2

HELM_URL ?= https://get.helm.sh/helm-$(HELM_VERSION)-$(GO_OS)-$(GO_ARCH).tar.gz
$(HELM):  	
	
	$(MAKE_ENV_MKDIR) -p $(LOCALBIN)/.make-env/http/$(shell echo $(HELM_URL) | base64 -w0)
	$(MAKE_ENV_CURL) -vfL $(HELM_URL) | tar -x -z  -C $(LOCALBIN)/.make-env/http/$(shell echo $(HELM_URL) | base64 -w0) $(GO_OS)-$(GO_ARCH)/helm
	$(MAKE_ENV_CHMOD) +x $(LOCALBIN)/.make-env/http/$(shell echo $(HELM_URL) | base64 -w0)/$(GO_OS)-$(GO_ARCH)/helm
	$(MAKE_ENV_RM) -f $(HELM)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/http/$(shell echo $(HELM_URL) | base64 -w0)/$(GO_OS)-$(GO_ARCH)/helm $(HELM)

.PHONY: helm
helm: $(HELM)



HELM_HOG ?= $(LOCALBIN)/helm-hog
$(HELM_HOG): $(MAKE_ENV_GO) 
	GOBIN=$(LOCALBIN)/.make-env/go/github.com/meln5674/helm-hog/3af9ec621dcc359e38e966a255571a39beefe624 \
	$(MAKE_ENV_GO) install \
		github.com/meln5674/helm-hog@3af9ec621dcc359e38e966a255571a39beefe624
	$(MAKE_ENV_RM) -f $(HELM_HOG)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/go/github.com/meln5674/helm-hog/3af9ec621dcc359e38e966a255571a39beefe624/helm-hog $(HELM_HOG)
.PHONY: helm-hog
helm-hog: $(HELM_HOG)



KIND ?= $(LOCALBIN)/kind
KIND_MIRROR ?= https://github.com/kubernetes-sigs/kind/releases/download
KIND_VERSION ?= v0.17.0

KIND_URL ?= $(KIND_MIRROR)/$(KIND_VERSION)/kind-$(GO_OS)-$(GO_ARCH)
$(KIND):  	
	
	$(MAKE_ENV_MKDIR) -p $(LOCALBIN)/.make-env/http
	$(MAKE_ENV_CURL) -vfL $(KIND_URL) -o $(LOCALBIN)/.make-env/http$(shell echo $(KIND_URL) | base64 -w0)
	$(MAKE_ENV_CHMOD) +x $(LOCALBIN)/.make-env/http$(shell echo $(KIND_URL) | base64 -w0)
	$(MAKE_ENV_RM) -f $(KIND)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/http$(shell echo $(KIND_URL) | base64 -w0) $(KIND)

.PHONY: kind
kind: $(KIND)



KUBECTL ?= $(LOCALBIN)/kubectl
KUBECTL_MIRROR ?= https://dl.k8s.io/release
KUBECTL_VERSION ?= v1.25.11

KUBECTL_URL ?= $(KUBECTL_MIRROR)/$(KUBECTL_VERSION)/bin/$(GO_OS)/$(GO_ARCH)/kubectl
$(KUBECTL):  	
	
	$(MAKE_ENV_MKDIR) -p $(LOCALBIN)/.make-env/http
	$(MAKE_ENV_CURL) -vfL $(KUBECTL_URL) -o $(LOCALBIN)/.make-env/http$(shell echo $(KUBECTL_URL) | base64 -w0)
	$(MAKE_ENV_CHMOD) +x $(LOCALBIN)/.make-env/http$(shell echo $(KUBECTL_URL) | base64 -w0)
	$(MAKE_ENV_RM) -f $(KUBECTL)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/http$(shell echo $(KUBECTL_URL) | base64 -w0) $(KUBECTL)

.PHONY: kubectl
kubectl: $(KUBECTL)



YQ ?= $(LOCALBIN)/yq
YQ_MIRROR ?= github.com/mikefarah/yq/releases/download
YQ_VERSION ?= v4.44.1

YQ_URL ?= https://$(YQ_MIRROR)/$(YQ_VERSION)/yq_$(GO_OS)_$(GO_ARCH).tar.gz
$(YQ):  	
	
	$(MAKE_ENV_MKDIR) -p $(LOCALBIN)/.make-env/http/$(shell echo $(YQ_URL) | base64 -w0)
	$(MAKE_ENV_CURL) -vfL $(YQ_URL) | tar -x -z  -C $(LOCALBIN)/.make-env/http/$(shell echo $(YQ_URL) | base64 -w0) ./yq_$(GO_OS)_$(GO_ARCH)
	$(MAKE_ENV_CHMOD) +x $(LOCALBIN)/.make-env/http/$(shell echo $(YQ_URL) | base64 -w0)/./yq_$(GO_OS)_$(GO_ARCH)
	$(MAKE_ENV_RM) -f $(YQ)
	$(MAKE_ENV_LN) -s $(LOCALBIN)/.make-env/http/$(shell echo $(YQ_URL) | base64 -w0)/./yq_$(GO_OS)_$(GO_ARCH) $(YQ)

.PHONY: yq
yq: $(YQ)

.PHONY: all-e2e-tools
all-e2e-tools: $(GINKGO) $(KUBECTL) $(HELM) $(DOCKER) $(KIND) $(HELM_HOG)

.PHONY: all-helm-tools
all-helm-tools: $(YQ) $(HELM) $(HELM_HOG) $(DOCKER) $(KIND)

.PHONY: all-test-tools
all-test-tools: $(GINKGO)

make-env.Makefile: make-env.yaml
	make-env --config 'make-env.yaml' --out 'make-env.Makefile'
