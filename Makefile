.PHONY: vet
vet:
	go vet ./...

TEST_SUITES ?= ./pkg/proxy
TEST_FLAGS ?= --race --trace -p

E2E_TEST_SUITES ?= ./
E2E_TEST_FLAGS ?= --race --trace -v

coverprofile.out: deps
	bin/ginkgo run --cover --coverpkg=./,./pkg/proxy/ $(TEST_FLAGS) $(TEST_SUITES)

.PHONY: test
test: coverprofile.out

.PHONY: show-coverage
show-coverage: coverprofile.out
	go tool cover -html=coverprofile.out

.PHONY: e2e
e2e: deps
	bin/ginkgo run --cover --coverpkg=./,./pkg/proxy/ $(E2E_TEST_FLAGS) $(E2E_TEST_SUITES)

LOCALBIN ?= bin
# $(LOCALBIN):
# 	mkdir -p $(LOCALBIN)

GINKGO_URL ?= $(shell grep ginkgo go.mod | awk '{ print $$1 "/ginkgo@" $$2 }')
GINKGO ?= $(LOCALBIN)/ginkgo
$(GINKGO):
	mkdir -p $(shell dirname $(GINKGO))
	GOBIN=/tmp/ go install $(GINKGO_URL)
	mv /tmp/ginkgo $(GINKGO)
	touch $(GINKGO)

KUBECTL_MIRROR ?= https://dl.k8s.io/release
KUBECTL_VERSION ?= v1.25.11
KUBECTL_URL ?= $(KUBECTL_MIRROR)/$(KUBECTL_VERSION)/bin/$(shell go env GOOS)/$(shell go env GOARCH)/kubectl
KUBECTL ?= $(LOCALBIN)/kubectl
$(KUBECTL):
	mkdir -p $(shell dirname $(KUBECTL))
	curl -vfL $(KUBECTL_URL) > $(KUBECTL)
	chmod +x $(KUBECTL)
	touch $(KUBECTL)


HELM_MIRROR ?= https://get.helm.sh
HELM_VERSION ?= v3.12.2
ifeq ($(shell go env GOOS),windows)
HELM_URL ?= $(HELM_MIRROR)/helm-$(HELM_VERSION)-$(shell go env GOOS)-$(shell go env GOARCH).zip
else
HELM_URL ?= $(HELM_MIRROR)/helm-$(HELM_VERSION)-$(shell go env GOOS)-$(shell go env GOARCH).tar.gz
endif

HELM ?= $(LOCALBIN)/helm
$(HELM):
	mkdir -p $(shell dirname $(HELM))
ifeq ($(shell go env GOOS),windows)
	curl -vfL $(HELM_URL) > $(HELM).zip
	unzip $(HELM).zip -j -d /tmp/ -x helm-windows-$(go env GOARCH)/helm
	mv helm-windows-$(go env GOARCH)/helm $(LOCALBIN)
else
	curl -vfL $(HELM_URL) | tar xz -C /tmp/ $(shell go env GOOS)-$(shell go env GOARCH)/helm
	mv /tmp/$(shell go env GOOS)-$(shell go env GOARCH)/helm $(HELM)
endif
	touch $(HELM)


KIND_MIRROR ?= https://github.com/kubernetes-sigs/kind/releases/download
KIND_VERSION ?= v0.17.0
KIND_URL ?= $(KIND_MIRROR)/$(KIND_VERSION)/kind-$(shell go env GOOS)-$(shell go env GOARCH)
KIND ?= $(LOCALBIN)/kind
$(KIND):
	mkdir -p $(shell dirname $(KIND))
	curl -vfL $(KIND_URL) > $(KIND)
	chmod +x $(KIND)

HELM_HOG_VERSION ?= 3af9ec621dcc359e38e966a255571a39beefe624
HELM_HOG ?= $(LOCALBIN)/helm-hog
$(HELM_HOG):
	mkdir -p $(shell dirname $(HELM_HOG))
	GOBIN=/tmp go install github.com/meln5674/helm-hog@$(HELM_HOG_VERSION)
	mv /tmp/helm-hog $(HELM_HOG)

.PHONY: deps
deps: $(GINKGO) $(KUBECTL) $(HELM) $(KIND) $(HELM_HOG)
	go mod download

bin/mlflow-oidc-proxy:
	go build -o bin/mlflow-oidc-proxy main.go
