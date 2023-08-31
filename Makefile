.PHONY: vet
vet: go vet ./...

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

HELM_HOG_VERSION ?= 3af9ec621dcc359e38e966a255571a39beefe624


KIND_MIRROR ?= https://github.com/kubernetes-sigs/kind/releases/download
KIND_VERSION ?= v0.20.0
KIND_URL ?= $(KIND_MIRROR)/$(KIND_VERSION)/kind-$(shell go env GOOS)-$(shell go env GOARCH)

.PHONY: deps
deps:
	mkdir -p bin
	go mod download
	grep ginkgo go.mod | awk '{ print $$1 "/ginkgo@" $$2 }' | GOBIN=$$PWD/bin xargs go install
	go install github.com/meln5674/helm-hog@$(HELM_HOG_VERSION)
	curl -vfL $(KIND_URL) > bin/kind
	chmod +x bin/kind

bin/mlflow-oidc-proxy:
	go build -o bin/mlflow-oidc-proxy main.go
