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

.PHONY: deps
deps:
	mkdir -p bin
	go mod download
	grep ginkgo go.mod | awk '{ print $$1 "/ginkgo@" $$2 }' | GOBIN=$$PWD/bin xargs go install

bin/mlflow-oidc-proxy:
	go build -o bin/mlflow-oidc-proxy main.go
