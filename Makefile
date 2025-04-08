include make-env.Makefile

CHART_DIR=deploy/helm


.PHONY: deps
deps:
	go mod download

.PHONY: vet
vet: deps
	go vet ./...

TEST_SUITES ?= ./pkg/proxy
TEST_FLAGS ?= --race --trace -p

coverprofile.out: deps all-test-tools
	$(GINKGO) run --cover --coverpkg=./,./pkg/proxy/ $(TEST_FLAGS) $(TEST_SUITES)

.PHONY: test
test: coverprofile.out

.PHONY: show-coverage
show-coverage: coverprofile.out
	go tool cover -html=coverprofile.out

E2E_TEST_SUITES ?= ./
E2E_TEST_FLAGS ?= --race --trace -vv --flake-attempts=5 # --until-it-fails --fail-fast

.PHONY: e2e
e2e: deps all-e2e-tools
	helm dep build $(CHART_DIR)/mlflow-oidc-proxy
	helm dep build $(CHART_DIR)/mlflow-multitenant
	helm dep build $(CHART_DIR)/mlflow-multitenant-deps
	$(GINKGO) run --cover --coverpkg=./,./pkg/proxy/ $(E2E_TEST_FLAGS) $(E2E_TEST_SUITES)

bin/mlflow-oidc-proxy:
	go build -o bin/mlflow-oidc-proxy main.go


MLFLOW_OIDC_PROXY_CHART_VERSION=$(shell yq .version $(CHART_DIR)/mlflow-oidc-proxy/Chart.yaml)
MLFLOW_MULTITENANT_CHART_VERSION=$(shell yq .version $(CHART_DIR)/mlflow-multitenant/Chart.yaml)
MLFLOW_MULTITENANT_DEPS_CHART_VERSION=$(shell yq .version $(CHART_DIR)/mlflow-multitenant-deps/Chart.yaml)

$(CHART_DIR)/mlflow-oidc-proxy/Chart.lock: $(CHART_DIR)/mlflow-oidc-proxy/Chart.yaml
	$(HELM) dependency update $(CHART_DIR)/mlflow-oidc-proxy

$(CHART_DIR)/mlflow-multitenant/Chart.lock: $(CHART_DIR)/mlflow-multitenant/Chart.yaml
	$(HELM) dependency update $(CHART_DIR)/mlflow-multitenant

$(CHART_DIR)/mlflow-multitenant-deps/Chart.lock: $(CHART_DIR)/mlflow-multitenant-deps/Chart.yaml
	$(HELM) dependency update $(CHART_DIR)/mlflow-multitenant-deps

CHART_LOCKS=\
	$(CHART_DIR)/mlflow-oidc-proxy/Chart.lock \
	$(CHART_DIR)/mlflow-multitenant/Chart.lock \
	$(CHART_DIR)/mlflow-multitenant-deps/Chart.lock \

.PHONY: chart-deps
chart-deps:
	cd $(CHART_DIR)/mlflow-oidc-proxy ; helm dependency build
	cd $(CHART_DIR)/mlflow-multitenant ; helm dependency build
	cd $(CHART_DIR)/mlflow-multitenant-deps ; helm dependency build

.PHONY: helm-hog
helm-hog: all-helm-tools $(CHART_LOCKS)
	cd $(CHART_DIR)/mlflow-oidc-proxy ; $(LOCALBIN)/helm-hog test --no-apply --batch --auto-remove-success --parallel=0
	cd $(CHART_DIR)/mlflow-multitenant ; $(LOCALBIN)/helm-hog test --no-apply --batch --auto-remove-success --parallel=0
	cd $(CHART_DIR)/mlflow-multitenant-deps ; $(LOCALBIN)/helm lint ; $(LOCALBIN)/helm template .

bin/charts/mlflow-oidc-proxy-$(MLFLOW_OIDC_PROXY_CHART_VERISON).tgz: all-helm-tools $(CHART_DIR)/mlflow-oidc-proxy/Chart.lock
	helm package $(CHART_DIR)/mlflow-oidc-proxy --destination bin/charts

bin/charts/mlflow-multitenant-$(MLFLOW_MULTITENANT_CHART_VERISON).tgz: all-helm-tools $(CHART_DIR)/mlflow-multitenant/Chart.lock
	helm package $(CHART_DIR)/mlflow-multitenant --destination bin/charts

bin/charts/mlflow-multitenant-deps-$(MLFLOW_MULTITENANT_DEPS_CHART_VERISON).tgz: all-helm-tools $(CHART_DIR)/mlflow-multitenant-deps/Chart.lock
	helm package $(CHART_DIR)/mlflow-multitenant-deps --destination bin/charts

BASE_CHARTS=\
	bin/charts/mlflow-oidc-proxy-$(MLFLOW_OIDC_PROXY_CHART_VERISON).tgz \
	bin/charts/mlflow-multitenant-deps-$(MLFLOW_MULTITENANT_DEPS_CHART_VERISON).tgz \

.PHONY: base-charts
base-charts: $(BASE_CHARTS)



CHARTS=\
	$(BASE_CHARTS) \
	bin/charts/mlflow-multitenant-$(MLFLOW_MULTITENANT_CHART_VERISON).tgz \

.PHONY: charts
charts: $(CHARTS)


