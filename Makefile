.PHONY: vet
vet: go vet ./...

TEST_SUITES ?= ./pkg/proxy ./
TEST_FLAGS ?= --race --trace -v

.PHONY: coverprofile.out
coverprofile.out:
	ginkgo run --cover --coverpkg=./,./pkg/proxy/ $(TEST_FLAGS) $(TEST_SUITES)

