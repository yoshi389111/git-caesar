SHELL = /bin/sh
VERSION = $(shell git describe --tags --abbrev=0)
GOFLAGS = -ldflags "-s -w -X main.version=$(shell git describe --tags --dirty)"
MODULE_NAME = $(shell go list -m)
GOVERSION = $(shell go env GOVERSION)

.DEFAULT_GOAL = help
help: ## Show help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
.PHONY: help

build: ## Build
	@mkdir -p ./target
	go build $(GOFLAGS) -trimpath -o target
.PHONY: build

clean: ## Clean build artifacts
	rm -rf ./target
.PHONY: clean

test: ## Unit test
	go test ./... --count=1 -v
.PHONY: test

roundtrip: build ## Roundtrip test
	./roundtrip.sh
.PHONY: roundtrip

licenses: ## Create Third Party Licenses
	@# requires go-licenses tool
	@# ```shell
	@# go install github.com/google/go-licenses@latest
	@# ```
	@rm -rf licenses
	@go-licenses save ./... --save_path=licenses --force
	@rm -rf licenses/$(MODULE_NAME)
	@find licenses -type d -empty -delete
	@go-licenses csv ./... | grep -v "^$(MODULE_NAME)," > licenses/THIRD_PARTY_LICENSES.csv
	@mkdir -p licenses/github.com/go/golang
	@curl -Lq -o licenses/github.com/go/golang/LICENSE --retry 5 "https://raw.githubusercontent.com/golang/go/refs/tags/$(GOVERSION)/LICENSE"
	@echo "github.com/golang/go (stdlib),https://github.com/golang/go/blob/$(GOVERSION)/LICENSE,BSD-3-Clause" >> licenses/THIRD_PARTY_LICENSES.csv
.PHONY: licenses
