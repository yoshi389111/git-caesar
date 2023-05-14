.DEFAULT_GOAL = help
help: ## Show help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
.PHONY: help

build: ## Build
	@mkdir -p ./target
	go build -ldflags="-s -w" -trimpath -o target
.PHONY: build

test: ## Unit test
	go test ./... --count=1 -v
.PHONY: test
