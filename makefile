.PHONY: run-gosec check-formatting lint-vault lint-api checks

run-gosec:
	gosec ./...

check-formatting:
	if [ -n "$(gofmt -l .)" ]; then echo "Go code is not properly formatted:"; gofmt -d .; exit 1; fi

lint-vault:
	cd vault && golangci-lint run --fast

lint-api:
	cd api && golangci-lint run --fast

checks: 
	$(MAKE) run-gosec
	$(MAKE) check-formatting
	$(MAKE) lint-vault
	$(MAKE) lint-api
