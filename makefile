.PHONY: run-gosec check-formatting lint-vault lint-api checks

tests:
	go test ./vault
	go test ./api


run-gosec:
	gosec ./...

check-formatting:
	if [ -n "$(gofmt -l .)" ]; then echo "Go code is not properly formatted:"; gofmt -d .; exit 1; fi

lint-vault:
	cd vault && golangci-lint run

lint-api:
	cd api && golangci-lint run

checks: 
	@echo "Running checks..."
	$(MAKE) tests
	$(MAKE) run-gosec
	$(MAKE) check-formatting
	$(MAKE) lint-vault
	$(MAKE) lint-api
