.PHONY: run-gosec check-formatting lint-vault lint-api checks

dev:
	docker-compose -f docker-compose.yml up

tests:
	go test ./vault
	go test ./api

run-gosec:
	gosec ./vault ./api ./logger

check-formatting:
	if [ -n "$(gofmt -l .)" ]; then echo "Go code is not properly formatted:"; gofmt -d .; exit 1; fi

lint-vault:
	cd vault && golangci-lint run

lint-api:
	cd api && golangci-lint run

checks: 
	@echo "Running checks..."
	docker-compose up --build -d 
	$(MAKE) run-gosec
	$(MAKE) check-formatting
	$(MAKE) lint-vault
	$(MAKE) lint-api
	docker-compose down --remove-orphans

e2e:
	@echo "Running CI..."
	docker-compose -f docker-compose.ci.yml --profile tests up --build --abort-on-container-exit 
	docker-compose -f docker-compose.ci.yml --profile simulations up --build --abort-on-container-exit 

ci:
	$(MAKE) checks
	$(MAKE) e2e
