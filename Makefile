BIN := voodoo

.PHONY: help build run test fmt vet tidy tools vulncheck sqlc migrate-new clean deploy theme

help:
	@echo "Targets:"
	@echo "  build         compile the voodoo binary into ./bin"
	@echo "  run           build, then run 'voodoo serve'"
	@echo "  test          go test ./..."
	@echo "  fmt vet       go fmt / go vet ./..."
	@echo "  tidy          go mod tidy"
	@echo "  tools         install pinned sqlc, goose, govulncheck CLIs"
	@echo "  vulncheck     govulncheck ./... (allowlist: deploy/govulncheck.allow)"
	@echo "  sqlc          regenerate sqlc code"
	@echo "  migrate-new   create a new goose migration  (NAME=add_thing)"
	@echo "  theme         regenerate design tokens from the org website  (WEBSITE=../0xD34DC0D3/website)"
	@echo "  clean         remove build artifacts"
	@echo "  deploy        gate (clean tree, vet, test, vulncheck), back up, install, migrate, health-check"

build:
	go build -o bin/$(BIN) ./cmd/voodoo

run: build
	./bin/$(BIN) serve

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

# Pinned. Keep goose in step with the goose/v3 version in go.mod.
SQLC_VERSION        := v1.31.1
GOOSE_VERSION       := v3.30.1
GOVULNCHECK_VERSION := v1.9.0

tools:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)
	go install github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

vulncheck:
	./deploy/vulncheck.sh

# Print a Makefile variable, e.g. `make -s print-SQLC_VERSION` (used by CI).
print-%:
	@echo $($*)

sqlc:
	@LC_ALL=C grep -n '[^ -~	]' internal/auth/store/queries.sql \
		&& { echo "queries.sql must be ASCII-only (see sqlc.yaml)"; exit 1; } || true
	sqlc generate

migrate-new:
	@test -n "$(NAME)" || (echo "usage: make migrate-new NAME=add_thing" && exit 1)
	goose -dir migrations create $(NAME) sql

# Pull the shared design tokens from the org website repo (a local checkout).
WEBSITE ?= ../0xD34DC0D3/website
theme:
	./scripts/sync-theme.sh $(WEBSITE)

clean:
	rm -rf bin/

deploy:
	./deploy/deploy.sh
