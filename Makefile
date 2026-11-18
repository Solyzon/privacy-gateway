.DEFAULT_GOAL := help
.PHONY: help dev stop verify live build release install

help: ## liste les commandes du dépôt
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  make %-7s %s\n", $$1, $$2}'

dev: ## passerelle de test au premier plan sur 127.0.0.1:8788, sans toucher au réglage de Claude Code
	go run ./cmd/privacy-gateway serve --addr 127.0.0.1:8788 --home .dev

stop: ## arrête la passerelle de test
	-pkill -f "privacy-gateway serve --addr 127.0.0.1:8788"

verify: ## format, analyse et tests Go, format de la doc, appelé par le hook de fin de tour
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	go test ./...

live: ## test réel avec Claude Code derrière un enregistreur, consomme un peu de quota Anthropic
	go test -tags live -count=1 -v -timeout 9m ./internal/livetest/

build: ## construit le binaire dans dist/
	go build -trimpath -ldflags "-s -w" -o dist/privacy-gateway ./cmd/privacy-gateway

release: ## binaires macOS et Linux et SHA256SUMS dans dist/release, version tirée de RELEASE_VERSION (vX.Y.Z)
	mkdir -p dist/release
	for os in darwin linux; do for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w $(if $(RELEASE_VERSION),-X main.version=$(patsubst v%,%,$(RELEASE_VERSION)))" \
			-o dist/release/privacy-gateway-$$os-$$arch ./cmd/privacy-gateway || exit 1; \
	done; done
	cd dist/release && sha256sum privacy-gateway-* > SHA256SUMS

install: build ## installe la passerelle sur ce poste et y branche Claude Code
	dist/privacy-gateway install
