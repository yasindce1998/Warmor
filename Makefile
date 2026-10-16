.PHONY: all clean build-bpf build-policy build-daemon generate test help \
	deploy deploy-audit undeploy status logs policy-check upgrade \
	docker-build docker-push build-policy-merge build-policy-diff build-policy-bundle \
	tools build-tests deps bench bench-kernel

NAMESPACE ?= warmor-system
RELEASE ?= warmor
CHART ?= deploy/helm/warmor
POLICY ?= examples/policies/kubernetes-hardening.yaml
IMAGE ?= ghcr.io/yasindce1998/warmor
TAG ?= latest

# Cross-platform support
ifeq ($(OS),Windows_NT)
    BINARY_EXT := .exe
    RM := del /f /q
    RMDIR := rmdir /s /q
else
    BINARY_EXT :=
    RM := rm -f
    RMDIR := rm -rf
endif

# Default target
# The tools are built after generate (in the recipe, not as a prerequisite)
# so a parallel make never compiles against half-written eBPF bindings.
all: build-bpf generate build-policy build-daemon
	@$(MAKE) --no-print-directory tools

# Help target
help:
	@echo "warmor - WASM-powered security enforcer"
	@echo ""
	@echo "Build Targets:"
	@echo "  all           - Build everything incl. all tools in ./bin (default)"
	@echo "  build-bpf     - Compile eBPF program"
	@echo "  generate      - Generate eBPF Go bindings"
	@echo "  build-policy  - Build WASM policy"
	@echo "  build-daemon  - Build warmor daemon"
	@echo "  tools         - Build every cmd/* binary into ./bin"
	@echo "  test          - Run tests"
	@echo "  bench         - Userspace performance harness (docs/PERFORMANCE.md)"
	@echo "  bench-kernel  - Kernel fast-path benchmarks in a vimto VM (KERNEL=...)"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "Deploy Targets:"
	@echo "  deploy        - Deploy to Kubernetes (enforce mode)"
	@echo "  deploy-audit  - Deploy in audit-only mode (safe, no blocking)"
	@echo "  undeploy      - Remove from cluster"
	@echo "  upgrade       - Upgrade existing deployment"
	@echo "  status        - Show deployment status"
	@echo "  logs          - Tail daemon logs"
	@echo "  policy-check  - Validate a policy file"
	@echo ""
	@echo "Docker Targets:"
	@echo "  docker-build  - Build container image locally"
	@echo "  docker-push   - Push image to registry"
	@echo ""
	@echo "Variables:"
	@echo "  NAMESPACE     - Target namespace (default: warmor-system)"
	@echo "  RELEASE       - Helm release name (default: warmor)"
	@echo "  POLICY        - Policy file to use (default: examples/policies/kubernetes-hardening.yaml)"
	@echo "  IMAGE         - Container image (default: ghcr.io/yasindce1998/warmor)"
	@echo "  TAG           - Image tag (default: latest)"
	@echo ""
	@echo "Examples:"
	@echo "  make docker-build TAG=v0.2.0                   # Build image"
	@echo "  make deploy-audit                              # Safe first deploy"
	@echo "  make deploy POLICY=examples/policies/block-crypto-miners.yaml"
	@echo "  make logs                                      # Watch events"
	@echo "  make upgrade                                   # Apply changes"

# Build eBPF program
build-bpf:
	@echo "==> Building eBPF program..."
	cd bpf && $(MAKE)

# Generate eBPF Go bindings
generate: build-bpf
	@echo "==> Generating eBPF Go bindings..."
	go generate ./internal/ebpf

# Build WASM policy
build-policy:
	@echo "==> Building WASM policy..."
	cd policies/example && $(MAKE)

# Build warmor daemon
build-daemon:
	@echo "==> Building warmor daemon..."
	go build -o warmor-daemon$(BINARY_EXT) ./cmd/warmor-daemon

# Build every command under cmd/ into ./bin (go adds .exe on Windows).
# Uses the committed eBPF bindings; run `make generate` first to refresh them.
tools:
	@echo "==> Building all tools into ./bin..."
	go build -o bin/ ./cmd/...

# Build policy merge tool
build-policy-merge:
	@echo "==> Building warmor-policy-merge..."
	go build -o warmor-policy-merge$(BINARY_EXT) ./cmd/warmor-policy-merge

# Build policy diff tool
build-policy-diff:
	@echo "==> Building warmor-policy-diff..."
	go build -o warmor-policy-diff$(BINARY_EXT) ./cmd/warmor-policy-diff

# Build policy bundle tool
build-policy-bundle:
	@echo "==> Building warmor-policy-bundle..."
	go build -o warmor-policy-bundle$(BINARY_EXT) ./cmd/warmor-policy-bundle

# Build test tools
build-tests:
	@echo "==> Building test tools..."
	go build -o test-ebpf$(BINARY_EXT) ./cmd/test-ebpf
	go build -o test-wasm$(BINARY_EXT) ./cmd/test-wasm

# Run tests
test:
	@echo "==> Running tests..."
	go test ./...

# Performance harness (docs/PERFORMANCE.md). Raw results go to bench-results/.
bench:
	@echo "==> Running userspace benchmarks..."
	scripts/bench.sh

# Kernel fast-path benchmarks need root and a BPF-LSM kernel, so they run in
# a vimto VM. KERNEL is an OCI image or an ABSOLUTE path to a kernel image.
KERNEL ?= ghcr.io/cilium/ci-kernels:stable-selftests
BENCH_KERNEL_COUNT ?= 10
VIMTO ?= $(shell go env GOPATH)/bin/vimto
bench-kernel:
	@echo "==> Running kernel fast-path benchmarks in a VM ($(KERNEL))..."
	@mkdir -p bench-results
	CGO_ENABLED=0 $(VIMTO) -kernel $(KERNEL) -- \
		go test -tags integration -run '^$$' -bench Kernel -benchtime 3000x \
		-count $(BENCH_KERNEL_COUNT) ./internal/ebpf/ | tee bench-results/kernel.txt

# Clean build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	cd bpf && $(MAKE) clean
	cd policies/example && $(MAKE) clean
	$(RM) warmor-daemon$(BINARY_EXT) test-ebpf$(BINARY_EXT) test-wasm$(BINARY_EXT)
	$(RMDIR) bin
	$(RM) internal/ebpf/execve_monitor_bpfeb.go
	$(RM) internal/ebpf/execve_monitor_bpfeb.o
	$(RM) internal/ebpf/execve_monitor_bpfel.go
	$(RM) internal/ebpf/execve_monitor_bpfel.o
	go clean

# Install dependencies
deps:
	@echo "==> Installing Go dependencies..."
	go mod download
	@echo "==> Installing Rust WASI target..."
	rustup target add wasm32-unknown-unknown

# --- Deployment Targets ---

# Deploy in enforce mode
deploy:
	@echo "==> Deploying warmor (enforce mode)..."
	helm upgrade --install $(RELEASE) $(CHART) \
		--namespace $(NAMESPACE) --create-namespace \
		--set image.repository=$(IMAGE) \
		--set image.tag=$(TAG) \
		--set daemon.auditMode=false \
		--set-file policy.yaml=$(POLICY)

# Deploy in audit-only mode (safe for initial rollout)
deploy-audit:
	@echo "==> Deploying warmor (audit mode - no blocking)..."
	helm upgrade --install $(RELEASE) $(CHART) \
		--namespace $(NAMESPACE) --create-namespace \
		--set image.repository=$(IMAGE) \
		--set image.tag=$(TAG) \
		--set daemon.auditMode=true \
		--set-file policy.yaml=$(POLICY)

# Upgrade existing deployment
upgrade:
	@echo "==> Upgrading warmor..."
	helm upgrade $(RELEASE) $(CHART) \
		--namespace $(NAMESPACE) \
		--reuse-values

# Remove from cluster
undeploy:
	@echo "==> Removing warmor..."
	helm uninstall $(RELEASE) --namespace $(NAMESPACE)

# Show status
status:
	@echo "==> Warmor Status"
	@echo ""
	@echo "--- Helm Release ---"
	@helm status $(RELEASE) -n $(NAMESPACE) 2>/dev/null || echo "Not deployed"
	@echo ""
	@echo "--- Pods ---"
	@kubectl get pods -n $(NAMESPACE) -l app.kubernetes.io/name=warmor -o wide 2>/dev/null || true
	@echo ""
	@echo "--- DaemonSet ---"
	@kubectl get ds -n $(NAMESPACE) -l app.kubernetes.io/name=warmor 2>/dev/null || true

# Tail logs
logs:
	kubectl logs -n $(NAMESPACE) -l app.kubernetes.io/name=warmor -f --tail=50

# Validate a policy file
policy-check:
	@echo "==> Validating policy: $(POLICY)"
	@go run ./cmd/warmor-daemon --validate-policy $(POLICY)

# --- Docker Targets ---

# Build container image
docker-build:
	@echo "==> Building container image $(IMAGE):$(TAG)..."
	docker build -t $(IMAGE):$(TAG) -f deploy/Dockerfile .

# Push container image
docker-push: docker-build
	@echo "==> Pushing $(IMAGE):$(TAG)..."
	docker push $(IMAGE):$(TAG)