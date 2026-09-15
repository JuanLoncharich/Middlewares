# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/security-eval/mcp-eval-operator:latest
CLONER_IMG ?= ghcr.io/security-eval/mcp-cloner:latest
TARGET_IMG ?= ghcr.io/security-eval/mcp-target-sandbox:latest
EVALUATOR_IMG ?= ghcr.io/security-eval/mcp-evaluator:latest

CONTROLLER_GEN_VERSION ?= v0.15.0
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
KUSTOMIZE ?= kubectl kustomize
CONTAINER_TOOL ?= docker

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: ## Generate CRDs and RBAC from kubebuilder markers.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: ## Generate DeepCopy implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: test
test: fmt vet ## Run unit tests.
	go test ./... -coverprofile cover.out

##@ Build

.PHONY: build
build: fmt vet ## Build the manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: fmt vet ## Run the controller locally against the current kubeconfig.
	CLONER_IMAGE=$(CLONER_IMG) TARGET_IMAGE=$(TARGET_IMG) EVALUATOR_IMAGE=$(EVALUATOR_IMG) go run ./cmd/main.go

.PHONY: docker-build
docker-build: ## Build the manager container image.
	$(CONTAINER_TOOL) build -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push the manager container image.
	$(CONTAINER_TOOL) push $(IMG)

.PHONY: docker-build-all
docker-build-all: docker-build ## Build manager, cloner, target sandbox and evaluator images.
	$(CONTAINER_TOOL) build -t $(CLONER_IMG) images/cloner
	$(CONTAINER_TOOL) build -t $(TARGET_IMG) images/target
	$(CONTAINER_TOOL) build -t $(EVALUATOR_IMG) runner

##@ Deployment

.PHONY: install
install: ## Install CRDs into the cluster.
	$(KUSTOMIZE) config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the cluster.
	$(KUSTOMIZE) config/crd | kubectl delete --ignore-not-found=true -f -

.PHONY: deploy
deploy: ## Deploy the controller (namespace, RBAC, manager) into the cluster.
	$(KUSTOMIZE) config/default | kubectl apply -f -
	kubectl apply -f config/rbac/runner_role.yaml

.PHONY: undeploy
undeploy: ## Remove the controller from the cluster.
	kubectl delete --ignore-not-found=true -f config/rbac/runner_role.yaml
	$(KUSTOMIZE) config/default | kubectl delete --ignore-not-found=true -f -

.PHONY: samples
samples: ## Apply the sample namespace, security manifests, agents and server.
	kubectl apply -k config/samples
