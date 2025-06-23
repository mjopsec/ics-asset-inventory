# ICS Asset Inventory Makefile

# Variables
APP_NAME=ics-asset-inventory
SERVER_BINARY=bin/server
GO_FILES=$(shell find . -name '*.go' -not -path './vendor/*')
CONFIG_FILE=configs/config.yaml

# Colors for output
GREEN=\033[32m
YELLOW=\033[33m
RED=\033[31m
NC=\033[0m

.PHONY: help build run dev test clean setup deps docker-build docker-run

# Default target
help: ## Show this help message
	@echo "$(GREEN)ICS Asset Inventory - Available Commands:$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'

# Development commands
setup: ## Initial project setup
	@echo "$(GREEN)Setting up project...$(NC)"
	@mkdir -p bin logs web/static/css web/static/js web/static/images
	@chmod +x scripts/test-setup.sh scripts/test-api.sh
	@echo "$(GREEN)✅ Project setup completed$(NC)"

deps: ## Install Go dependencies
	@echo "$(GREEN)Installing dependencies...$(NC)"
	@go mod tidy
	@go mod download
	@echo "$(GREEN)✅ Dependencies installed$(NC)"

build: ## Build the application
	@echo "$(GREEN)Building application...$(NC)"
	@go build -o $(SERVER_BINARY) cmd/server/main.go
	@echo "$(GREEN)✅ Build completed: $(SERVER_BINARY)$(NC)"

run: build ## Build and run the application
	@echo "$(GREEN)Starting server...$(NC)"
	@./$(SERVER_BINARY)

dev: ## Run with auto-reload (requires air: go install github.com/cosmtrek/air@latest)
	@echo "$(GREEN)Starting development server with auto-reload...$(NC)"
	@if which air > /dev/null; then \
		air; \
	else \
		echo "$(RED)Air not found. Install with: go install github.com/cosmtrek/air@latest$(NC)"; \
		echo "$(YELLOW)Falling back to normal run...$(NC)"; \
		make run; \
	fi

# Testing commands
test: ## Run tests
	@echo "$(GREEN)Running tests...$(NC)"
	@go test -v ./...

test-setup: ## Test project setup
	@echo "$(GREEN)Testing project setup...$(NC)"
	@./scripts/test-setup.sh

test-api: ## Test API endpoints (requires server to be running)
	@echo "$(GREEN)Testing API endpoints...$(NC)"
	@./scripts/test-api.sh

test-all: test-setup test ## Run all tests

# Code quality commands
fmt: ## Format Go code
	@echo "$(GREEN)Formatting code...$(NC)"
	@go fmt ./...
	@echo "$(GREEN)✅ Code formatted$(NC)"

lint: ## Run linter (requires golangci-lint)
	@echo "$(GREEN)Running linter...$(NC)"
	@if which golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "$(RED)golangci-lint not found. Install from: https://golangci-lint.run/usage/install/$(NC)"; \
	fi

vet: ## Run go vet
	@echo "$(GREEN)Running go vet...$(NC)"
	@go vet ./...

check: fmt vet ## Run code quality checks

# Database commands
db-reset: ## Reset database (delete and recreate)
	@echo "$(GREEN)Resetting database...$(NC)"
	@rm -f ics_inventory.db
	@echo "$(GREEN)✅ Database reset$(NC)"

# Development utilities
clean: ## Clean build artifacts
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	@rm -rf bin/
	@rm -f ics_inventory.db
	@rm -f /tmp/response.json
	@echo "$(GREEN)✅ Clean completed$(NC)"

logs: ## View application logs (if logging to file)
	@if [ -f "logs/app.log" ]; then \
		tail -f logs/app.log; \
	else \
		echo "$(YELLOW)No log file found. Application may be logging to stdout.$(NC)"; \
	fi

# Docker commands
docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(NC)"
	@docker build -t $(APP_NAME):latest .
	@echo "$(GREEN)✅ Docker image built$(NC)"

docker-run: ## Run Docker container
	@echo "$(GREEN)Running Docker container...$(NC)"
	@docker run -p 8080:8080 --name $(APP_NAME) $(APP_NAME):latest

docker-stop: ## Stop Docker container
	@docker stop $(APP_NAME) || true
	@docker rm $(APP_NAME) || true

# Development workflow
start: setup deps build test-setup ## Complete setup and start
	@echo "$(GREEN)🚀 Starting ICS Asset Inventory...$(NC)"
	@make run

restart: ## Stop, clean, and restart
	@echo "$(GREEN)Restarting application...$(NC)"
	@pkill -f "bin/server" || true
	@make clean
	@make start

# Configuration
config-check: ## Check configuration file
	@echo "$(GREEN)Checking configuration...$(NC)"
	@if [ -f "$(CONFIG_FILE)" ]; then \
		echo "$(GREEN)✅ Config file exists: $(CONFIG_FILE)$(NC)"; \
		echo "Contents:"; \
		cat $(CONFIG_FILE); \
	else \
		echo "$(RED)❌ Config file not found: $(CONFIG_FILE)$(NC)"; \
	fi

# Status checks
status: ## Check application status
	@echo "$(GREEN)Checking application status...$(NC)"
	@if curl -s http://localhost:8080/health > /dev/null 2>&1; then \
		echo "$(GREEN)✅ Application is running$(NC)"; \
		curl -s http://localhost:8080/health | jq . || curl -s http://localhost:8080/health; \
	else \
		echo "$(RED)❌ Application is not running$(NC)"; \
	fi

# Quick development commands
quick-test: build ## Quick build and test
	@echo "$(GREEN)Quick test sequence...$(NC)"
	@timeout 10s ./$(SERVER_BINARY) & SERVER_PID=$$!; \
	sleep 3; \
	if curl -s http://localhost:8080/health > /dev/null; then \
		echo "$(GREEN)✅ Server test passed$(NC)"; \
	else \
		echo "$(RED)❌ Server test failed$(NC)"; \
	fi; \
	kill $$SERVER_PID 2>/dev/null || true

install-tools: ## Install development tools
	@echo "$(GREEN)Installing development tools...$(NC)"
	@go install github.com/cosmtrek/air@latest
	@echo "$(GREEN)✅ Development tools installed$(NC)"

# Help with common issues
troubleshoot: ## Show troubleshooting information
	@echo "$(YELLOW)Troubleshooting Information:$(NC)"
	@echo ""
	@echo "$(GREEN)1. Check Go version:$(NC)"
	@go version
	@echo ""
	@echo "$(GREEN)2. Check if port 8080 is available:$(NC)"
	@if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null; then \
		echo "$(RED)Port 8080 is in use:$(NC)"; \
		lsof -Pi :8080 -sTCP:LISTEN; \
	else \
		echo "$(GREEN)Port 8080 is available$(NC)"; \
	fi
	@echo ""
	@echo "$(GREEN)3. Check database file:$(NC)"
	@if [ -f "ics_inventory.db" ]; then \
		echo "$(GREEN)Database file exists$(NC)"; \
		ls -la ics_inventory.db; \
	else \
		echo "$(YELLOW)Database file not found (will be created on first run)$(NC)"; \
	fi