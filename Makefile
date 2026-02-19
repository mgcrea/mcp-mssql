.PHONY: help install server format lint spec docker-build docker-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install dependencies with uv
	uv sync

server: ## Run the MCP server locally
	uv run mcp-mssql

format: ## Format code
	uv run ruff check --fix; uv run ruff format

lint: ## Lint code
	uv run ruff check

spec: ## Run tests
	uv run pytest -s

docker-build: ## Build Docker image
	docker build -t mcp-mssql:latest .

docker-run: ## Run Docker container
	docker run -p 8080:8080 --env-file .env mcp-mssql:latest
