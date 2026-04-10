# Makefile for w3af development
# Usage: make <target>

.PHONY: help install test lint format clean docker-build docker-run

# Default target
help:
	@echo "w3af Development Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install        - Install all dependencies"
	@echo "  install-dev    - Install development dependencies"
	@echo "  test           - Run tests with pytest"
	@echo "  test-cov       - Run tests with coverage"
	@echo "  lint           - Run all linters"
	@echo "  format         - Format code with black and isort"
	@echo "  typecheck      - Run mypy type checking"
	@echo "  security       - Run security scans"
	@echo "  clean          - Clean build artifacts"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  docker-shell   - Run Docker container with shell"
	@echo "  pre-commit     - Run pre-commit hooks"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -r w3af/tests/requirements.txt
	pip install black flake8 isort mypy pylint pytest pytest-cov pytest-timeout

# Testing
test:
	pytest w3af/ -v

test-cov:
	pytest w3af/ --cov=w3af --cov-report=html --cov-report=term-missing

test-unit:
	pytest w3af/ -v -m unit

test-integration:
	pytest w3af/ -v -m integration

test-slow:
	pytest w3af/ -v -m slow

# Linting
lint:
	@echo "Running flake8..."
	flake8 w3af/ --count --show-source --statistics || true
	@echo "Running pylint..."
	pylint w3af/ --disable=all --enable=E || true

# Code formatting
format:
	black w3af/
	isort w3af/

# Type checking
typecheck:
	mypy w3af/ --ignore-missing-imports --warn-unused-configs

# Security scanning
security:
	@echo "Running bandit..."
	bandit -r w3af/ -f json -o bandit-report.json || true
	@echo "Running safety..."
	safety check --json -o safety-report.json || true

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache/ .mypy_cache/ .coverage
	rm -rf htmlcov/ coverage.xml
	rm -rf __pycache__/ w3af/**/__pycache__
	rm -f bandit-report.json safety-report.json

# Docker
docker-build:
	docker build -t w3af:latest .

docker-run:
	docker run -it w3af:latest ./w3af_console

docker-shell:
	docker run -it w3af:latest /bin/bash

# Pre-commit
pre-commit:
	pre-commit run --all-files

# Development setup
dev-setup: install-dev format typecheck

# CI-like full check
ci: format typecheck test-cov security