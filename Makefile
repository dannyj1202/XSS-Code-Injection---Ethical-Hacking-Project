.PHONY: help install install-dev test lint format clean run demo

# Default target
help:
	@echo "XSS Code Injection - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make install       - Install production dependencies"
	@echo "  make install-dev   - Install development dependencies"
	@echo "  make test          - Run unit tests"
	@echo "  make test-cov      - Run tests with coverage report"
	@echo "  make lint          - Run linting (ruff)"
	@echo "  make format        - Format code (black)"
	@echo "  make type-check    - Run type checking (mypy)"
	@echo "  make clean         - Clean temporary files"
	@echo "  make run           - Run the tool with default settings"
	@echo "  make demo          - Run with EICAR payload in demo mode"
	@echo "  make detect        - Run defensive detection scan"
	@echo ""

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -e .

# Testing
test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=src --cov-report=html --cov-report=term

# Code quality
lint:
	ruff check src/ tests/ detect.py

format:
	black src/ tests/ detect.py

type-check:
	mypy src/

# Quality check (all)
check: lint type-check test
	@echo "All checks passed!"

# Cleanup
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '.coverage' -delete
	rm -rf build/ dist/ *.egg-info 2>/dev/null || true

# Running the tool
run:
	@echo "Error: Please create TARGETS.txt first with allowed target IPs"
	@echo "Example: echo '192.168.1.100' > TARGETS.txt"
	@echo ""
	@echo "Then run: sudo python -m src.cli --i-have-authorization --verbose"

demo:
	@echo "Creating demo TARGETS.txt..."
	@echo "# Demo targets - replace with actual lab IPs" > TARGETS.txt
	@echo "192.168.1.100" >> TARGETS.txt
	@echo "192.168.1.101" >> TARGETS.txt
	@echo ""
	@echo "Demo TARGETS.txt created. Run with:"
	@echo "sudo python -m src.cli --i-have-authorization --payload eicar --verbose"

detect:
	python detect.py --scan

# CI/CD
ci: lint type-check test
	@echo "CI checks completed successfully"
