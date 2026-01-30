.PHONY: help install dev-install test lint format security clean docs build publish docker

help:
	@echo "Sentinel-V Cyber-Defense Framework"
	@echo ""
	@echo "Usage:"
	@echo "  make install     Install the package"
	@echo "  make dev-install Install development dependencies"
	@echo "  make test        Run tests"
	@echo "  make coverage    Run tests with coverage"
	@echo "  make lint        Run linters"
	@echo "  make format      Format code with black"
	@echo "  make security    Run security checks"
	@echo "  make clean       Clean build artifacts"
	@echo "  make docs        Build documentation"
	@echo "  make build       Build package"
	@echo "  make publish     Publish to PyPI (requires credentials)"
	@echo "  make docker      Build Docker image"

install:
	pip install -e .

dev-install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

coverage:
	pytest tests/ --cov=sentinel_v --cov-report=html --cov-report=term

lint:
	flake8 sentinel_v/ tests/ examples/
	mypy sentinel_v/
	bandit -r sentinel_v/

format:
	black sentinel_v/ tests/ examples/
	isort sentinel_v/ tests/ examples/

security:
	safety check
	bandit -r sentinel_v/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docs:
	cd docs && make html

build:
	python -m build

publish:
	twine upload dist/*

docker:
	docker build -t sentinel-v:latest .

docker-run:
	docker run -d \
		--name sentinel-v \
		-v ./config:/app/config \
		-v ./logs:/app/logs \
		--network host \
		sentinel-v:latest

version:
	@python -c "import sentinel_v; print(sentinel_v.__version__)"
