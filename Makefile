.PHONY: help install start stop test lint docker clean

help:
	@echo "CyberSentinel Makefile Commands:"
	@echo "  make install  - Install Python dependencies"
	@echo "  make start    - Start CyberSentinel backend server"
	@echo "  make test     - Run complete test suite"
	@echo "  make docker   - Build and start Docker containers"
	@echo "  make clean    - Remove build artifacts and caches"

install:
	pip install -r backend/requirements.txt

start:
	python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

test:
	python tests/integration/test_integration.py
	python tests/integration/test_six_detectors.py
	python tests/e2e/test_e2e.py

docker:
	docker compose up --build

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache
