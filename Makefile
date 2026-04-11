.PHONY: install install-dev test lint format check run clean

install:
	uv sync

install-dev:
	uv sync --group dev --group test

test:
	uv run pytest tests/ -m "not e2e" -v

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/

check: lint
	uv run ruff format --check src/ tests/
	uv run mypy src/

run:
	uv run tailscale-blade-mcp

clean:
	rm -rf .venv __pycache__ .pytest_cache .mypy_cache *.egg-info dist build
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
