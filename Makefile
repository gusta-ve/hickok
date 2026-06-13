.PHONY: install dev test clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -q

clean:
	rm -rf build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
