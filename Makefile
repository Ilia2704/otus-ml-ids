.PHONY: sync data train notebook test lint smoke up down clean-runtime

sync:
	uv sync --frozen --all-groups

data:
	uv run ids-build-data

train:
	uv run ids-train

notebook:
	uv run python scripts/setup_notebook_kernel.py
	code notebooks/01_train_validate_explain.ipynb notebooks/02_isolation_forest.ipynb

test:
	uv run pytest

lint:
	uv run ruff check .

smoke:
	./scripts/smoke_live.sh

up:
	docker compose up --build

down:
	docker compose down

clean-runtime:
	find runtime -type f ! -name '.gitkeep' -delete
