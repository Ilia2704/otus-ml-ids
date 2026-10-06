.PHONY: sync data train notebook test lint smoke up down clean-runtime prepare rules infer check-notebooks

CAPTURE ?= artifacts/rule_generation/prepared
MODEL ?= models/demo_iforest/model.joblib
INPUT ?= models/demo_iforest/inference_sample.csv
OUTPUT ?= /tmp/kdd-predictions.csv
CAPTURE_FLAGS ?=

sync:
	uv sync --frozen --all-groups

data:
	uv run ids-build-data

train:
	uv run ids-train

notebook:
	uv run python scripts/setup_notebook_kernel.py
	code notebooks/02_isolation_forest.ipynb notebooks/03_automatic_rule_generation.ipynb

prepare:
	uv run ids-rules capture --demo --scenario A --run-dir $(CAPTURE) $(CAPTURE_FLAGS)

rules:
	uv run ids-rules generate --source $(CAPTURE) --scenario A

infer:
	uv run ids-infer --model $(MODEL) --input $(INPUT) --output $(OUTPUT)

check-notebooks:
	uv run python scripts/execute_notebooks.py

test:
	uv run pytest

lint:
	uv run ruff check .

smoke:
	./scripts/smoke_live.sh

up:
	docker compose build generator
	docker compose --profile live up --no-build

down:
	docker compose --profile live down

clean-runtime:
	find runtime -type f ! -name '.gitkeep' -delete
