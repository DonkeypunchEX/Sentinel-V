.PHONY: setup test lint run docker validate
VENV=.venv
PY=$(VENV)/bin/python

setup:
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[ml,intel,dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check sentinel_v tests
	$(PY) -m mypy sentinel_v

run:
	$(PY) -m uvicorn sentinel_v.api.app:app --host 127.0.0.1 --port 8787 --reload

validate:  ## Phase 4: run Atomic Red Team procedures, assert detections fire
	@echo "TODO(Phase 4): wire Atomic Red Team validation (see docs/ROADMAP.md)"

docker:
	docker compose up --build
