.PHONY: setup backend frontend dev test lint seed demo mitre benchmark up down

setup:            ## install backend + frontend dependencies
	cd backend && uv sync
	cd frontend && npm install

backend:          ## run the API on :8000 (SQLite by default)
	cd backend && uv run uvicorn app.main:app --reload --port 8000

frontend:         ## run the UI on :3000 (proxies /api to :8000)
	cd frontend && npm run dev

seed:             ## regenerate the synthetic corpus into data/demo (SEED=7)
	cd backend && uv run python ../scripts/generate_demo_data.py --seed $${SEED:-7}

demo:             ## load demo data + run the pipeline via the API (backend must be running)
	curl -s -X POST localhost:8000/api/v1/demo/load -H 'content-type: application/json' -d '{"seed": 7, "run_pipeline": true}'

mitre:            ## re-download the official ATT&CK STIX bundle and rebuild the catalog snapshot
	cd backend && uv run python ../scripts/download_mitre.py

benchmark:        ## run pipeline + ground-truth metrics for several seeds
	cd backend && uv run python ../scripts/benchmark_pipeline.py --seeds 7 11 23

test:             ## backend tests + frontend type-check
	cd backend && uv run pytest -q
	cd frontend && npx tsc -b

lint:
	cd backend && uv run ruff check app tests
	cd frontend && npm run lint

up:               ## full stack with Postgres + pgvector
	docker compose up --build

down:
	docker compose down
