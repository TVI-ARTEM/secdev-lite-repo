
.PHONY: venv deps init run test ci ci-s06 compose decompose

PY?=python3

venv:
	$(PY) -m venv .venv

deps:
	pip install -r requirements.txt

init:
	$(PY) scripts/init_db.py

run:
	uvicorn app.main:app --host 127.0.0.1 --port 8000

test:
	pytest -q

ci:
	mkdir -p EVIDENCE/S08
	pytest --junitxml=EVIDENCE/S08/test-report.xml -q

ci-s06:
	mkdir -p EVIDENCE/S06/logs
	pytest --junitxml=EVIDENCE/S06/test-report.xml --log-file=EVIDENCE/S06/logs/pytest.log --log-file-level=INFO -q


compose:
 docker compose up -d

decompose:
 docker compose down
