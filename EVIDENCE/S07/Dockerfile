
FROM python:3.11-slim

# —— Runtime env ————————————————————————————————————————————————
ENV PYTHONDONTWRITEBYTECODE=1         PYTHONUNBUFFERED=1         PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# —— Deps ————————————————————————————————————————————————————————
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# —— App —————————————————————————————————————————————————————————
COPY app ./app
COPY scripts ./scripts

RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Инициализация БД на старте контейнера (простая семинарская логика)
CMD python scripts/init_db.py && uvicorn app.main:app --host 0.0.0.0 --port 8000
