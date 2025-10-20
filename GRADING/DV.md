# DV - Мини-проект «DevOps-конвейер»

## 0) Мета

- **Проект (опционально BYO):** [«учебный шаблон» (secdev-seed-s06-s08)](https://github.com/TVI-ARTEM/secdev-06-08)
- **Версия (commit/date):** `v1` / `2025-10-20`
- **Кратко (1-2 предложения):** тестируем: SQLi, XSS, rate-limit, заголовки безопасности и работу env-конфига, публикуем: образ приложения
- **Группа:** Беловицкий Владислав, Жулин Артем, Кочнев Виктор, Сергеев Илья, Сидоренков Олег
  
---

## 1) Воспроизводимость локальной сборки и тестов (DV1)

- **Команда для запуска образа:**

  ```bash
  make compose
  ```

- **Команда для уничтожения образа:**

  ```bash
  make decompose
  ```

- **Команда для запуска тестов:**

  ```bash
  `make venv` + `make deps` + `make init` - создать окружение
  `make run` - запустить приложение
  `make ci-s06` - запустить тесты, результат создастся в `EVIDENCE/S06`, файл `test-report.xml`
  ```

- **Версии инструментов:**

  ```bash
  python --version
  pip freeze > EVIDENCE/S06/requirements.txt
  ```

- **Локальный запуск:**
  - Для локального запуска достаточно вызвать команду `make compose`, которая запустит docker-образ версии указанной в [docker-compose.yml](https://github.com/TVI-ARTEM/secdev-06-08/blob/main/docker-compose.yml) - в текущей версии latest версию

EVIDENCE: 
  - [requirements](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/requirements.txt)
  - [docker-compose.yml](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/docker-compose.yml)
  - [Makefile](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/Makefile)

---

## 2) Контейнеризация (DV2)

- **Dockerfile:** `./Dockerfile` - базовый образ python:3.11-slim, добавлены healthcheck и non-root.
- **Сборка b запуск локально:**
  
  ```bash
  docker build -t secdev-seed-web:latest .
  docker run --rm -p 8080:8080 secdev-seed-web:local
  ```

  - Healthcheck: 200
  - No-Root: 1001

- **docker-compose:** запускает образ `tvi02/secdev-app` версии `latest` (в текущей версии docker-compose), собранной при выполнение ci/cd.

EVIDENCE:
  - [CI/CD Запуски](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci-run.txt)
  - [docker-compose.yml](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/docker-compose.yml)
  - [Dockefile](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/Dockerfile)
  - [build.log](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/build.log)
  - [compose-up.log](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/compose-up.log)
  - [health.json](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/health.json)
  - [http_root_code.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/edit/main/GRADING/DV.md)
  - [image-size.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/image-size.txt)
  - [inspect_web.json](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/inspect_web.json)
  - [non-root.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/edit/main/GRADING/DV.md)
  - [run.log](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S07/run.log)
  - [CD](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/cd.yml)

---

## 3) CI: базовый pipeline и стабильный прогон (DV3)

- **Платформа CI:** GitHub Actions
- **Файл конфига CI:** `.github/workflows/ci.yml`
- **Стадии (минимум):** **checkout** → **deps** → **setup** → **cache** → **deps** → **secrets read** → **pre-commit** → **init db** → **test** → **artifacts**
- **Фрагмент конфигурации:**

  ```yaml
  # TODO: укоротите под себя
  jobs:
  build_test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Cache pip
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-
      - name: Install deps
        run: |
          pip install -r requirements.txt
          pip install pre-commit
      - name: Prepare masked secrets
        shell: bash
        env:
          SECRET_KEY: ${{ secrets.SECRET_KEY }}
        run: |
          ...
      - name: Pre-commit checks
        run: pre-commit run --all-files
      - name: Init DB
        run: python scripts/init_db.py
      - name: Run tests
        run: |
          mkdir -p EVIDENCE/S08
          pytest -q --junitxml=EVIDENCE/S08/test-report.xml
        continue-on-error: false
      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: evidence-s08
          path: |
            EVIDENCE/S08/**
          if-no-files-found: warn
  ```

- **Стабильность:** последние 14 запусков зеленые ([link](https://github.com/TVI-ARTEM/secdev-06-08/actions))
- **CD:** кроме CI был добавлен CD Для сборки свежего образа, создаются два тега - один с новым id, другой обновляет `latest` тег, что позволяет запускать `docker-compose` на свежем релизе.
- **Ссылка/копия лога прогона:** `EVIDENCE/S08/ci-run.txt` ([link](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci-run.txt))

EVIDENCE:
  - [CI/CD Запуски](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci-run.txt)
  - [CI](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci.yml)
  - [CD](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/cd.yml)


---

## 4) Артефакты и логи конвейера (DV4)


| Артефакт/лог                    | Путь в `EVIDENCE/`            | Комментарий                                  |
|---------------------------------|-------------------------------|----------------------------------------------|
| Лог успешной сборки/тестов и сборки образа (CI/CD) | [S08/ci-run.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci-run.txt)     | Ссылки на успешные выполнения CI/CD запусков                       |
| Локальный лог сборки     | [S06/ci-so6-test.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/ci-so6-test.txt)  | Локальный запуск тестов и сборки перед загрузкой в CI                                  |
| Результаты запуска тестов      | [S08/test-report.xml](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/test-report.xml)          |  Отчет в формате XML с результатами всех unit-тестов. Можно открыть любым текстовым редактором.        |
| Версии инструментов      | [S06/requirements.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/requirements.txt) | Список используемых Python-пакетов с точными версиями для воспроизводимости сборки.                  |
| Описание CI | [S08/ci.yml](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci.yml)  | Конфигурация GitHub Actions |
| Описание CD | [S08/cd.yml](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/cd.yml) | Конфигурация деплоя Docker-образа в контейнерный реестр. Содержит шаги сборки и публикации с версией, привязанной к коммиту. |
| Docker-образ после CD| [S08/cd-docker.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/cd-docker.txt) | Ссылка на docker-образ в hub.docker |


---

## 5) Секреты и переменные окружения (DV5 - гигиена, без сканеров)

- **Шаблон окружения:** [env.example](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/env.example)
- **Хранение и передача в CI:**
  - проверка наличии секректов проверяется в [pre-commit](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/pre-commit-config.yaml#L10)
  - секреты лежат в настройках репозитория.
  - в pipeline они **не печатаются** в явном виде.
- **Пример использования секрета в job CI:**

  ```yaml
      - name: Prepare masked secrets
        shell: bash
        env:
          SECRET_KEY: ${{ secrets.SECRET_KEY }}
        run: |
          source="placeholder"
          if [ -n "${SECRET_KEY}" ]; then
            source="github-secret"
          else
            SECRET_KEY="ci-placeholder-secret"
          fi
          echo "::add-mask::$SECRET_KEY"
          echo "SECRET_KEY=$SECRET_KEY" >> "$GITHUB_ENV"
          echo "SECRET_KEY_SOURCE=$source" >> "$GITHUB_ENV"
          echo "SECRET_KEY_LENGTH=${#SECRET_KEY}" >> "$GITHUB_ENV"
  ```

- **Пример использования секрета в job CD:**

  ```yaml
      - name: Build and Push SecDev App
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: |
            ${{ secrets.DOCKER_USERNAME }}/secdev-app:${{ github.sha }}
            ${{ secrets.DOCKER_USERNAME }}/secdev-app:latest
          labels: ${{ steps.meta.outputs.labels }}
  ```

- **Быстрая проверка отсутствия секретов в коде:**

  ```bash
  git grep -nE 'AKIA|SECRET|token=|password='
  ```

  Результат: [grep-secrets.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/grep-secrets.txt)
- **Памятка по ротации:** [SECURITY.md](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/SECURITY.md)

EVIDENCE:
  - [grep-secrets.txt](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/grep-secrets.txt)
  - [Использование секретов в CI](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci.yml#L37-L47)
  - [Использование секретов в CD](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/cd.yml#L37-L39)
  - [Запуск CI/CD](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/ci-run.txt)
  - [Памятка по ротоации](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/SECURITY.md)
  - [Наличие Secret'ов](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S08/repo-secrets.png)
  - [pre-commit-config.yaml](https://github.com/TVI-ARTEM/secdev-lite-repo/blob/main/EVIDENCE/S06/pre-commit-config.yaml)

---

## 6) Индекс артефактов DV

_Чтобы преподаватель быстро сверил файлы._

| Тип     | Файл в `EVIDENCE/`            | Дата/время         | Коммит/версия | Runner/OS    |
|---------|--------------------------------|--------------------|---------------|--------------|
| CI-лог  | `ci-YYYY-MM-DD-build.txt`      | `YYYY-MM-DD hh:mm` | `abc123`      | `gha-ubuntu` |
| Лок.лог | `local-build-YYYY-MM-DD.txt`   | …                  | `abc123`      | `local`      |
| Package | `package-notes.txt`            | …                  | `abc123`      | -            |
| Freeze  | `pip-freeze.txt` (или аналог)  | …                  | `abc123`      | -            |
| Grep    | `grep-secrets.txt`             | …                  | `abc123`      | -            |

---

## 7) Связь с TM и DS (hook)

- **TM:** этот конвейер обслуживает риски процесса сборки/поставки (например, культура работы с секретами, воспроизводимость).  
- **DS:** сканы/гейты/триаж будут оформлены в `DS.md` с артефактами в `EVIDENCE/`.

---

## 8) Самооценка по рубрике DV (0/1/2)

- **DV1. Воспроизводимость локальной сборки и тестов:** 2  
- **DV2. Контейнеризация (Docker/Compose):** 2  
- **DV3. CI: базовый pipeline и стабильный прогон:** 2  
- **DV4. Артефакты и логи конвейера:** 2  
- **DV5. Секреты и конфигурация окружения (гигиена):** 2  

**Итог DV (сумма):** 10/10
