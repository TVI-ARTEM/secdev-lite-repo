# DS - Отчёт «DevSecOps-сканы и харднинг»

## 0) Мета

- **Проект (опционально BYO):** [учебный шаблон (secdev-09-12)](https://github.com/TVI-ARTEM/secdev-09-12)
- **Версия (commit/date):** `v1` / 2025-10-26
- **Кратко (1-2 предложения):** происходит `SBOM` + `SCA`, `SAST`, `DAST` и `IaC & Container Security` сканирования. Осуществляется устранения уязвимостей зависимостей, частичное устранение DAST алертов + частичное применение хардингов на основе  `IaC & Container Security` сканирования.
-  **Группа:** Беловицкий Владислав, Жулин Артем, Кочнев Виктор, Сергеев Илья, Сидоренков Олег


---

## 1) SBOM и уязвимости зависимостей (DS1)

- **Инструмент/формат:** `Syft`, `Grype`; `CycloneDX`
- **Как запускал (локально):**

  ```bash
  // SBOM  сканирование
  docker run --rm -v $PWD:/work -w /work anchore/syft:latest packages dir:. -o cyclonedx-json > EVIDENCE/S09/sbom.json

  // SCA сканирование
  docker run --rm -v $PWD:/work -w /work anchore/grype:latest sbom:/work/EVIDENCE/S09/sbom.json -o json > EVIDENCE/S09/sca_report.json


  // Человекочитаемый вывод:
  echo "# SCA summary" > EVIDENCE/S09/sca_summary.md
  jq -r '
    .matches
    | map({
        artifact_name: (.artifact.name // "N/A"),
        artifact_version: (.artifact.version // "N/A"),
        vulnerability_id: (.vulnerability.id // "N/A"),
        description: (.vulnerability.description // "N/A"),
        fix_versions: (
          (.vulnerability.fix.versions // [])
          | if length == 0 then ["N/A"] else . end
          | join(", ")
        )
      })
    | unique
    | map(
        "Artifact: " + .artifact_name
        + ", version: " + .artifact_version
        + ". Vulnerability - " + .vulnerability_id
        + ": " + .description
        + ". Fixed: " + .fix_versions
      )
    | join("\n")
  ' EVIDENCE/S09/sca_report.json >> EVIDENCE/S09/sca_summary.md
  
  ```

- **Отчёты:** `EVIDENCE/S09/v*/sbom.json`, `EVIDENCE/S09/v*/sca_report.json`, `EVIDENCE/S09/v*/sca_summary.json`,
- **Выводы:** После `SCA` сканирования уязвимостей было выявлено 4 уязвимости Medium уровня
- **Действия:** обновлен package jinja2 с 3.1.6, с actions/download-artifact@v4 на actions/download-artifact@v4.1.3
- **Quality gate:** `--fail-on critical` + `Critical=0, High<=1` в `EVIDENCE/S09/ci-s09-sbom-sca.yml`.
- **Запуски:** https://github.com/TVI-ARTEM/secdev-09-12/actions/workflows/ci-s09-sbom-sca.yml
---

## 2) SAST и Secrets (DS2)

### 2.1 SAST

- **Инструмент/профиль:** semgrep, p/security-audit
- **Как запускал (локально):**

  ```bash
  docker run --rm \
            -v "$PWD:/src" \
            returntocorp/semgrep:latest semgrep ci \
              --config p/security-audit \
              --config /src/security/semgrep/rules.yml \
              --sarif \
              --output /src/EVIDENCE/S10/semgrep.sarif \
              --metrics=off
  ```

- **Отчёт:** `EVIDENCE/S10/semgrep.sarif`
- **Выводы:** не обнаружено проблем.
- **Quality gate:** `EVIDENCE/S10ci-s10-sast-secrets.yml` проверяет `Semgrep critical = 0`, иначе `exit 1`.
- **Запуски:** https://github.com/TVI-ARTEM/secdev-09-12/actions/workflows/ci-s10-sast-secrets.yml

### 2.2 Secrets scanning

- **Инструмент:** gitleaks
- **Как запускал (локально):**

  ```bash
  docker run --rm -v $PWD:/repo zricethezav/gitleaks:latest detect \
            --config=/repo/security/.gitleaks.toml \
            --source=/repo \
            --report-format=json \
            --report-path=/repo/EVIDENCE/S10/gitleaks.json
  ```

- **Отчёт:** `EVIDENCE/S10/gitleaks.json`
- **Выводы:** не обнаружено проблем.
- **Quality gate:** `EVIDENCE/S10/ci-s10-sast-secrets.yml` — `Gitleaks findings = 0`.
- **Запуски:** https://github.com/TVI-ARTEM/secdev-09-12/actions/workflows/ci-s10-sast-secrets.yml

---

## 3) DAST и Policy (Container/IaC) (DS3)

### DAST (лайт)

- **Инструмент/таргет:** zap
- **Как запускал:**

  ```bash
  docker run --rm --network host -v $PWD/zap-work:/zap/wrk zaproxy/zap-stable zap-baseline.py -t http://localhost:8080 -r zap_baseline.html -J zap_baseline.json -d || true
  mv zap-work/zap_baseline.* EVIDENCE/S11/
  ```

- **Отчёт:** `EVIDENCE/S11/v1/zap_baseline.json`, `EVIDENCE/S11/v2/zap_baseline.json`, HTML отчеты в `EVIDENCE/S11/v*/zap_baseline.html`.
- **Выводы:** v1 — 2 Medium (CSP header not set, Missing Anti-clickjacking header) + Low. После внедрения middleware с CSP/CSPP/Cache-Control (см. `EVIDENCE/S11/v2/main.py`) повторный прогон (v2) = только informational (Non-Storable Content, Potential XSS info).
- **Quality gate:** `EVIDENCE/S11/ci-s11-dast.yml` — fail если `High>0` или `Critical>0`.
- **Запуски:** https://github.com/TVI-ARTEM/secdev-09-12/actions/workflows/ci-s11-dast.yml

### Policy / Container / IaC

- **Инструмент(ы):** trivy config, checkov, hadolint
- **Как запускал (локально):**

  ```bash
  docker run --rm -i hadolint/hadolint hadolint -f json - < Dockerfile > EVIDENCE/S12/hadolint.json || true
  docker run --rm -v $PWD:/src bridgecrew/checkov:latest -d /src/iac -o json > EVIDENCE/S12/checkov.json || true
  docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v $PWD:/work \
            aquasec/trivy:latest image \
            --format json \
            --output /work/EVIDENCE/S12/trivy.json \
            --ignore-unfixed \
            s09s12-app:ci || true
  ```

- **Отчёты:** Trivy/Hadolint/Checkov JSON — `EVIDENCE/S12/v1/*`, `EVIDENCE/S12/v2/*`.  
- **Выводы:**
  - Trivy: фокус на приложении — 2 High (starlette) остаются, помечены как backlog.  
  - Checkov: фэйлов 17 → 13 благодаря `readOnlyRootFilesystem`, `runAsNonRoot`, CPU/Memory limits.  
  - Hadolint: 0 нарушений (Dockerfile вычищен).  
- **Quality gate:** `EVIDENCE/S12/ci-s12-iac-container.yml` — `Checkov violations = 0` (на данный момент в dev ветке fail)
- **Запуски:** https://github.com/TVI-ARTEM/secdev-09-12/actions/workflows/ci-s12-iac-container.yml

---

## 4) Харднинг (доказуемый) (DS4)

- [x] **Контейнер non-root / drop capabilities** -> Evidence: `EVIDENCE/S12/v2/Dockerfile`, `EVIDENCE/S12/v2/checkov.json`. Завел системного пользователя `app`, переключаем `USER`, в Kubernetes включены `runAsNonRoot`, `readOnlyRootFilesystem`. Checkov снизил `CKV_K8S_23/22`.
- [x] **Secrets handling** (нет секретов в git; хранилище секретов) -> Evidence: `EVIDENCE/S10/gitleaks.json`, `EVIDENCE/S10/ci-s10-sast-secrets.yml`. Отчет пустой, quality gate запрещает merge при утечках.
- [x] **HTTP security headers / CSP / HTTPS-only** -> Evidence: `EVIDENCE/S11/v2/main.py`, `EVIDENCE/S11/v2/zap_baseline.json`. Middleware выставляет CSP/XFO/COEP, ZAP Medium-alert'ы исчезли (см. раздел 7).
- [x] **Container/IaC best-practice** (минимальная база, readonly fs, …) -> Evidence: `EVIDENCE/S12/v2/trivy.json`, `EVIDENCE/S12/v2/checkov.json`. Использую slim-образ, `readOnlyRootFilesystem`, лимиты CPU/Memory; количество policy-нарушений сокращено 17->13.

---

## 5) Quality-gates и проверка порогов (DS5)

- **Пороговые правила (конкретные проверки):**  
  - SCA: `EVIDENCE/S09/ci-s09-sbom-sca.yml:64-86` — `--fail-on critical`, `Critical=0`, `High<=1` (см. блок `Enforce SCA quality gate`).  
  - SAST: `EVIDENCE/S10/ci-s10-sast-secrets.yml:54:94` — Semgrep критичность `>0` -> `exit 1`.  
  - Secrets: `EVIDENCE/S10/ci-s10-sast-secrets.yml:54:94` — Gitleaks `length > 0` -> fail.  
  - DAST: `EVIDENCE/S11/ci-s11-dast.yml:44-86` — ZAP High/Critical >0 -> fail.  
  - Policy: `EVIDENCE/S12/ci-s12-iac-container.yml:55-85` — Checkov `FAILED_POLICIES > 0` -> fail.
- **Автоматизация:** каждый workflow скачивает артефакты через `actions/download-artifact@v4.1.3` и применяет `jq`/bash для подсчета. Логика закончена `exit 1`, что приводит к падению pipeline при нарушении порога.
- **До/после:** см. раздел 7, итерации зафиксированы в отчетах: `EVIDENCE/S09/v3/sca_report.json` (High->0), `EVIDENCE/S11/v2/zap_baseline.json` (Medium->0), `EVIDENCE/S12/v2/checkov.json` (17->13).

---

## 6) Триаж-лог (fixed / suppressed / open)

| Канал    | Severity | Статус    | Мера / комментарий                         | Evidence                                                                                                  |
|----------|----------|-----------|--------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| SCA      | High     | fixed     | Bump `actions/download-artifact` -> v4.1.3  | `EVIDENCE/S09/v2/sca_summary.md`, `EVIDENCE/S10/ci-s10-sast-secrets.yml`       |
| SCA | High | fixed | Bump `jinja2` -> 3.1.6                      | `EVIDENCE/S09/v2/sca_summary.md`, `EVIDENCE/S09/v3/sbom.json`, `EVIDENCE/S09/v3/requirements.txt`   | 
| DAST     | Medium   | fixed     | Middleware с CSP/XFO/COEP                  | `EVIDENCE/S11/v1/zap_baseline.json`, `EVIDENCE/S11/v2/zap_baseline.json`, `EVIDENCE/S11/v2/main.py` |
| Policy   | High     | open      | Требуется Kubernetes NetworkPolicy         | `EVIDENCE/S12/v2/checkov.json`                                                                            |

---

## 7) Эффект «до/после» (метрики) (DS4/DS5)

| Контроль/Мера | Метрика                 |  До  | После | Evidence                                                            |
|---------------|-------------------------|-----:|------:|-----------------------------------------------------------------------------------------|
| Зависимости   | Critical / High (SCA) | 0 / 1| 0 / 0 | `EVIDENCE/S09/v2/sca_report.json`, `EVIDENCE/S09/v3/sca_report.json`                    |
| SAST          | Critical / High       | 0 / 0| 0 / 0 | `EVIDENCE/S10/semgrep.sarif1`     |
| Secrets       | Истинные находки        |   0  |   0   | `EVIDENCE/S10/gitleaks.json` |
| DAST          | High / Medium           | 0 / 2| 0 / 0 | `EVIDENCE/S11/v1/zap_baseline.json`, `EVIDENCE/S11/v2/zap_baseline.json`                 |
| Policy/IaC    | Violations (Checkov)    |  17  |  13   | `EVIDENCE/S12/v1/checkov.json`, `EVIDENCE/S12/v2/checkov.json`                           |

---

## 8) Самооценка по рубрике DS (0/1/2)

- **DS1. SBOM и SCA:** 2  
- **DS2. SAST + Secrets:** 2  
- **DS3. DAST или Policy (Container/IaC):** 2  
- **DS4. Харднинг (доказуемый):** 2  
- **DS5. Quality-gates, триаж и «до/после»:** 2  

**Итог DS (сумма):** 10/10
