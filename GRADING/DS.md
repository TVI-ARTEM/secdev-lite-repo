# DS - Отчёт «DevSecOps-сканы и харднинг»

## 0) Мета

- **Проект (опционально BYO):** [учебный шаблон (secdev-09-12)](https://github.com/TVI-ARTEM/secdev-09-12)
- **Версия (commit/date):** `v1` / 2025-10-26
- **Кратко (1-2 предложения):** происходит `SBOM` + `SCA`, `SAST`, `DAST` и `IaC & Container Security` сканирования. Осуществляется устранения уязвимостей зависимостей, частичное устранение DAST алертов + частичное применение хардингов на основе  `IaC & Container Security` сканирования.

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
- **Гейт по зависимостям:** Critical=0; High=0

---

## 2) SAST и Secrets (DS2)

### 2.1 SAST

- **Инструмент/профиль:** semgrep
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
- **Гейт по зависимостям:** Critical=0;

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
- **Гейт по зависимостям:** секретов не должно быть обнаружено

---

## 3) DAST и Policy (Container/IaC) (DS3)

### DAST (лайт)

- **Инструмент/таргет:** zap
- **Как запускал:**

  ```bash
  docker run --rm --network host -v $PWD/zap-work:/zap/wrk zaproxy/zap-stable zap-baseline.py -t http://localhost:8080 -r zap_baseline.html -J zap_baseline.json -d || true
  mv zap-work/zap_baseline.* EVIDENCE/S11/
  ```

- **Отчёт:** `EVIDENCE/dast-YYYY-MM-DD.pdf#alert-...`
- **Выводы:** TODO: 1-2 meaningful наблюдения

### Вариант B - Policy / Container / IaC

- **Инструмент(ы):** TODO (trivy config / checkov / conftest и т.п.)
- **Как запускал:**

  ```bash
  trivy image --severity HIGH,CRITICAL --exit-code 1 <image:tag> > EVIDENCE/policy-YYYY-MM-DD.txt
  trivy config . --severity HIGH,CRITICAL --exit-code 1 --format table > EVIDENCE/trivy-YYYY-MM-DD.txt
  checkov -d . -o cli > EVIDENCE/checkov-YYYY-MM-DD.txt
  ```

- **Отчёт(ы):** `EVIDENCE/policy-YYYY-MM-DD.txt`, `EVIDENCE/trivy-YYYY-MM-DD.txt`, …
- **Выводы:** TODO: какие правила нарушены/исправлены

---

## 4) Харднинг (доказуемый) (DS4)

Отметьте **реально применённые** меры, приложите доказательства из `EVIDENCE/`.

- [ ] **Контейнер non-root / drop capabilities** → Evidence: `EVIDENCE/policy-YYYY-MM-DD.txt#no-root`
- [ ] **Rate-limit / timeouts / retry budget** → Evidence: `EVIDENCE/load-after.png`
- [ ] **Input validation** (типы/длины/allowlist) → Evidence: `EVIDENCE/sast-YYYY-MM-DD.*#input`
- [ ] **Secrets handling** (нет секретов в git; хранилище секретов) → Evidence: `EVIDENCE/secrets-YYYY-MM-DD.*`
- [ ] **HTTP security headers / CSP / HTTPS-only** → Evidence: `EVIDENCE/security-headers.txt`
- [ ] **AuthZ / RLS / tenant isolation** → Evidence: `EVIDENCE/rls-policy.txt`
- [ ] **Container/IaC best-practice** (минимальная база, readonly fs, …) → Evidence: `EVIDENCE/trivy-YYYY-MM-DD.txt#cfg`

> Для «1» достаточно ≥2 уместных мер с доказательствами; для «2» - ≥3 и хотя бы по одной показать эффект «до/после».

---

## 5) Quality-gates и проверка порогов (DS5)

- **Пороговые правила (словами):**  
  Примеры: «SCA: Critical=0; High≤1», «SAST: Critical=0», «Secrets: 0 истинных находок», «Policy: Violations=0».
- **Как проверяются:**  
  - Ручной просмотр (какие файлы/строки) **или**  
  - Автоматически:  (скрипт/job, условие fail при нарушении)

    ```bash
    SCA: grype ... --fail-on high
    SAST: semgrep --config p/ci --severity=high --error
    Secrets: gitleaks detect --exit-code 1
    Policy/IaC: trivy (image|config) --severity HIGH,CRITICAL --exit-code 1
    DAST: zap-baseline.py -m 3 (фейл при High)
    ```

- **Ссылки на конфиг/скрипт (если есть):**

  ```bash
  GitHub Actions: .github/workflows/security.yml (jobs: sca, sast, secrets, policy, dast)
  или GitLab CI: .gitlab-ci.yml (stages: security; jobs: sca/sast/secrets/policy/dast)
  ```

---

## 6) Триаж-лог (fixed / suppressed / open)

| ID/Anchor       | Класс     | Severity | Статус     | Действие | Evidence                               | Ссылка на фикс/исключение         | Комментарий / owner / expiry |
|-----------------|-----------|----------|------------|----------|----------------------------------------|-----------------------------------|------------------------------|
| CVE-2024-XXXX   | SCA       | High     | fixed      | bump     | `EVIDENCE/deps-YYYY-MM-DD.json#CVE`    | `commit abc123`                   | -                            |
| ZAP-123         | DAST      | Medium   | suppressed | ignore   | `EVIDENCE/dast-YYYY-MM-DD.pdf#123`     | `EVIDENCE/suppressions.yml#zap`   | FP; owner: ФИО; expiry: 2025-12-31 |
| SAST-77         | SAST      | High     | open       | backlog  | `EVIDENCE/sast-YYYY-MM-DD.*#77`        | issue-link                        | план фикса в релизе N        |

> Для «2» по DS5 обязательно указывать **owner/expiry/обоснование** для подавлений.

---

## 7) Эффект «до/после» (метрики) (DS4/DS5)

| Контроль/Мера | Метрика                 | До   | После | Evidence (до), (после)                          |
|---------------|-------------------------|-----:|------:|-------------------------------------------------|
| Зависимости   | #Critical / #High (SCA) | TODO | 0 / ≤1| `EVIDENCE/deps-before.json`, `deps-after.json`  |
| SAST          | #Critical / #High       | TODO | 0 / ≤1| `EVIDENCE/sast-before.*`, `sast-after.*`        |
| Secrets       | Истинные находки        | TODO | 0     | `EVIDENCE/secrets-*.json`                       |
| Policy/IaC    | Violations              | TODO | 0     | `EVIDENCE/checkov-before.txt`, `checkov-after.txt` |

---

## 8) Связь с TM и DV (сквозная нитка)

- **Закрываемые угрозы из TM:** TODO: T-001, T-005, … (ссылки на таблицу трассировки TM)
- **Связь с DV:** TODO: какие сканы/проверки встроены или будут встраиваться в pipeline

---

## 9) Out-of-Scope

- TODO: что сознательно не сканировалось сейчас и почему (1-3 пункта)

---

## 10) Самооценка по рубрике DS (0/1/2)

- **DS1. SBOM и SCA:** [ ] 0 [ ] 1 [ ] 2  
- **DS2. SAST + Secrets:** [ ] 0 [ ] 1 [ ] 2  
- **DS3. DAST или Policy (Container/IaC):** [ ] 0 [ ] 1 [ ] 2  
- **DS4. Харднинг (доказуемый):** [ ] 0 [ ] 1 [ ] 2  
- **DS5. Quality-gates, триаж и «до/после»:** [ ] 0 [ ] 1 [ ] 2  

**Итог DS (сумма):** __/10
