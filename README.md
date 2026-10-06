# IDS/IPS & ML: два демо для лекции

Основной показ: **Isolation Forest на KDD → отдельный инференс** и
**события генератора → LLM → правило Suricata → PCAP replay**.
Длинные ноутбуки сохранены. Обучение на KDD и сетевой replay — два отдельных сценария:
KDD-модель не выдаётся за модель, обученную на трафике генератора.

## Подготовка до занятия

Нужны Python 3.12, uv, Docker Desktop, локальный Ollama и установленная модель
`hf.co/Qwen/Qwen3-0.6B-GGUF:Q8_0`. Загрузка модели не входит в показ.

```bash
make sync
make notebook
uv run ids-rules health
make prepare
```

`make notebook` регистрирует проектное ядро и открывает ноутбуки 02 и 03 в VS Code.
Выберите ядро `Python (ids-ml-detection-lab)` из `.venv`.
`make prepare` создаёт реальный capture baseline и сценария A:
6000 запросов за 40 секунд на период, включая DNS/HTTP, 1% учебных подозрительных событий в A.
Подготовка строит один Python-образ, запускает generator + lab-service + Zeek,
сохраняет PCAP, Zeek logs и отдельный ground truth, затем удаляет временный стенд.

Подготовка требует **нового каталога**. Для повторной подготовки:

```bash
make prepare CAPTURE=artifacts/rule_generation/prepared-new
```

Если общий образ уже собран из текущего кода, можно пропустить сборку:
`make prepare CAPTURE=artifacts/rule_generation/prepared-new CAPTURE_FLAGS=--no-build`.

`03_automatic_rule_generation.ipynb` по умолчанию читает `artifacts/rule_generation/prepared`.
Если его нет, использует ранее подготовленный `qwen06-complete`, явно печатая источник.
Для другого capture задайте `RULE_DEMO_RUN` до запуска Jupyter или измените `SOURCE` в notebook.
Suricata (`jasonish/suricata:8.0.0`) должна быть загружена до занятия:

```bash
docker pull jasonish/suricata:8.0.0
```

## Показ: 13 минут + 2 минуты запаса

| Время | Действие |
|---|---|
| 0–2 мин | Notebook 02: KDD-события, очистка, графики normal/attack и признаки |
| 2–4 мин | Обучение IF на normal train; score, порог и результаты test |
| 4–6 мин | Один SHAP-пример, экспорт joblib, отдельный CLI-инференс |
| 6–8 мин | Notebook 03: события генератора, новый DNS suffix, живой запрос к Qwen |
| 8–11 мин | DetectionSpec → `candidate.rules` → Suricata syntax check и PCAP replay |
| 11–13 мин | Реальные alerts, benign matches; сравнение с широким правилом `.test` |
| 13–15 мин | Запас и вопросы |

В notebook 02 можно выполнить Run All: CV, интервалы и все графики остаются на месте.
Во время выступления достаточно остановиться на указанных результатах.
KDD исторический; его метрики не описывают качество детекта в современной сети.
Score IF — необычность, а не вероятность атаки.

## Демо 1: KDD Isolation Forest и инференс

`notebooks/02_isolation_forest.ipynb` сохраняет модель в `models/demo_iforest/`:
весь pipeline, порог, отчёты и `inference_sample.csv` с исходными признаками для проверки CLI.
Классы preprocessing остаются в `src/ids_ml_lab/demo.py`, чтобы joblib работал вне notebook.

```bash
make infer
# Произвольные новые наблюдения: CSV с заголовками или Parquet
uv run ids-infer --model models/demo_iforest/model.joblib \
  --input models/demo_iforest/inference_sample.csv --output /tmp/kdd-predictions.csv
```

Инференс загружает модель и входной файл. Не обучает модель, не читает исходный KDD,
не перестраивает splits. Требует 41 исходный KDD-признак; метки необязательны.
Старый путь `scripts/predict_demo.py` оставлен как короткая обёртка этой же команды;
вместо `--split` используются `--input` и `--output`.

## Демо 2: LLM пишет кандидат для Suricata

`notebooks/03_automatic_rule_generation.ipynb`, разделы 1–6:

```text
capture генератора → DNS evidence → локальная Qwen → DetectionSpec
→ Python renderer → rules/candidate.rules → Suricata -T → Suricata -r
→ replay/eve.json → quality_report.json
```

Как в лекции, LLM формулирует условия DetectionSpec, а renderer записывает файл
в синтаксисе Suricata с action ALERT и локальным SID. **Suricata исполняет этот файл** через `-S`.
Это offline replay кандидата; установка в действующий IPS не выполняется.
Каждый обычный Run All использует новый каталог: старый ответ LLM и старый отчёт
не подставляются. Capture повторно используется, LLM и Suricata выполняются заново.
Правило `.test` — локальный отрицательный контроль, не ответ LLM.

CLI того же сценария:

```bash
make rules
# Другой подготовленный capture
uv run ids-rules generate --source artifacts/rule_generation/prepared-new --scenario A
# Весь pipeline, включая capture, в новом каталоге
uv run ids-rules all --demo --scenario A
```

Результаты находятся в напечатанном каталоге под `artifacts/rule_generation/`:
`A/llm/`, `A/rules/candidate.rules`, `A/replay/eve.json`, `A/quality_report.json`.
Ground truth читается только при оценке, не передаётся LLM.
Для учебного UDP5353 replay явно включает DNS и отключает mDNS parser.

Дополнительные behavioral-разделы 7–9 **сохранены**. Они включаются через
`LECTURE_BEHAVIORAL=1` и требуют capture сценария B:

```bash
uv run ids-rules capture --demo --scenario both --run-dir artifacts/rule_generation/with-behavioral
```

Уникальность/entropy/NXDOMAIN по окнам требуют корреляции и не превращаются в простой suffix-rule.
Этот второй LLM-вызов не входит в обязательный показ.
`LECTURE_OFFLINE=1` явно включает резервный просмотр прошлых ответов/replay;
источник должен содержать готовые `llm`, rules и отчёты, а не только capture.

## Docker и код

| Компонент | Роль |
|---|---|
| `ids-ml-lab-generator:latest` | Один общий Python-образ для generator, lab-service и опционального live-стенда |
| `zeek/zeek:8.2.2` | Capture реальных запросов |
| `jasonish/suricata:8.0.0` | Временный `docker run --rm` для syntax check и replay |
| `prom/prometheus:v3.5.5` | Опциональный мониторинг |

Ollama работает на хосте. Обычная подготовка не запускает detector, evaluator и Prometheus.
Сервисы прежнего live-стенда сохранены под профилем `live`:

```bash
make up
make down
make smoke
```

Live-detector использует отдельную старую модель и KDD-подобные признаки;
это не инференс экспортированного полного KDD notebook. В два демо он не входит.
`01_train_validate_explain.ipynb`, dataset builder и training сохранены для других занятий.
Основные модули: `demo.py` — KDD; `inference.py` — инференс;
`generator.py` — трафик; `ollama.py` — HTTP-вызов LLM;
`rule_generation.py` — evidence/spec/renderer; `rule_validation.py` — capture/replay/оценка.
Новый DNS-инференс не добавляется: для этого показа используется KDD-инференс.

## Проверки

```bash
make test
make lint
make check-notebooks
```

`check-notebooks` выполняет 02 и 03 в свежих kernels. Для 03 нужны готовый capture,
Docker и Ollama. Исторические измерения предыдущего полного A/B pipeline:
`docs/rule_generation_results.md`; актуальная репетиция: `docs/lecture_demo.md`.
