# IDS/IPS & ML lab

Воспроизводимый production-like учебный стенд для anomaly-based IDS: публичный подготовленный датасет, Isolation Forest, SHAP, long-running генератор трафика, live Zeek, detector, ground-truth evaluator и Prometheus. Grafana намеренно не включена: на практике достаточно Prometheus UI и PromQL.

> Стенд предназначен для обучения. Он обнаруживает события, но не блокирует пакеты и не должен подключаться к внешней сети как реальный IPS.

## Что уже лежит в репозитории

- `data/source/` — исходный публичный KDD Cup 1999 10% с проверяемой SHA-256 и описанием происхождения;
- `data/prepared/` — готовые `train.parquet`, `validation.parquet`, `test.parquet` и manifest;
- `notebooks/01_train_validate_explain.ipynb` — preprocessing, Isolation Forest, ROC/PR, CV, bootstrap CI, KS, полные метрики, confusion matrix, threshold selection и SHAP;
- `models/ids_iforest_v1/` — готовый artifact: pipeline, threshold, schema, metadata, validation report;
- `src/ids_ml_lab/` — generator, online feature adapter, detector, evaluator и внутренние DNS/HTTP-сервисы;
- `zeek/` — live capture с JSON-логами;
- `prometheus/` — scrape-конфигурация и alert rules;
- `tests/` — unit-тесты feature contract, inference и live evaluation;
- `docker-compose.yml` — весь live-стенд без Grafana.

## Архитектура

```text
                       ┌──────────────┐
                       │ lab-service  │  DNS :5353 / HTTP :8080
                       └──────▲───────┘
                              │ synthetic traffic
┌─────────────┐  truth JSONL  │      shared network namespace
│  generator  ├───────────────┼────────────────────┐
└──────┬──────┘               │                    │
       │ metrics              │              ┌─────▼─────┐ JSON logs
       │                      └──────────────►│   Zeek    ├─────────┐
       │                                     └───────────┘         │
       │                                                           ▼
       │                                                   ┌────────────┐
       │                                                   │  detector  │
       │                                                   └─────┬──────┘
       │                                                         │ predictions
       │                    ┌─────────────┐                      ▼
       └───────────────────►│ Prometheus  │◄─────────────┌────────────┐
                            └─────────────┘               │ evaluator  │◄── truth
                                                         └────────────┘
```

`event_id` встраивается в DNS query или HTTP URI. Поэтому evaluator сопоставляет Zeek-derived prediction с ground truth без приблизительного timestamp join.

## Требования

- `uv` 0.12+;
- Python 3.12 (его установкой управляет `uv`);
- Docker Desktop / Docker Engine с Compose v2 — только для live-стенда;
- ориентировочно 3 GB свободного места для образов и окружения.

## Быстрый старт: ML-часть

```bash
uv sync --frozen --all-groups
uv run pytest
uv run jupyter lab notebooks/01_train_validate_explain.ipynb
```

Готовые Parquet splits и model artifact уже включены. Чтобы проверить полную воспроизводимость с локального публичного source-файла:

```bash
uv run ids-build-data
uv run ids-train
uv run pytest
```

`ids-train` является каноническим путём изготовления модели и всегда создаёт согласованный полный artifact: pipeline, feature schema, threshold, metadata, validation report и SHAP importance. Notebook использует тот же training path при финальном экспорте.

Builder сначала проверяет SHA-256 источника, затем делает deterministic deduplication, balanced sample и stratified split 60/20/20 с seed `42`. Обучение использует только normal-строки training split. Validation labels нужны для выбора threshold, test используется один раз для финальной оценки.

## Быстрый старт: live-стенд

Готовый model artifact уже включён, поэтому достаточно:

```bash
docker compose up --build
```

Перед новой студенческой демонстрацией рекомендуется удалить runtime volumes предыдущего запуска:

```bash
docker compose down -v
docker compose up --build
```

Короткая автоматическая проверка запускается в отдельном Compose project и удаляет только созданные ею временные volumes:

```bash
make smoke
```

После старта доступны:

- Prometheus: <http://localhost:9090>
- generator metrics: <http://localhost:9101/metrics>
- detector metrics: <http://localhost:9102/metrics>
- evaluator metrics: <http://localhost:9103/metrics>

Полезные PromQL-запросы:

```promql
sum by (label, service, attack_type) (rate(ids_generator_events_total[2m]))
sum by (prediction, source) (rate(ids_detector_predictions_total[2m]))
ids_evaluator_precision
ids_evaluator_recall
ids_evaluator_f1
ids_evaluator_false_positive_rate
ids_evaluator_confusion_total
```

Сырые данные хранятся в named volumes (это устраняет проблемы UID/GID на Linux и macOS). Их удобно смотреть так:

```bash
docker compose exec generator tail -f /runtime/truth/events.jsonl
docker compose exec zeek tail -f /logs/dns.log /logs/http.log
docker compose exec detector tail -f /runtime/predictions/events.jsonl
```

Остановка:

```bash
docker compose down
```

Prometheus history и runtime-события хранятся в отдельных named volumes. Для полностью чистого нового эксперимента остановите стенд и удалите его volumes:

```bash
docker compose down -v
```

`make clean-runtime` очищает только локальный `runtime/`, если компоненты запускались напрямую через `uv`.

## Режимы генератора

По умолчанию используется `mixed`: нормальный фон плюс DNS-tunnel-like и HTTP-burst события с ground truth. Для одного нормального фона:

```bash
GENERATOR_MODE=normal docker compose up --build
```

Интенсивность, вероятности и targets задаются в `config/generator.yaml`. Значение `GENERATOR_MODE` имеет приоритет над файлом.

## Notebook и методика оценки

Notebook показывает полный путь:

1. загрузка фиксированных train/validation/test splits и проверка schema;
2. `OneHotEncoder(handle_unknown="ignore")` для категорий и `RobustScaler` для чисел;
3. обучение Isolation Forest только на normal training data;
4. ROC AUC и PR AUC на непрерывном anomaly score;
5. 5-fold stratified CV с повторным fit только на normal-части каждого fold;
6. bootstrap 95% CI для ROC AUC и PR AUC;
7. two-sample KS между normal и attack scores;
8. threshold на validation: максимум F1 при FPR ≤ 5%;
9. accuracy, balanced accuracy, precision, recall, F1, specificity, FPR, MCC и confusion matrix на test;
10. SHAP TreeExplainer для интерпретации Isolation Forest и экспорт global feature importance.

ROC/PR и метрики считаются по anomaly score, а confusion matrix — только после фиксации threshold на validation. Test не участвует в выборе threshold.

## Offline/online feature contract

Общие 16 признаков перечислены в `dataset_builder/schema.py`. Zeek adapter строит тот же schema из rolling двухсекундного окна, DNS и HTTP полей. Семантика live-полей является приближением к KDD-99 — это сделано явно, чтобы на следующих лекциях показать:

- training-serving skew;
- schema/version registry;
- data-quality checks и drift;
- shadow/canary rollout новой модели;
- feedback labels, retraining и model registry;
- безопасное превращение IDS-сигнала в IPS policy.

## Проверки и CI-команды

```bash
uv run ruff check .
uv run pytest --cov=ids_ml_lab --cov=dataset_builder
docker compose config --quiet
```

В `uv.lock` зафиксированы все Python-зависимости. Dockerfile фиксирует Python и `uv`; Compose фиксирует версии Zeek и Prometheus. Случайные процессы используют явный seed, входной dataset проверяется checksum, а manifest содержит checksum каждого prepared split.

## Ограничения

- KDD Cup 1999 исторический и синтетический; его метрики не переносятся на современную сеть.
- Docker capture использует network namespace генератора и видит только трафик учебного контейнера.
- Live feature adapter — демонстрационный, а не совместимый с конкретным production feature store.
- SHAP объясняет поведение модели, но не доказывает причинность и не является security verdict.

Происхождение и лицензия данных подробно описаны в `data/source/README.md`. Код репозитория распространяется по MIT, dataset — отдельно по CC BY 4.0.
