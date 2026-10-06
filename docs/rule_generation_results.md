# Проверенный результат: автоматическое создание detection rules

Запуск: 2026-10-05 21:14 -03. Все числа ниже измерены на реальном generator → Zeek/PCAP capture.
Артефакты: `artifacts/rule_generation/qwen06-complete/` (около 70 MiB, gitignored).

## Модель и ресурсы

4B выгружена и удалена командой `ollama rm hf.co/Qwen/Qwen3-4B-GGUF:Q4_K_M` по запросу пользователя.
`ollama list` показывает только `hf.co/Qwen/Qwen3-0.6B-GGUF:Q8_0` (639 MB на диске).
Digest: `54d053a1b435c1f0cbe74f83da1a2365857b61e8ca04751d37c491ec15f32ab7`. Ollama `0.35.1`.
Контекст 4096 tokens, temperature 0, seed 42, `keep_alive=0`. `ollama ps` после проверок пуст.
Модели не скачивались, cloud API не использовались. Capture, inference и replay выполнялись последовательно.
Ответы A/B заняли около 7.6 и 9.9 секунд; оба final specs получены с первой попытки при prompt `detection-spec-v3`.
Эти времена относятся только к проверенному локальному запуску.

## Архитектура и обнаруженные компоненты

Существующий generator отправляет реальные DNS/HTTP запросы в lab-service. Zeek наблюдает namespace
генератора и сохраняет JSON logs. Ground truth уже отделён; event_id встроен в query/URI.
Существующие detector/evaluator, 16 KDD-подобных признаков, models и два KDD notebooks сохранены.
Уже были httpx, Pydantic, YAML, pandas, sklearn, Parquet в analysis group, uv и pytest.
Suricata, PCAP replay и Ollama adapter отсутствовали; они добавлены как небольшая опциональная практика.

```text
A: existing generator → Zeek + PCAP → novel DNS evidence relative to baseline
   → local Qwen0.6B → validated DetectionSpec → deterministic ALERT renderer
   → Suricata -T → Suricata -r → quality report → human review
B: existing generator → Zeek DNS → per-session windows → fit IF on baseline
   → top-N evidence → Qwen0.6B → behavioral specification → evidence sanity check
   → manual review / future correlation detector
```

## Scenario A

6 000 delivered requests: 60 synthetic suspicious events, 5 940 benign events.
Relevant evidence определяется новизной имени относительно отдельного baseline; labels не участвуют.

DetectionSpec (ключевые поля):

```json
{
  "name": "telemetry-update.bad-example.test",
  "hypothesis": "The observed activity could be related to automated requests or benign automation, but no definitive proof of an attack has been established.",
  "rule_type": "ioc",
  "protocol": "dns",
  "conditions": [
    {
      "field": "dns.query",
      "operator": "endswith",
      "value": ".telemetry-update.bad-example.test"
    }
  ],
  "suricata_compatible": true,
  "requires_correlation": false
}
```

Реальный candidate rule:

```suricata
alert dns any any -> any any (msg:"LOCAL GENERATED candidate"; dns.query; content:".telemetry-update.bad-example.test"; nocase; endswith; sid:9900001; rev:1;)
```

| Проверка | Измеренный результат |
|---|---:|
| Suricata 8.0.0 syntax | PASS |
| Suspicious events detected | 60/60 |
| Missed events | 0 |
| Benign matches | 0 |
| Alerts | 60 |
| Precision | 1.0 |
| Missing capture / replay events | 0 / 0 |
| Decision | ACCEPT_CANDIDATE |

Правило только candidate, не активировано в IPS. Для offline replay DNS на учебном UDP5353
явно разрешён как DNS, mDNS parser отключён только в этом запуске. Без этого Suricata 8
определяла учебные requests как mDNS. Настройки сохраняются в exact replay command.

Контрольное широкое правило `.test` тоже прошло syntax check, но получило
**5351 benign matches**, 5411 alerts и precision 0.0111:
**REJECT**. Оно написано локально как negative control, не выдаётся за ответ LLM.

## Scenario B

Baseline: 32 окна из 5 409 реальных DNS-событий. Mixed: 6 000 requests, 60 behavioral events.
Окна 5 секунд в ускоренном профиле, entity — source IP + persistent UDP source port.
IF trained без labels; 200 деревьев, random_state 42. Весь ranking сохранён в Parquet.
Окно с максимальной уникальностью — rank **2**, anomaly score **0.5904**.
Rank 1 здесь является другим необычным окном: IF ranking не равен attack verdict.

| Признак | Baseline p95 | Выбранное необычное окно |
|---|---:|---:|
| unique_subdomains | 4 | 63 |
| avg_qname_length | 19.1667 | 22.6877 |
| nxdomain_ratio | 0.0396 | 0.2082 |

Qwen hypothesis: «The observed anomalous DNS windows suggest that the source IP and persistent UDP source port are engaging in automated requests or benign automation.».
Модель описала увеличенную уникальность, длину и NXDOMAIN; атакой это не объявила.
Она не дала надёжной атрибуции tunneling/DGA — такое утверждение потребовало бы дополнительных evidence.

```json
{
  "rule_type": "behavioral",
  "conditions": [
    {
      "field": "unique_subdomains",
      "operator": "gt",
      "value": 33.5
    },
    {
      "field": "avg_qname_length",
      "operator": "gt",
      "value": 20.9272
    },
    {
      "field": "nxdomain_ratio",
      "operator": "gt",
      "value": 0.1239
    }
  ],
  "suricata_compatible": false,
  "requires_correlation": true,
  "correlation_entity": "source IP and persistent UDP source port",
  "window_seconds": 5
}
```

Совместные условия совпали с **1/5 top-N окон** и
**0/32 baseline-окон**.
Это evidence-only sanity check, не готовый production correlation engine. Decision: REQUIRES_REVIEW.

Для маленькой 0.6B Python подготавливает допустимые numeric predicates из baseline p95 и elevated top-N
значений. Qwen выбирает 2–3 предиката и формулирует объяснение. Пороги не выдаются за свободное
изобретение модели. Контракт для DNS IOC допускает один наблюдаемый suffix; контракт для windows
допускает только behavioral logic. Тем самым capabilities ограничиваются кодом, а не доверяются LLM.

## Осмысленность ответа и ограничения 0.6B

Условия final A/B привязаны к evidence и проверены. Но **весь свободный текст нельзя считать правильным**.
В A модель написала, что домен не совпадает с известными malicious domains: threat intelligence ей
не предоставлялась, поэтому утверждение неподтверждено. Часть test_plan говорит про агрегацию или
benignness вместо matching DNS suffix. Это нужно разобрать со студентами, а не скрывать.
Текст не контролирует action, SID, header, rule syntax или quality gate.

Первый менее ограниченный прогон 0.6B дал `http.query` вместо DNS-поля, затем несовместимые поля;
полный первоначальный прогон объединил три разных имени через AND и предложил невозможное
`unique_base_domains > 2`, когда максимум в evidence равнялся 2. Эти проблемы не маскировались:
контракт усилен и результаты повторно проверены. Исходные результаты сохранены в
`initial_model_checks/` и `initial_pipeline/`; final evaluation находится в A/B.

Итог: 0.6B пригодна для **этой ограниченной учебной практики**. Она не является надёжным
свободным генератором detection logic; prose и test_plan требуют редактуры аналитиком.
Подробная оценка: `semantic_assessment.json` рядом с runtime artifacts.

## Проверки

- Исходный baseline: 23 unit tests и lint прошли; compatibility smoke также проверен.
- Итог: 41 unit tests passed, 2 optional integrations skipped в обычном suite; ruff и diff check чистые.
- Финальный live smoke прежнего стенда: PASS, matched=19, Prometheus targets up=3, generator restarts=0.
- Opt-in local Qwen native integration: PASS; реальный final pipeline A/B: validated specs, без retry.
- Opt-in Suricata integration на generator PCAP: PASS.
- Третий notebook executed в свежем kernel на сохранённых real artifacts; оба старых notebooks не перезаписывались.
- `uv sync --frozen --all-groups` прошёл, новых dependencies нет, lockfile не потребовал изменения.

## Как показывать занятие: 10–15 минут

Откройте `notebooks/03_automatic_rule_generation.ipynb` в VS Code, выберите проектную `.venv`.
Notebook уже содержит фактические outputs. Если локальный `qwen06-complete` существует,
первая ячейка автоматически выбирает его для Run All:
сохранённые capture/spec/reports загружаются без повторного traffic и inference.

1. Показать raw Zeek DNS rows и отдельный ground truth sidecar, который дальше не читается.
2. Показать новый относительно baseline домен и 60 наблюдений. Новизна не доказывает атаку.
3. Показать spec и читаемое ALERT rule; разобрать неподтверждённую фразу Qwen про known threats.
4. SYNTAX PASS → replay 60/60, benign 0 → accepted_candidate. Никакого deployment.
5. Сравнить с широким `.test`: SYNTAX PASS, но benign matches 5 351 → REJECT.
6. B: таблица baseline vs окно из top-N с максимальной уникальностью, затем весь ranking.
7. Обсудить, почему rank 1 не обязан быть атакой, а behavioral burst здесь rank 2.
8. Показать Qwen hypothesis, три условия, sanity check 0/32 vs 1/5.
9. Завершить `suricata_compatible=false`, `requires_correlation=true`: нужен correlation detector,
   простая Suricata signature не считает уникальность/энтропию/NXDOMAIN по окнам.

Ключевой тезис: **AI proposes · code constrains · engine validates · data tests · human approves.**

## Точные команды

Подготовка / просмотр готовых результатов:

```bash
uv sync --frozen --all-groups
uv run ids-rules health
uv run python scripts/setup_notebook_kernel.py
RULE_DEMO_RUN=artifacts/rule_generation/qwen06-complete \
  uv run python scripts/execute_notebooks.py 03_automatic_rule_generation.ipynb
```

Новый end-to-end запуск (с новым пустым каталогом, Docker/Ollama должны работать):

```bash
uv run ids-rules all --demo --run-dir artifacts/rule_generation/lecture-new
```

Подготовка заранее и отдельно inference:

```bash
uv run ids-rules capture --demo --run-dir artifacts/rule_generation/lecture-prepared
uv run ids-rules generate --run-dir artifacts/rule_generation/lecture-prepared
```

Возобновление после завершённого capture-периода с теми же settings:

```bash
uv run ids-rules capture --demo --resume --run-dir artifacts/rule_generation/lecture-prepared
```

Checks:

```bash
uv run pytest
uv run ruff check .
RUN_OLLAMA_INTEGRATION=1 uv run pytest tests/test_rule_generation.py -m integration -k qwen
RULE_RUN_DIR="$PWD/artifacts/rule_generation/qwen06-complete/A" \
  RUN_SURICATA_INTEGRATION=1 uv run pytest tests/test_rule_generation.py -m integration -k suricata
ollama ps
ollama list
```

Runtime artifacts не коммитятся. Для другой машины нужно выполнить новый capture.
Realistic профиль без `--demo`: 0.1%, 60-секундные окна, три периода по 480 секунд;
demo: 1%, 5-секундные окна, три периода по 40 секунд. Повторные LLM prose могут отличаться.
Полный сетевой прогон проверен именно для `--demo`. При 0.1% редкий burst может не попасть
в top-5 IF; это наблюдалось в отдельной проверке планов генератора. Для лекции используйте
проверенный demo-профиль; надёжное обнаружение в realistic-профиле здесь не заявляется.

## Файлы и необходимость изменений

Изменены:

- `src/ids_ml_lab/generator.py` — finite lecture profiles in the existing generator
- `src/ids_ml_lab/lab_service.py` — synthetic NXDOMAIN, legacy responses preserved
- `src/ids_ml_lab/features.py` — lecture DNS windows, legacy feature contract preserved
- `zeek/local.zeek` — optional capture-ready marker
- `pyproject.toml` — ids-rules CLI and integration marker; no dependencies added
- `README.md` — architecture, commands, limitations
- `.gitignore` — heavy runtime artifacts excluded

Добавлены:

- `src/ids_ml_lab/rule_generation.py` — discovery/spec/renderer/orchestration
- `src/ids_ml_lab/ollama.py` — local HTTP, schema, retry and provenance
- `src/ids_ml_lab/rule_validation.py` — capture, rotated logs, replay and quality gate
- `config/rule_generation.yaml` — seed/rates/windows/model/quality thresholds
- `docker-compose.rules.yml` — optional override for existing services
- `prompts/detection_rule_system.txt` — versioned system prompt
- `notebooks/03_automatic_rule_generation.ipynb` — executed compact lecture
- `tests/test_rule_generation.py` — unit and opt-in integration checks
- `docs/rule_generation_results.md` — this report

Упрощения относительно production: четыре personas в одном контейнере, synthetic .test domains,
last-two-label base domain вместо PSL, малый baseline, короткие demo windows, ограниченный renderer,
подготовленные numeric predicates, ручная проверка prose, отсутствие correlation engine и deployment.
Это сохраняет фокус занятия на evidence → candidate detection → validation.
