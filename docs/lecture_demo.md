# Репетиция двух демо — 6 октября 2026

Ноутбуки сохранены полностью: 02 — 34 ячейки, 03 — 21 ячейка.
Основной маршрут рассчитан на 13 минут объяснения и 2 минуты запаса.

## Измеренный запуск

| Проверка | Результат |
|---|---|
| Notebook 02: полный Run All в свежем kernel | 26,3 с с запуском kernel; 16 code cells; 15 графических выводов; ошибок нет |
| Экспорт KDD и загрузка joblib | PASS; pipeline, threshold и пример входных наблюдений сохранены |
| Отдельный CLI-инференс | 100 наблюдений без меток; score и prediction совпали с сохранённым pipeline |
| Notebook 03: свежий вызов Qwen и Suricata | 12,97 с внутри ячеек / 13,8 с с запуском kernel; 10 code cells; ошибок нет |
| Candidate Suricata | Syntax PASS; 60/60 учебных подозрительных событий; benign matches 0 |
| Широкий отрицательный контроль `.test` | Syntax PASS; benign matches 5351; REJECT |

Финальная репетиция notebook 03 использовала новый реальный capture
`artifacts/rule_generation/prepared`: baseline и A по 6000 запросов за 40 секунд.
Новые LLM request/response, правило, syntax check и replay сохранены в
`artifacts/rule_generation/demo/20261006T163113390589Z`.
Независимая CLI-команда тоже проверена на этом capture:
`artifacts/rule_generation/lecture-verification`. Обнаружено 60/60 подозрительных событий,
benign matches 0, capture/replay missing events 0. Сценарий B для этой команды не требовался.
Старые ответы и отчёты не копировались: `copy_capture` переносит только raw-трафик,
ground truth и settings. Резервный режим OFFLINE явно выключен.

Таблица измеряет выполнение кода на этой машине, не скорость объяснения.
Capture, Docker build/pull и установка модели вынесены в подготовку.

## Порядок показа

1. **0–2 мин, 02:** несколько KDD-событий, normal/attack и признаки. Это исторические соединения,
   не временная лента и не текущий трафик генератора.
2. **2–4 мин, 02:** normal train → IF → выбранный на validation порог → раздел 9.1:
   точки типичных/аномальных соединений, сравнение с истинными метками и score всех test-событий.
   Полный Run All включает CV и интервалы, но объяснять все таблицы не требуется.
3. **4–6 мин, 02:** один локальный SHAP-пример и сохранение; `make infer` в отдельном процессе.
   Для IF SHAP объясняет длину пути изоляции; score не является вероятностью атаки.
4. **6–8 мин, 03:** реальные DNS rows генератора и имя, отсутствующее в baseline;
   живой вызов Qwen → условия DetectionSpec.
5. **8–11 мин, 03:** читаемый `candidate.rules`; Suricata `-T` и `-r`; первые alerts в `eve.json`.
6. **11–13 мин, 03:** quality gate и широкий `.test`; вывод о проверке человеком.
7. **13–15 мин:** вопросы и запас.

Разделы 7–9 третьего notebook сохранены как дополнительная behavioral-практика,
по умолчанию выключены. Они не обязательны для первого KDD-демо.

## Граница результата LLM

Qwen 0.6B верно выбрала наблюдаемый DNS suffix и дала исполнимые условия.
В свободном тексте снова встретилась неподтверждённая фраза про отсутствие совпадений
с известными malicious domains; threat intelligence ей не предоставлялась.
`test_plan` тоже содержит лишние рассуждения про агрегации. Это не основание для автопубликации.
Условия проходят схему, renderer и реальный replay; смысл hypothesis читает аналитик.

LLM создаёт DetectionSpec, Python записывает правило Suricata, движок исполняет именно этот файл.
Исполнение — offline ALERT replay, не установка в действующий IPS.

## Быстрые команды

```bash
make notebook
make infer
make rules
```

На этой машине исходный Docker build завис в Desktop credential-helper при чтении
метаданных публичных образов. Проверка сборки/подготовки выполнена с временным Docker config
без credential-helper; глобальные настройки Docker не менялись.
Для capture на уже собранном актуальном образе доступен `CAPTURE_FLAGS=--no-build`.

## Остальные проверки

- `pytest`: 43 passed, 2 opt-in integrations skipped; локальные Ollama/Suricata отдельно проверены настоящим pipeline.
- Ruff, diff check, frozen sync и Compose config (default/live): PASS.
- Live smoke с общим образом: PASS; matched=27, Prometheus targets up=3, generator restarts=0.
- Capture/smoke/replay контейнеры удалены; сторонний контейнер Metabase сохранён.
- Для лаборатории остался один общий Python-образ, Zeek, Suricata и Prometheus; сборки на каждую роль не создаются.
