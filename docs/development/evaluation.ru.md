# Измерение статической детекции

[English](evaluation.md) · Русский

`scout-dev evaluate` проверяет размеченный JSON-корпус через публичный Scanner API,
не исполняя код примеров. Нужен Scanner без сетевых сервисов без OSV и LLM-проверок.

```bash
# Reduced/core: built-in checks only.
CGO_ENABLED=0 go run -mod=readonly -tags=coreonly ./cmd/scout-dev evaluate \
  --profile custom testdata/security-corpus/cases.json
# Full native build with a trusted PKG_CONFIG_PATH:
CGO_ENABLED=1 go run -mod=readonly -tags=static_link ./cmd/scout-dev evaluate \
  --profile standard testdata/security-corpus/cases.json
```

Standard выбирает полный статический план. В этой команде custom включает только
встроенные проверки. `--timeout` ограничивает весь корпус. Формат задан в
`testdata/security-corpus/cases.json`; один пример соответствует одному файлу.

## Метрики

- `signal` и `known_static_gap` — положительные случаи. Отсутствие находки считается
  пропуском, включая неполное сканирование.
- `benign` с находкой — ложное срабатывание. Полный benign без находок — верное отрицательное заключение; неполный результат остаётся неопределённым.
- `ambiguous` не включается в precision/recall.

Метрики используют метки и фактические находки; `expected_rules` задаёт ожидания
регрессии. Отчёт хранит хеш корпуса, движок и план, результаты случаев, метрики
категорий, число неполных проверок и локальные p50/p95. `null` означает отсутствие знаменателя.

Встроенные 26 авторских случаев — регрессионный корпус, не независимый holdout.
Для независимого измерения нужны отдельно проверенные исходники, метки, лицензии
и хеши с типом `independent_labelled_corpus`. Сохраняйте отчёт каждого запуска.
