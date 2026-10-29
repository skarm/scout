# Команды разработчика

Оглавление

- [Измерения и приёмка сборки](#измерения-и-приёмка-сборки)
- [Сохранённые исходники и replay](#сохранённые-исходники-и-replay)
- [Source-bound provenance](#source-bound-provenance)
- [Внешние эксперименты](#внешние-эксперименты)
- [Проверки памяти Tree-sitter](#проверки-памяти-tree-sitter)

[English](commands.md) · Русский

Соберите developer CLI вместе со Scout:

```sh
make build build-dev
export PATH="$PWD/bin:$PATH"
scout-dev evaluate testdata/security-corpus/cases.json
scout-dev releasecheck --binary "$(command -v scout)"
```

Другой каталог сборки задаётся через `BIN_DIR`; тогда добавьте в `PATH` его.

Для команд сохранённых данных без нативных проверок используйте
`go run -tags=coreonly ./cmd/scout-dev <command> [flags]`.
При запуске из другого каталога maintenance-команды принимают `--root PROJECT_ROOT`.

## Измерения и приёмка сборки

- `evaluate [--profile standard|custom] [--timeout 2m] CORPUS_JSON`: проверить
  размеченный корпус. Здесь custom выбирает только встроенные проверки.
- `releasecheck --binary SCOUT`: проверить linkage и metadata, затем запустить
  нативные selftests. `--inspect-only` ограничивает работу чтением бинарника.

См. [измерения](evaluation.ru.md) и [проверки](validation.ru.md).

## Сохранённые исходники и replay

- `verify-knowledge-sources --cache DIR`: сверить закреплённые байты исходников.
  `--download` разрешает загрузку недостающих файлов.
- `check-knowledge-runtime --binary SCOUT --output NEW_DIR`: проверить статические
  scans и scripted reviewer на локальном сервере.
- `compare-upstream-suite prepare --capture SAVED_DIR --replay NEW_DIR`: проверить
  blobs и подготовить входы replay.
- `compare-upstream-suite compare --capture SAVED_DIR --replay REPLAY_DIR
  --results RESULTS_JSONL --output DIFFERENCES_JSON`: сравнить replay с сохранёнными наблюдениями.
- `adjudicate-upstream-suite --upstream SOURCE --before OLD_DIFFERENCES_JSON
  --after DIFFERENCES_JSON --results RESULTS_JSONL --output LEDGER_JSON`: записать разбор различий.

```sh
scout-dev replay --input captures.jsonl.gz --output replay-results.jsonl \
  --workers 6 --analyzer-workers 1 --case-timeout 5s
```

Replay анализирует захваченный код как данные и сохраняет порядок результатов.
Неполнота и ошибки выполнения учитываются отдельно. Используйте новые каталоги вывода.

## Source-bound provenance

Сохранённый receipt — `testdata/provenance/scout-current-review.json`.
Обычная проверка сверяет сохранённые артефакты без обращения к сегодняшним исходникам.
Правки кода не требуют нового receipt. Явная проверка `provenance verify --current-sources`
показывает, соответствует ли измерение текущим исходникам; поле результата
`current_sources_checked` отличает её от проверки сохранённых данных.

При намеренном обновлении измерений создавайте прогоны в `.work/`; после проверки
заменяйте `testdata/provenance/current/`.
Задайте `SCOUT_EVIDENCE_DIR` — каталог replay и releasecheck:

```sh
scout-dev provenance compare --root . \
  --before testdata/provenance/baseline/replay.jsonl.gz \
  --replay "$SCOUT_EVIDENCE_DIR/replay.jsonl.gz" \
  --output "$SCOUT_EVIDENCE_DIR/comparison.json"
scout-dev provenance generate --root . \
  --input testdata/acceptance/upstream-inputs.jsonl.gz \
  --replay "$SCOUT_EVIDENCE_DIR/replay.jsonl.gz" \
  --summary "$SCOUT_EVIDENCE_DIR/summary.json" \
  --releasecheck "$SCOUT_EVIDENCE_DIR/releasecheck.json" \
  --comparison "$SCOUT_EVIDENCE_DIR/comparison.json" \
  --output "$SCOUT_EVIDENCE_DIR/receipt.json"
scout-dev provenance verify --root . \
  --manifest "$SCOUT_EVIDENCE_DIR/receipt.json"
```

Artifacts должны находиться внутри корня проекта. Перед генерацией receipt
изменившиеся наблюдения требуют причины и ссылки на regression test.
Приёмка использует `testdata/acceptance/upstream-inputs.jsonl.gz`.
Для отдельных проверок без capture есть явный `--input-mode pinned`.

Поле `engine_version` обозначает проверенную сборку; до первого релиза достаточно
SHA коммита. Проверка требует, чтобы replay и selftests бинарника относились
к записанному идентификатору. Хеши текущих исходников сверяются только с флагом
`--current-sources`. Тег или автоматически
определённая версия самой программы проверки могут отличаться.
Флаг `provenance verify --expected-version BUILD_ID` позволяет дополнительно
потребовать конкретный идентификатор проверенной сборки.

## Внешние эксперименты

Эти команды запускают внешние инструменты отдельно от обычных Go-проверок:

- `compare-upstream --upstream-source SOURCE --skillspector CLI
  --scout SCOUT --output NEW_DIR`: сравнить закреплённый корпус через оба CLI.
- `run-upstream-suite --upstream SOURCE --python PYTHON --output NEW_DIR`: запустить
  закреплённый pytest под macOS `sandbox-exec`, с запретом публичной сети.

## Проверки памяти Tree-sitter

C harness требует Python 3, Clang и загруженных Go modules:

```sh
python3 internal/dev/maintenance/treeparse_sanitize.py --sanitizer address --output /tmp/treeparse-asan
python3 internal/dev/maintenance/treeparse_sanitize.py --sanitizer thread --output /tmp/treeparse-tsan
python3 internal/dev/maintenance/treeparse_sanitize.py --sanitizer none --output /tmp/treeparse-plain
MallocStackLogging=1 leaks --atExit -- /tmp/treeparse-plain 1000
```

Последняя команда предназначена для macOS. `--uaf-control` и `--leak-control`
намеренно добавляют ошибки для проверки детекторов. Владение Go-ресурсами
и параллельное закрытие проверяются отдельно через `go test -race ./internal/syntax/treeparse`.
