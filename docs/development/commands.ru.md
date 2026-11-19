# Команды разработчика

Оглавление

- [Измерения и приёмка сборки](#измерения-и-приёмка-сборки)
- [Сохранённые исходники и replay](#сохранённые-исходники-и-replay)
- [Source-bound provenance](#source-bound-provenance)
- [Проверки памяти Tree-sitter](#проверки-памяти-tree-sitter)

[English](commands.md) · Русский

Соберите CLI разработчика вместе со Scout:

```sh
make build build-dev
export PATH="$PWD/bin:$PATH"
scout-dev evaluate testdata/security-corpus/cases.json
scout-dev releasecheck --binary "$(command -v scout)"
```

Другой каталог сборки задаётся через `BIN_DIR`; тогда добавьте в `PATH` его.

Для команд сохранённых данных без нативных проверок используйте
`go run -tags=coreonly ./cmd/scout-dev <command> [flags]`.
При запуске из другого каталога команды обслуживания принимают `--root PROJECT_ROOT`.

## Измерения и приёмка сборки

- `evaluate [--profile standard|custom] [--timeout 2m] CORPUS_JSON`: проверить
  размеченный корпус отдельных файлов (схема 1) или пакетов (схема 2).
  Здесь `custom` выбирает только встроенные проверки. `--split train|tune|holdout`
  фильтрует после проверки всего корпуса. `--llm-config FILE --allow-source-upload`
  добавляет отдельный LLM-прогон; `--input-usd-per-million N --output-usd-per-million N`
  задают тарифы для оценки стоимости.
- `releasecheck --binary SCOUT`: проверить компоновку и метаданные, затем запустить
  нативные самопроверки. `--inspect-only` ограничивает работу чтением бинарника.
  Выбранный бинарник должен быть ограниченным по размеру обычным файлом; явная
  ссылка на него поддерживается, FIFO и устройства отвергаются до чтения.

См. [измерения](evaluation.ru.md) и [проверки](validation.ru.md).

## Сохранённые исходники и replay

- `verify-knowledge-sources --cache DIR`: сверить закреплённые байты исходников.
  `--download` разрешает загрузку недостающих файлов.
- `check-knowledge-runtime --binary SCOUT --output NEW_DIR`: проверить статические
  сканирования и провайдер проверки с заданными ответами на локальном сервере.

```sh
scout-dev replay --input captures.jsonl.gz --output replay-results.jsonl \
  --workers 6 --analyzer-workers 1 --case-timeout 5s
```

Replay анализирует захваченный код как данные и сохраняет порядок результатов.
Неполнота и ошибки выполнения учитываются отдельно. Входом должен быть обычный
файл JSONL или gzip; FIFO и устройства отклоняются до чтения. Используйте новые
каталоги вывода.

Replay применяет полную длительность `--case-timeout`. Поле `budget_seconds`
в сохранённой записи содержит целое число секунд с округлением вниз. Задавайте
таймаут в целых секундах, если по записи нужно точно воспроизвести бюджет.

Тип, размер и признак исполняемого файла после записи должны совпадать с захватом.
Если файловая система не сохраняет их (включая executable-биты в Windows), запись
получает `replay_capture_error` и не сканируется с изменёнными метаданными.

## Source-bound provenance

`make acceptance` проверяет сохранённые артефакты измерения. Чтобы сверить запись с текущими исходниками, запустите `provenance verify --current-sources`. Поле `current_sources_checked` отмечает такую сверку. См. [проверки](validation.ru.md#бинарник-и-сохранённые-измерения).

Для измерений нужны обычные файлы ограниченного размера внутри репозитория. Символические ссылки должны разрешаться в его пределах.

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

Артефакты должны находиться внутри корня проекта. Перед созданием записи
изменившиеся наблюдения требуют причины и ссылки на регрессионный тест.
Приёмка использует `testdata/acceptance/upstream-inputs.jsonl.gz`.
Для отдельных проверок без захваченных входов есть явный `--input-mode pinned`.

`engine_version` обозначает измеренную сборку. Replay и самопроверки бинарника должны совпадать с этим значением. Чтобы потребовать конкретный идентификатор, укажите `--expected-version BUILD_ID`.

## Проверки памяти Tree-sitter

Тестовая программа на C требует Go, Clang и загруженных модулей Go:

```sh
go run ./internal/dev/treeparsecheck --sanitizer address --output /tmp/treeparse-asan
go run ./internal/dev/treeparsecheck --sanitizer thread --output /tmp/treeparse-tsan
go run ./internal/dev/treeparsecheck --sanitizer none --output /tmp/treeparse-plain
MallocStackLogging=1 leaks --atExit -- /tmp/treeparse-plain 1000
```

Последняя команда предназначена для macOS. `--uaf-control` и `--leak-control`
намеренно добавляют ошибки для проверки детекторов. Владение Go-ресурсами
и параллельное закрытие проверяются отдельно через `go test -race ./internal/syntax/treeparse`.
