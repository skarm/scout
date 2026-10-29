# Структура репозитория

[English](layout.md) · Русский

Scout использует один Go-модуль. Публичные пакеты: `scout`, `report`, `policy`,
`baseline`, `review`, `fetch`, `osv`, `knowledge`, `mcp`.

```text
scout/
├── *.go                         # Scanner API; scan_test.go checks private helpers
│   └── doc.go                   # package documentation
├── cmd/{scout,scout-dev}/        # entrypoints
├── report/                      # independent public contract
├── policy/                      # policy evaluation of a sealed Run
├── baseline/                    # trusted approvals
├── review/                      # public provider protocols
├── fetch/                       # public download configuration
├── osv/                         # OSV and offline cache
├── knowledge/{data,prompts,sources}/
├── mcp/                         # public server API
├── internal/
│   ├── buildinfo/               # module versions embedded in the running binary
│   ├── capture/                 # ingest, artifact, rootfs, archives, extraction, external
│   ├── syntax/                  # parsers, frontend, language/filetype, source maps
│   ├── analysis/
│   │   ├── languages/{golang,python,shell,javascript,sql,literals}/
│   │   ├── analyzer/            # common catalog and cross-language checks
│   │   ├── check/               # Analyzer, Match, Facts and binding contract
│   │   ├── sourcepolicy/        # offline default package-source predicates
│   │   ├── document/            # prepared source views
│   │   ├── engine/              # orchestration and budgets
│   │   └── other analysis packages
│   ├── signatures/{rules,testdata}/
│   ├── distribution/{integrations,skills,registry,attestation}/
│   ├── commands/{cli,devcli,output}/
│   ├── dev/{maintenance,evaluation,replay,replaywire,provenance,releasecheck}/
│   ├── nativecheck/
│   ├── nativecontract/
│   ├── netpolicy/
│   ├── textmatch/
│   ├── architecture/
│   └── scantest/scenarios/
├── tests/{api,scan,languages,regression,acceptance,performance}/
├── testdata/                    # inputs, acceptance captures and provenance receipts
├── docs/{user,development,reference}/
├── licenses/
├── .github/workflows/
├── bin/                         # ignored: default build output; configurable with BIN_DIR
└── .work/                       # ignored: temporary artifacts, coverage and metrics
```

## Владение кодом

Языковая семантика принадлежит `internal/analysis/languages/<language>`, разбор
и координаты — `internal/syntax`. Языковые пакеты экспортируют
`Rules() []check.Analyzer`, не импортируют друг друга и общий реестр.
Общие проверки находятся в `analyzer`, facts — в `check`, лимиты — в `analysisbudget`.
Потребители используют контракты непосредственно из `check`. Отображаемые категории
по именам файлов находятся в `syntax/filetype`; они не дают доверия и не подавляют проверки.

Unit tests и fixtures хранятся рядом с пакетом. Проверки `foo.go` помещайте
в `foo_test.go`; отдельный файл оправдан build constraints или крупным компонентом.
Сквозные Scanner tests находятся в `tests/`, общая поддержка — в `internal/scantest`.
CLI tests принадлежат адаптеру команды, host adapter tests — integration assets.

Перемещайте встроенные assets вместе с их пакетом. При переносе и переименовании
сохраняйте ссылки лицензий и provenance. Записанные доказательства не переписываются.

## Документация и рабочие данные

Английские руководства используют `.md`, русские — `.ru.md`.
Комментарии GoDoc пишутся на английском. См. [соглашения](documentation.ru.md).

`bin/` — каталог бинарников по умолчанию; другой путь задаётся через `BIN_DIR`.
`make install` копирует Scout в `PREFIX/bin` (по умолчанию `~/.local/bin`). `.work/`
хранит временные отчёты, coverage и metrics. `make clean` удаляет бинарники сборки
и `.work/`, сохраняя установленные копии. Captures приёмки находятся в
`testdata/acceptance/`, replay и receipts — в `testdata/provenance/`.
Нативные зависимости используют пользовательский кеш.
