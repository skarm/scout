# Зависимости и лицензии

[English](third-party.md) · Русский

Собственные исходники Scout распространяются под [MIT](../../LICENSE).
Сведения об авторах адаптированных материалов находятся в [NOTICE](../../NOTICE), полные тексты сторонних лицензий —
в [licenses](../../licenses).

## Модули Go

[go.mod](../../go.mod) и [go.sum](../../go.sum) закрепляют версии:

- YARA-X Go: 1.22.0.
- `go-toml/v2`: 2.4.3; `go.yaml.in/yaml/v3`: 3.0.5.
- `go-tree-sitter`, грамматики Python и JavaScript: 0.25.0; TypeScript: 0.23.2.
- `mvdan.cc/sh/v3`: 3.14.1, BSD-3-Clause; синтаксический анализатор без интерпретатора.
- `x/mod`: 0.42.0; `x/sys`: 0.49.0.
- Косвенные зависимости: `go-pointer`: 0.0.1; protobuf: 1.36.12.

`make deps` скачивает и проверяет модули. Минимальная версия Go — 1.26.0.

## Нативные зависимости

Полная сборка использует Tree-sitter и YARA-X C API 1.22.0.
См. [подготовку сборки](../development/native-build.ru.md).
`internal/syntax/treeparse/tree_sitter_api.h` скопирован без изменений из
go-tree-sitter v0.25.0; лицензия — `licenses/go-tree-sitter-MIT.txt`.
Лицензии нативных и Go-зависимостей действуют и при распространении бинарников.

## Встроенные материалы

- Адаптации NVIDIA SkillSpector и Cisco skill-scanner: Apache-2.0.
- Паттерны, производные от signature-base: Detection Rule License 1.1.
- Данные нормализации Unicode и визуально похожих символов: Unicode License V3.
- Грамматики JS/TS: MIT.

Ссылки на источники — в [манифесте](port-manifest.ru.md).
Пакеты интеграций содержат свои LICENSE/NOTICE и диапазоны версий peer-зависимостей в package.json.
