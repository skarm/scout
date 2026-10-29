# Зависимости и лицензии

[English](third-party.md) · Русский

Собственные исходники Scout распространяются под [MIT](../../LICENSE).
Attribution адаптаций находится в [NOTICE](../../NOTICE), полные сторонние тексты —
в [licenses](../../licenses).

## Go modules

[go.mod](../../go.mod) и [go.sum](../../go.sum) закрепляют версии:

- YARA-X Go: 1.22.0.
- `go-toml/v2`: 2.4.3; `go.yaml.in/yaml/v3`: 3.0.5.
- `go-tree-sitter`, Python и JavaScript grammars: 0.25.0; TypeScript: 0.23.2.
- `mvdan.cc/sh/v3`: 3.14.1, BSD-3-Clause; syntax parser без interpreter.
- `x/mod`: 0.42.0; `x/sys`: 0.49.0.
- Indirect: `go-pointer`: 0.0.1; protobuf: 1.36.12.

`make deps` скачивает и проверяет modules. Минимальная версия Go — 1.26.0.

## Нативные зависимости

Полная сборка использует Tree-sitter и YARA-X C API 1.22.0.
См. [подготовку сборки](../development/native-build.ru.md).
`internal/syntax/treeparse/tree_sitter_api.h` скопирован без изменений из
go-tree-sitter v0.25.0; лицензия — `licenses/go-tree-sitter-MIT.txt`.
Лицензии нативных и Go-зависимостей действуют и при распространении бинарников.

## Встроенные материалы

- Адаптации NVIDIA SkillSpector и Cisco skill-scanner: Apache-2.0.
- Derived signature-base patterns: Detection Rule License 1.1.
- Unicode normalization/confusables data: Unicode License V3.
- JS/TS grammars: MIT.

Ссылки на источники — в [manifest](port-manifest.ru.md).
Host bundles содержат свои LICENSE/NOTICE и peer ranges в package.json.
