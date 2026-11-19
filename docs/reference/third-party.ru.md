# Зависимости и лицензии

[English](third-party.md) · Русский

Собственные исходники Scout распространяются под [MIT](../../LICENSE).
Сведения об авторах адаптированных материалов находятся в [NOTICE](../../NOTICE), полные тексты сторонних лицензий —
в [licenses](../../licenses).

## Модули Go

Версии модулей и контрольные суммы указаны в [go.mod](../../go.mod) и [go.sum](../../go.sum). Команда `make deps` загружает и проверяет модули. Для сборки нужен Go 1.26+. `mvdan.cc/sh/v3` распространяется под BSD-3-Clause, Goldmark под MIT.

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
