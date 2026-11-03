# Темы базы знаний

[English](curated-knowledge.md) · Русский

Встроенный набор содержит критерии проверки, пояснения правил, рекомендации
и ссылки на источники. Темы дополняют LLM-проверку и пояснения существующих
правил, без добавления статических детекторов.

## Просмотр

```sh
scout knowledge
scout knowledge --mode discovery
scout knowledge --mode assessment
scout integrations export --bundle review-materials --output /tmp/scout-review-materials.zip
```

CLI и экспорт показывают встроенные темы, источники, пояснения и дополнительные
паттерны. Темы охватывают Go, JS/TS, Python, Shell, SQL, внедрение инструкций,
сочетания инструментов, разрешения, закрепление (persistence), секреты и происхождение зависимостей.

## Использование при `review`

Режимы `discovery`, `assessment` и `proposal_assessment` получают критерии проверки.
`intent` и `tool_consistency` используют темы назначения и полномочий;
для `quality` заданы отдельные критерии. Полные сценарии и снимки исходников
не включаются в системные инструкции.

В режиме `discovery` модель может выбрать встроенную причину `knowledge:<topic ID>`.
Повторная проверка получает исходные доказательства и выбранные пояснения.
Отчёт сохраняет тему и пояснения Scout; результат остаётся семантической гипотезой.

## Проверка источников

`knowledge/data/review_sources.json` хранит закреплённые ревизии и хеши просмотренных
файлов. Источники помогают составлять критерии, но их движки детекции не включены.
Для адаптированных материалов есть отдельный [манифест](port-manifest.ru.md).

```sh
go run -tags=coreonly ./cmd/scout-dev verify-knowledge-sources --cache /absolute/source-cache
go run -tags=coreonly ./cmd/scout-dev verify-knowledge-sources --cache /absolute/source-cache --download
```

`--download` разрешает загрузку недостающих закреплённых файлов.
Доставка инструкций проверяется в [тестах использования знаний](knowledge-runtime.ru.md).
