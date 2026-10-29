# Темы базы знаний

[English](curated-knowledge.md) · Русский

Встроенный набор содержит критерии review, пояснения правил, рекомендации
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
patterns. Темы охватывают Go, JS/TS, Python, Shell, SQL, prompt injection,
сочетания инструментов, разрешения, persistence, секреты и происхождение зависимостей.

## Использование при review

Discovery, assessment и proposal assessment получают критерии проверки.
Intent/tool consistency используют темы назначения и полномочий;
quality имеет отдельные критерии. Полные сценарии и снимки исходников
не включаются в системные инструкции.

Discovery может выбрать встроенную причину `knowledge:<topic ID>`.
Повторная проверка получает исходные доказательства и выбранный guide.
Отчёт сохраняет тему и пояснения Scout; результат остаётся семантической гипотезой.

## Проверка источников

`knowledge/data/review_sources.json` хранит закреплённые ревизии и хеши просмотренных
файлов. Источники помогают составлять критерии, но их detector engines не включены.
Для адаптированных материалов есть отдельный [manifest](port-manifest.ru.md).

```sh
go run -tags=coreonly ./cmd/scout-dev verify-knowledge-sources --cache /absolute/source-cache
go run -tags=coreonly ./cmd/scout-dev verify-knowledge-sources --cache /absolute/source-cache --download
```

`--download` разрешает загрузку недостающих закреплённых файлов.
Доставка инструкций проверяется в [runtime-тестах](knowledge-runtime.ru.md).
