# Источники и адаптированные материалы

[English](port-manifest.md) · Русский

Scout адаптирует выбранные материалы для своих анализаторов и процесса проверки.
Совпадение имён правил не доказывает эквивалентность поведения исходному проекту.

## NVIDIA SkillSpector

Адаптированы выбранные паттерны, идеи детекторов, 27 YARA-правил, инструкции проверки,
пояснения и процесс Skill Inspector. Сведения об авторах сохранены в [NOTICE](../../NOTICE)
и [лицензии Apache-2.0](../../licenses/SkillSpector-Apache-2.0.txt).

Подробное происхождение указано в `knowledge/sources/skillspector.md`, ссылках
пояснений и `internal/distribution/integrations/sources/transfer-manifest.json`.
Исторические адаптации включают представления из кеша и ветки main. Не все адаптации
привязаны к одному коммиту исходного проекта. Закреплённый инвентарь сравнений находится в
`testdata/provenance/upstream-inventory.json`.

## Cisco

Восемь YARA-правил адаптированы из
[Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner/tree/f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1).
Набор — `internal/signatures/rules/cisco_adapted.yar`, хеши источников — в
[записи измерения](../../testdata/provenance/cisco-hardening-2026-10-29.json).
Уведомления об авторских правах и Apache-2.0 сохранены в [NOTICE](../../NOTICE)
и [лицензии Cisco](../../licenses/Cisco-Apache-2.0.txt).

## Справочные материалы

[Snyk agent-scan](https://github.com/snyk/agent-scan/tree/a69e1c354ad0812c13da15dc64770e1c21786841)
использован для сравнения коллизий инструментов и сочетаний возможностей.
Его клиент и серверная часть не включены. Закреплённые источники авторских критериев
хранятся в `knowledge/data/review_sources.json`; см. [темы базы знаний](curated-knowledge.ru.md).

## Проверка и распространение

Сохранённые сравнения привязаны к конкретным исходникам и хешам. Команды находятся
в [руководстве разработчика](../development/commands.ru.md). Они не доказывают
полную эквивалентность детекции или независимую точность. При распространении
адаптаций сохраняйте применимые LICENSE/NOTICE. См. [лицензии зависимостей](third-party.ru.md).
