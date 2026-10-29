# Источники и адаптированные материалы

[English](port-manifest.md) · Русский

Scout адаптирует выбранные материалы для своих анализаторов и процесса review.
Совпадение имён правил не доказывает эквивалентность поведения upstream.

## NVIDIA SkillSpector

Адаптированы выбранные patterns, идеи детекторов, 27 YARA rules, review prompts,
пояснения и процесс Skill Inspector. Attribution сохранена в [NOTICE](../../NOTICE)
и [лицензии Apache-2.0](../../licenses/SkillSpector-Apache-2.0.txt).

Подробное происхождение указано в `knowledge/sources/skillspector.md`, ссылках
пояснений и `internal/distribution/integrations/sources/transfer-manifest.json`.
Исторические адаптации включают cached/main views и не все привязаны к одному
upstream commit. Закреплённый inventory сравнений находится в
`testdata/provenance/upstream-inventory.json`.

## Cisco

Восемь YARA rules адаптированы из
[Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner/tree/f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1).
Набор — `internal/signatures/rules/cisco_adapted.yar`, хеши источников — в
[receipt](../../testdata/provenance/cisco-hardening-2026-10-29.json).
Copyright и Apache-2.0 notices сохранены в [NOTICE](../../NOTICE)
и [лицензии Cisco](../../licenses/Cisco-Apache-2.0.txt).

## Справочные материалы

[Snyk agent-scan](https://github.com/snyk/agent-scan/tree/a69e1c354ad0812c13da15dc64770e1c21786841)
использован для сравнения коллизий инструментов и сочетаний возможностей.
Его client и backend не включены. Закреплённые источники авторских критериев
хранятся в `knowledge/data/review_sources.json`; см. [темы базы знаний](curated-knowledge.ru.md).

## Проверка и распространение

Сохранённые сравнения привязаны к конкретным исходникам и хешам. Команды находятся
в [руководстве разработчика](../development/commands.ru.md). Они не доказывают
полную эквивалентность детекции или независимую точность. При распространении
адаптаций сохраняйте применимые LICENSE/NOTICE. См. [лицензии зависимостей](third-party.ru.md).
