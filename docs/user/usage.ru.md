# Использование CLI

Оглавление

- [Первая проверка](#первая-проверка)
- [Конфигурация](#конфигурация)
- [Сохранение отчётов](#сохранение-отчётов)
- [Baseline](#baseline)
- [Сетевые сервисы и дополнительные rules](#сетевые-сервисы-и-дополнительные-rules)

[English](usage.md) · Русский

## Первая проверка

Используйте `scout` из `PATH` или замените его путём к вашему бинарнику. Примеры
работают из любого каталога; пути проверяемых папок считаются от текущего каталога.
Установка описана в [руководстве сборки](../development/native-build.ru.md#установка-и-пути-сборки).

```sh
scout doctor
scout scan -- ./my-skill
scout scan --format markdown --output /tmp/scout-report.md -- ./my-skill
scout compare -- ./previous ./candidate
```

Замените пути в примерах своими локальными папками навыков или плагинов. Проверка
по умолчанию не требует конфигурации и API-ключей и не делает сетевых запросов.
Scout анализирует пакет без выполнения его кода. Сохраняйте отчёты вне проверяемых
каталогов.

Смотрите `Findings` — обнаруженные проблемы, `Completeness` — завершённость
проверки и `Decision` — решение политики: `allow`, `review` или `block`.
`review` возможен и без находок, если ограничения анализа требуют ручной проверки.

Указывайте параметры перед позиционными входами. `--` завершает разбор параметров.
`scan` принимает до 32 входов; `batch` — другое имя той же команды. `--target-workers` задаёт параллелизм
входов, `--workers` — анализаторов, `--timeout` ограничивает всю операцию.

## Конфигурация

Scout читает конфигурацию только по явному `--config`. Пример `/ci/scout.json`:

```json
{
  "schema": "scout.config/v1",
  "profile": "standard",
  "concurrency": {"targets": 1, "workers": 4},
  "timeout": "2m",
  "policy": {"fail_at": "high", "scope": "conservative"}
}
```

```sh
scout config validate --config /ci/scout.json
scout scan --config /ci/scout.json --format json -- ./my-plugin
```

Явные параметры переопределяют конфигурацию. Неуказанные поля получают значения по умолчанию;
неизвестные и повторяющиеся ключи отвергаются. Храните конфигурацию, baseline,
дополнительные правила и кеши вне проверяемых входов. См. [профили](inspection-profiles.ru.md).

## Сохранение отчётов

```sh
scout scan --format json \
  --report json=/ci-results/scout.json \
  --report sarif=/ci-results/scout.sarif \
  --fail-on high --timeout 2m -- ./skills ./plugins
scout scan --format markdown --output /ci-results/scout.md -- ./my-plugin
```

Форматы: `text`, `json`, `sarif`, `markdown`. Без `--output` основной отчёт идёт
в stdout. Повторяемый `--report FORMAT=PATH` добавляет другие представления.
Диагностика идёт в stderr. Создайте каталоги отчётов перед запуском.

Scout готовит каждый отчёт в приватном временном файле, затем заменяет назначение
переименованием. Ошибка подготовки сохраняет прежний файл. Символические ссылки, каталоги и пути
внутри проверяемых входов отвергаются. Несколько файлов публикуются независимо.

Коды завершения:

- `0`: полный запуск, политика разрешает установку, все отчёты записаны.
- `1`: полный запуск, политика требует ручной проверки или блокирует установку.
- `2`: неполный, неуспешный или отменённый запуск; неверный запрос; ошибка записи.

В CI сохраняйте отчёты и исходный код завершения. Консервативная область проверки
также требует ручной проверки при заявленных ограничениях языка.
См. [выбор области](inspection-profiles.ru.md#область-проверки).

## Baseline

Создайте baseline из JSON-отчёта с одним входом, проверьте записи и одобрите их:

```sh
scout baseline create --from /ci-results/scout.json \
  --output /ci-results/pending-baseline.json \
  --reason 'Manual triage required' --expires '2099-01-01T00:00:00Z'
scout baseline approve --from /ci-results/pending-baseline.json \
  --output /ci-results/reviewed-baseline.json \
  --reason 'Reviewed by operator' --expires '2099-01-01T00:00:00Z'
scout scan --baseline /ci-results/reviewed-baseline.json -- ./my-plugin
```

Выберите подходящий будущий срок в RFC3339. `create` сохраняет неодобренные записи;
`approve` одобряет все записи выбранного файла. Изменение идентичности требует
новой проверки. Исключения по маске требуют `--allow-baseline-globs`.
Находки остаются в отчёте; пробелы проверки и семантические гипотезы не подавляются.

## Сетевые сервисы и дополнительные rules

Сетевой вход требует `--allow-download`. Корень GitHub-репозитория также требует
`--revision` с полным commit SHA. См. [внешние источники](../reference/external-sources.ru.md).

```sh
scout scan --vulnerability-check --allow-vulnerability-network \
  --format json -- ./my-plugin
scout scan --vulnerability-check --osv-cache /ci/osv-cache.json \
  --osv-cache-max-age 168h --format json -- ./my-plugin
```

OSV проверяет точные координаты захваченных зависимостей. Кеш для работы без сети задаёт
оператор; отсутствующие и устаревшие записи оставляют пробелы проверки.
Запись об уязвимости не доказывает её достижимость в проверяемом коде.

`--yara-rules` добавляет доверенные правила оператора. Директивы include и вывод в консоль запрещены;
невалидные правила завершают операцию ошибкой. LLM требует отдельного
[согласия на передачу исходников](semantic-review.ru.md).
