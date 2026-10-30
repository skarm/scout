# Готовые конфигурации

[English](README.md) · Русский

Выберите файл через `--config`. Это обычные файлы `scout.config/v1`;
имена профилей проверки остаются `standard`, `review` и `custom`.
Примеры выполняются из корня репозитория со `scout` в `PATH`.

- [standard.json](standard.json): обычная статическая проверка без сети;
  стандартные покрытие и лимиты, порог блокировки `high`.
- [ci.json](ci.json): более строгая политика без сети; блокировка от `medium`,
  ручная проверка находок меньшей серьёзности.
- [batch.json](batch.json): проверка нескольких входов без сети, четыре
  одновременно проверяемые цели и увеличенные общие бюджеты.
- [core.json](core.json): встроенные проверки и адаптированные шаблоны для
  core-сборки или явно сокращённого набора.
- [vuln.json](vuln.json): стандартные статические проверки и сетевые OSV-запросы
  с явным разрешением при запуске.
- [review.template.json](review.template.json): шаблон стандартных статических
  проверок с Chat Completions reviewer оператора. Заполните адрес и модель.

## Выбор и валидация конфигурации

```sh
scout config validate --config examples/configs/standard.json
scout scan --config examples/configs/standard.json --format markdown ./my-skill
scout compare --config examples/configs/standard.json --format markdown ./previous ./candidate
```

Храните конфиг вне всех проверяемых входов. Для сканирования самого этого
репозитория сначала скопируйте конфиг в каталог оператора вне репозитория:

```sh
mkdir -p "$HOME/.config/scout"
cp examples/configs/standard.json "$HOME/.config/scout/standard.json"
scout scan --config "$HOME/.config/scout/standard.json" --format markdown .
```

При запуске из другого каталога задавайте абсолютный путь к конфигу. Явные флаги
переопределяют выбранный файл, например `--timeout 4m` или `--harness claude-code`.
Допускается только один `--config`; для объединения настроек скопируйте и измените
пресет. Относительные пути baseline, правил и кеша внутри конфига считаются
от текущего рабочего каталога.

Все конфиги используют консервативную политику покрытия. Заявленные ограничения
анализа языка могут требовать review даже без находок. Если ваша политика допускает
выбранную область анализа, явно добавьте `--scope selected`; ошибки выполнения
и пробелы проверки по-прежнему исключают полный allow.

## Строгая политика CI

```sh
scout scan --config examples/configs/ci.json --format json \
  --report sarif=/tmp/scout.sarif ./my-skill
```

Находки `medium`, `high` и `critical` блокируют установку. Находки `low` и `info`
требуют ручной проверки. Один порог блокировки не определяет код завершения:

- `0`: полный запуск и allow по политике.
- `1`: полный запуск, но требуется review или block.
- `2`: неполнота, отмена, неверный запрос или ошибка записи отчёта.

Пресет не добавляет одобрения baseline. В CI сохраняйте исходный код завершения
и отчёты. См. [вывод отчётов](../../docs/user/usage.ru.md#сохранение-отчётов).

## Несколько входов

```sh
scout scan --config examples/configs/batch.json --format markdown ./skills ./plugins
```

Пресет задаёт четыре worker для входов, четыре общих worker анализаторов
и срок всей операции пять минут. Общие бюджеты: 128 МиБ захвата, 64 МиБ извлечения,
16384 файла, 32768 элементов инвентаризации, 67108864 операции анализа
и 4096 сохраняемых находок. Лимиты захвата и извлечения на один вход остаются
стандартными. Общие бюджеты делятся между фактическим числом входов;
четыре worker не означают отдельный полный бюджет для каждого входа.

## Core-сборка

```sh
make build-core
./bin/scout-core scan --config examples/configs/core.json --format markdown ./my-skill
```

Профиль `custom` включает встроенные проверки и `patterns`. Python AST,
парсеры YAML/TOML и YARA явно отключены. Тот же файл работает с полным бинарником
как `scout scan --config examples/configs/core.json ...`. Покрытие этого набора уже,
чем у `standard`; неподдержанный анализ остаётся виден в отчёте.
См. [варианты сборки](../../docs/development/native-build.ru.md).

## Запросы уязвимостей

```sh
scout config validate --config examples/configs/vuln.json --allow-vulnerability-network
scout scan --config examples/configs/vuln.json --allow-vulnerability-network \
  --format markdown ./my-skill
```

Конфиг включает OSV-запросы по точным координатам с потолком 32 запроса на вход,
также ограниченным общим бюджетом сервисов. Разрешение требуется при каждом
запуске, включая валидацию. У загрузок и передачи исходников отдельные разрешения.
Для офлайн-проверки предоставьте свой кеш точных запросов по
[инструкции работы с кешем](../../docs/user/usage.ru.md#сетевые-сервисы-и-дополнительные-rules).

## Шаблон LLM-проверки

```sh
mkdir -p "$HOME/.config/scout"
cp examples/configs/review.template.json "$HOME/.config/scout/review.json"
```

Измените `review.endpoint` и `review.model` для выбранного Chat Completions сервиса.
Адрес `.invalid` и модель `REPLACE_ME` — заполнители. Задайте API-ключ в переменной
`SCOUT_REVIEW_API_KEY` через оболочку или менеджер секретов; `key_env` хранит
только имя переменной.

```sh
scout config validate --config "$HOME/.config/scout/review.json" --allow-source-upload
scout scan --config "$HOME/.config/scout/review.json" --allow-source-upload \
  --format markdown ./my-skill
```

Пресет допускает до 32 запросов reviewer и 2 МиБ сериализованных пользовательских
запросов, срок одного запроса — 30 секунд, всей операции — пять минут.
Дополнительная проверка качества включается через `--quality-review`.
Согласие на передачу исходников требуется при каждом запуске: фрагменты могут
содержать секреты. Валидация проверяет настройки и локальные движки;
доступность провайдера проверяется при сканировании.
Другие транспорты описаны в [настройке reviewer](../../docs/user/semantic-review.ru.md).

Формат отчёта, назначения и входы задаются аргументами командной строки.
Разрешения загрузок, сети и передачи исходников всегда задаются явными флагами.
Все параметры и defaults — в [полном справочнике CLI](../../docs/reference/cli.ru.md).
