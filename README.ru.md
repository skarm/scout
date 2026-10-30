# Scout

[English](README.md) · Русский

Scout проверяет навыки и плагины AI-агентов перед установкой или обновлением.
Анализирует инструкции, конфигурацию, код и поддерживаемые вложения без выполнения
проверяемого пакета. Доступен через CLI, Go API и MCP.

## Установка из исходников

Нужны Go 1.26+, компилятор C, `make` и `pkg-config`.

```sh
make deps install
export PATH="$HOME/.local/bin:$PATH"
scout doctor
```

На поддерживаемых macOS и Linux Make автоматически подготавливает нативные
зависимости. По умолчанию бинарник устанавливается в `~/.local/bin`; один раз добавьте
этот каталог в `PATH` вашей оболочки. После этого Scout запускается из любой папки.
Другой путь установки, сборка в CI и подготовка к работе без сети описаны в
[инструкции сборки](docs/development/native-build.ru.md).

## Сканирование и сравнение

```sh
scout scan --format markdown ./my-skill
scout scan --format json --fail-on high ./skills ./plugins
scout compare --format markdown ./previous ./candidate
scout scan --input - --name SKILL.md --format json < ./SKILL.md
```

Профиль `standard` по умолчанию выполняет статические проверки без сети.
`review` добавляет проверку настроенной LLM и требует согласия на передачу исходников.
`custom` позволяет выбрать проверки. Для загрузок и сетевого поиска уязвимостей
нужны отдельные разрешения.

Отчёт сохраняет находки, пробелы проверки и решение политики. Неполная проверка
требует внимания даже без находок. Конфигурация, запись отчётов, baseline
и коды завершения описаны в [руководстве CLI](docs/user/usage.ru.md).
Все флаги и значения по умолчанию перечислены в [справочнике CLI](docs/reference/cli.ru.md);
`scout -h` печатает полный список в терминале.
Для обычной проверки, CI, нескольких входов, core-сборки, OSV и LLM-review
есть [готовые конфигурации](examples/configs/README.ru.md).

## Проверки и расширения

В полную сборку входят проверки инструкций агента и prompt injection, разрешений
и hooks, конфигураций MCP, скрытого содержимого, зависимостей и выбранных потоков
данных в Go, Shell, JS/TS, Python и SQL. Профиль `standard` также включает
адаптированные правила SkillSpector и встроенные YARA-X-сигнатуры malware,
webshells, cryptominers, hacktools и угроз в навыках агентов.

Без пересборки можно добавить свои или сторонние YARA-правила через `--yara-rules`,
включить OSV через `--vuln` или подключить LLM в профиле `review`.
Сеть и передача исходников требуют отдельных разрешений.

```sh
scout rules list --all
scout capabilities
scout scan --yara-rules /etc/scout/organization.yar --fail-on medium ./my-plugin
```

Категории, ограничения и примеры подключения описаны в
[руководстве проверок и профилей](docs/user/inspection-profiles.ru.md).

## Go API и интеграции

Создайте Scanner через `scout.New(ctx, scout.DefaultOptions())` и освободите его
через `Close`. Вызовите `Scan`, `ScanMany` или `Compare`, оцените результат через доверенный
`policy.Gate` и подготовьте вывод через `report.Prepare`.
[Контракты API](docs/development/go-api.ru.md) · [Пример использования Go API](examples/go-api/README.ru.md).

[Руководство интеграций](docs/user/integrations.ru.md) описывает MCP и reviewer-пакеты
для Claude Code, Codex, Pi и OpenCode.

## Разработка

```sh
make test-core
make test
```

Полный набор тестов требует нативных зависимостей. `make build` по умолчанию пишет
бинарники в `bin/`; другой каталог задаётся через `BIN_DIR`. `make clean` удаляет
бинарники сборки и временные рабочие данные; установленные копии сохраняются.
Другие проверки описаны в [руководстве валидации](docs/development/validation.ru.md).

[Участие в разработке](CONTRIBUTING.md) · [Политика безопасности](SECURITY.md)

[Документация](docs/README.ru.md) · [Примеры](examples/README.ru.md) · [Архитектура](docs/development/architecture.ru.md) ·
[Языки](docs/reference/languages.ru.md) · [Лицензии и источники](docs/reference/port-manifest.ru.md)
