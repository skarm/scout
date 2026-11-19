# Scout

[English](README.md)

Scout проверяет навыки и плагины ИИ-агентов перед установкой или обновлением. Он анализирует инструкции, конфигурацию, код и поддерживаемые вложения без запуска пакета.

## Установка

Для сборки на поддерживаемых macOS и Linux нужны Go 1.26+, компилятор C, `make` и `pkg-config`. Make подготовит нативные зависимости. Добавьте `~/.local/bin` в `PATH` оболочки, чтобы запускать Scout из любого каталога. [Руководство по сборке](docs/development/native-build.ru.md)

```sh
make deps install
export PATH="$HOME/.local/bin:$PATH"
scout doctor
```

## Сканирование и сравнение

```sh
scout scan --format markdown ./my-skill
scout scan --format json --fail-on high ./skills ./plugins
scout compare --format markdown ./previous ./candidate
```

Смотрите на находки, полноту проверки и решение политики вместе. Ручная проверка может потребоваться даже при нуле находок. Профиль `standard` работает без сети. В `custom` можно выбрать проверки, а `review` подключает LLM с явным согласием на отправку исходных данных. Для загрузок и поиска уязвимостей по сети нужны отдельные разрешения. [Руководство CLI](docs/user/usage.ru.md) · [Проверки и профили](docs/user/inspection-profiles.ru.md)

## Интеграция Scout

- [Команды и флаги CLI](docs/reference/cli.ru.md) и [примеры конфигураций](examples/configs/README.ru.md)
- [Go API](docs/development/go-api.ru.md) и [пример использования](examples/go-api/README.ru.md)
- [MCP и интеграции с агентами](docs/user/integrations.ru.md)
- [Документация](docs/README.ru.md), [правила участия](CONTRIBUTING.md) и [политика безопасности](SECURITY.md)
