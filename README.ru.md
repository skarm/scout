# Scout

[English](README.md)

Scout проверяет навыки и плагины ИИ-агентов перед установкой или обновлением. Он анализирует инструкции, конфигурацию, код и поддерживаемые вложения без запуска пакета.

## Установка

Скачайте архив для своей платформы и файл `SHA256SUMS` из [релизов GitHub](https://github.com/skarm/scout/releases). Суффикс `macos-arm64` обозначает Apple Silicon, `linux-amd64` — Linux x86-64, `windows-amd64` — Windows x64. Доступные архивы перечислены в каждом релизе.

На macOS и Linux замените имя архива в примере на имя скачанного файла. Выполните команды в каталоге загрузки. Архив распакуется после успешной проверки суммы.

```sh
archive=scout-vX.Y.Z-macos-arm64.tar.gz
checksum=$(awk -v file="$archive" '$2 == file { print; matches++ } END { if (matches != 1) exit 1 }' SHA256SUMS) &&
  printf '%s\n' "$checksum" | shasum -a 256 -c - &&
  tar -xzf "$archive" && ./scout doctor
```

На Linux вместо `shasum -a 256 -c -` можно использовать `sha256sum -c -`.

На Windows выполните `Get-FileHash -Algorithm SHA256 .\scout-vX.Y.Z-windows-amd64.zip` в PowerShell и сверьте `Hash` со строкой именно этого архива в `SHA256SUMS`. Распакуйте проверенный архив и запустите `.\scout.exe doctor`. Для примеров ниже добавьте каталог с бинарником в `PATH`.

Для сборки из исходников на поддерживаемых macOS и Linux нужны Go 1.26+, компилятор C, `make` и `pkg-config`. Make подготовит нативные зависимости. [Руководство по сборке](docs/development/native-build.ru.md)

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

## Отслеживание изменений окружения агента

Из каталога проекта сохраните снимок навыков Codex из `.agents/skills`.

```sh
scout discover --agent codex --project . --kind skill --include-path "$PWD/.agents/skills" \
  --snapshot /path/to/private/before.json -- --format markdown
```

После обновления навыков сравните текущее окружение с этим снимком.

```sh
scout snapshot compare --snapshot /path/to/private/before.json --format markdown
```

Укажите новый файл в приватном каталоге вне проекта и каталогов агента. Снимки содержат исходные байты проверенных файлов. Настройка для Claude Code и выбор других компонентов описаны в руководстве. [Снимки окружения](docs/user/environment-snapshots.ru.md)

Код выхода `1` означает, что завершённая проверка требует ручного разбора или блокирует выбранное содержимое. Снимок при этом может быть сохранён вместе с решением.

## Интеграция Scout

- [Команды и флаги CLI](docs/reference/cli.ru.md) и [примеры конфигураций](examples/configs/README.ru.md)
- [Go API](docs/development/go-api.ru.md) и [пример использования](examples/go-api/README.ru.md)
- [MCP и интеграции с агентами](docs/user/integrations.ru.md)
- [Документация](docs/README.ru.md), [правила участия](CONTRIBUTING.md) и [политика безопасности](SECURITY.md)
