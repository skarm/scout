# Интеграции и MCP

[English](integrations.md) · Русский

## Reviewer-пакеты

```sh
scout integrations list
scout integrations export --bundle agent-skill --output /tmp/scout-reviewer.zip
scout integrations export --bundle opencode --output /tmp/scout-opencode.zip
```

Доступны `agent-skill`, `claude-code`, `codex`, `pi`, `opencode` и `review-materials`.
Экспорт создаёт новый ZIP с инструкциями EN/RU, лицензиями и манифестом файлов.
Установка выполняется отдельно. См. [настройку пакета](../../internal/distribution/integrations/assets/README.ru.md).

## Pi и OpenCode

Оператор задаёт абсолютный `SCOUT_BIN` и именованные входы в `SCOUT_TARGETS`.
Модель выбирает только имя входа и необязательный параметр `semantic`.
Pi запрашивает интерактивное подтверждение, OpenCode использует `context.ask`.

По умолчанию выбран standard. Семантическая проверка требует настроенного
`SCOUT_REVIEWER` и отдельного разрешения на передачу исходников.
`SCOUT_REDUCED_CORE=1` явно выбирает custom без нативных движков.
Инструмент сохраняет partial/block и возвращает ограниченную сводку.
Для полного отчёта используйте отдельный CLI-вызов.

## MCP server

```sh
scout mcp --profile standard --transport stdio \
  --target candidate=/absolute/review/candidate
scout mcp --profile standard --transport http --listen 127.0.0.1:8837 \
  --auth-token-env SCOUT_MCP_TOKEN --target candidate=/absolute/review/candidate
```

`scan_skill` принимает разрешённый ключ входа либо filename/base64 до 128 КиБ.
`compare_skills` использует два разрешённых ключа. Аргументы инструмента не выбирают
произвольные пути и не меняют профиль, провайдера или исключения.
Без именованных входов stdio работает только с загрузками.

HTTP требует привязки к числовому loopback-адресу и явного bearer-токена от 32 байтов.
Браузерные источники запросов запрещены, пока оператор не разрешит их через `--origin`.
Сервер поддерживает JSON-ответы, без SSE и потокового GET.

`mcp.New` заимствует Scanner и доверенный `policy.Gate`.
См. [владение ресурсами API](../development/go-api.ru.md#координаты-лимиты-и-доверие).

## Проверка

`make host-test` проверяет разрешения, отмену и коды завершения на тестовых реализациях SDK
и настоящем CLI. Совместимость с реальными приложениями проверяется отдельно.
