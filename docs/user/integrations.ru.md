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

По умолчанию выбран `standard`. Семантическая проверка требует настроенного
`SCOUT_REVIEWER` и отдельного разрешения на передачу исходников.
`SCOUT_REDUCED_CORE=1` явно выбирает `custom` без нативных движков.
Инструмент сохраняет неполные результаты и решения о блокировке, возвращая ограниченную сводку.
Для полного отчёта используйте отдельный CLI-вызов.

## MCP server

```sh
scout mcp --profile standard --transport stdio \
  --target candidate=/absolute/review/candidate
scout mcp --profile standard --transport http --listen 127.0.0.1:8837 \
  --token-env SCOUT_MCP_TOKEN --target candidate=/absolute/review/candidate
```

`scan_skill` принимает разрешённый ключ входа либо загрузку с именем файла
и содержимым в base64. Размер содержимого после декодирования ограничен 128 КиБ.
`compare_skills` использует два разрешённых ключа. Аргументы инструмента не выбирают
произвольные пути и не меняют профиль, провайдера или исключения.
Без именованных входов stdio работает только с загрузками.

### MCP stdio в клиентах

Укажите абсолютные пути к доверенному бинарнику Scout и локальному входу,
который разрешаете проверить из агента. Замените оба пути в примере и добавьте
запись `scout` в конфигурацию клиента. Клиент запустит Scout как локальный процесс.

**Codex.** Добавьте запись в `~/.codex/config.toml`. [Настройка MCP в Codex](https://developers.openai.com/codex/mcp)

```toml
[mcp_servers.scout]
command = "/absolute/path/to/scout"
args = ["mcp", "--profile", "standard", "--transport", "stdio", "--target", "candidate=/absolute/review/candidate"]
```

**Claude Code и Cursor.** Для Claude Code используйте `.mcp.json` в корне проекта,
для Cursor — `.cursor/mcp.json`. Подтвердите подключение сервера `scout`, если
клиент запросит разрешение. [MCP в Claude Code](https://code.claude.com/docs/en/mcp) · [MCP в Cursor](https://cursor.com/docs/mcp)

```json
{
  "mcpServers": {
    "scout": {
      "command": "/absolute/path/to/scout",
      "args": ["mcp", "--profile", "standard", "--transport", "stdio", "--target", "candidate=/absolute/review/candidate"]
    }
  }
}
```

**GitHub Copilot CLI.** Используйте `.github/mcp.json` в доверенном Git-репозитории.
Запись делает доступным `scan_skill`. Запись `scout` из `.mcp.json` в том же
каталоге имеет приоритет. [Настройка MCP в Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers)

```json
{
  "mcpServers": {
    "scout": {
      "type": "local",
      "command": "/absolute/path/to/scout",
      "args": ["mcp", "--profile", "standard", "--transport", "stdio", "--target", "candidate=/absolute/review/candidate"],
      "tools": ["scan_skill"]
    }
  }
}
```

**OpenCode.** Используйте `opencode.json` в корне проекта. [Настройка MCP в OpenCode](https://opencode.ai/docs/mcp-servers/)

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "scout": {
      "type": "local",
      "command": ["/absolute/path/to/scout", "mcp", "--profile", "standard", "--transport", "stdio", "--target", "candidate=/absolute/review/candidate"],
      "enabled": true
    }
  }
}
```

В новой сессии попросите агента вызвать `scan_skill` у Scout с аргументом
`{"target":"candidate"}` и сообщить решение и состояние проверки. Клиент может
добавить к имени инструмента префикс `scout`. В результате вызова ищите отчёт
с `operation: scan`, `evaluation.decision` и `run.state`. Если Copilot CLI
сохранит большой ответ инструмента в файл, откройте указанный файл с отчётом.
В Cursor CLI одобрите запись командой `agent mcp enable scout` и проверьте
обнаружение инструментов через `agent mcp list-tools scout`. Для вызова из
агента нужен вход в Cursor. [MCP в Cursor CLI](https://cursor.com/docs/cli/mcp)

### Ответы MCP и HTTP-транспорт

Отчёт содержит одинаковый JSON в `structuredContent` и в текстовом блоке, если
обе копии укладываются в лимит ответа JSON-RPC в 8 МиБ (без завершающего перевода
строки). Если помещается только структурированный отчёт, в тексте остаётся
резюме, а не обрезанный JSON. Если структурированный отчёт с резюме не
помещается, сервер возвращает ошибку JSON-RPC; одобрение не подразумевается.

HTTP-транспорт CLI требует привязки к числовому loopback-адресу и явного bearer-токена размером 32–512 байтов.
Браузерные источники запросов запрещены, пока оператор не разрешит их через `--origin`.
Сервер поддерживает JSON-ответы, без SSE и потокового GET.
После инициализации передавайте полученный `Mcp-Session-Id` в последующих
запросах. POST и DELETE без него возвращают HTTP 400, кроме начального POST.
Для истёкшей или завершённой сессии POST, GET и DELETE возвращают HTTP 404;
GET без идентификатора или с идентификатором активной сессии возвращает HTTP 405,
поскольку SSE не поддерживается.

Сервер согласует MCP `2025-06-18` поверх JSON-RPC 2.0. Имена параметров запросов
чувствительны к регистру; метаданные передаются в необязательном объекте `_meta` внутри `params`.
Числовые ID ограничены диапазоном знакового 64-битного целого. Допускается десятичная
и экспоненциальная запись целых значений; ответ сохраняет исходную запись ID.
Ограничения размера сообщения, глубины и числа узлов продолжают действовать.
Регистр имени схемы HTTP-аутентификации несущественен; bearer-секрет сравнивается
точно. Ответы 401 содержат заголовок `WWW-Authenticate` со схемой Bearer.

`mcp.New` заимствует Scanner и доверенный `policy.Gate`.
См. [владение ресурсами API](../development/go-api.ru.md#координаты-лимиты-и-доверие).

## Проверка

`make host-test` проверяет разрешения, отмену и коды завершения на тестовых реализациях SDK
и настоящем CLI. Совместимость с реальными приложениями проверяется отдельно.
