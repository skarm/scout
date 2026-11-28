# Обнаружение установленных компонентов агентов

[English](discovery.md) · Русский

`scout discover` находит локальные декларации Codex, Claude Code, Cursor, GitHub Copilot CLI, OpenCode, Gemini CLI, OpenClaw, Grok CLI, DeepSeek Harness, ZCode, Qwen Code и Kimi Code перед проверкой
их файлов. Команда читает конфигурации и манифесты без запуска MCP-серверов,
выполнения команд, подстановки переменных окружения из файлов и сетевых запросов.

```sh
scout discover
scout discover --agent codex --format json --output /tmp/environment.json
scout discover --project /work/repository --scan -- --format markdown
scout discover --home /review/home --system=false --no-project --format json
```

Флаги перед `--` управляют обнаружением. В режиме `--scan` после `--` задаются
обычные флаги сканирования: профиль, отчёты, политика, проверки, разрешения сервисов
и лимиты сканирования. Флаги инвентаря `--format` и `--output` несовместимы с
`--scan`; параметры отчёта сканирования указывайте после `--`. Позиционные входы
и stdin в этом режиме не принимаются. Настройки Scout по-прежнему явно выбирает оператор.

## Матрица поддержки

Для каждого профиля регрессии Scout проверяют инвентаризацию, прямое сканирование,
сканирование после discovery и сравнение неизменённых и изменённых снимков.
В третьей колонке указан пример проверенного нативного входа. В последней колонке
приведены ссылки на примеры подключения Scout по MCP stdio.

| Агент | `--agent` / `--harness` | Нативный вход в сквозной проверке | Пример MCP stdio для Scout |
| --- | --- | --- | --- |
| Codex | `codex` | `.codex/config.toml` с `[mcp_servers]` и `hooks/hooks.json` в пакете Agent Plugins | [Есть](integrations.ru.md#mcp-stdio-в-клиентах) |
| Claude Code | `claude-code` | MCP в `.claude.json` и групповые хуки в `.claude/settings.local.json` | [Есть](integrations.ru.md#mcp-stdio-в-клиентах) |
| Cursor | `cursor` | Плоские хуки в `.cursor/hooks.json` | [Есть](integrations.ru.md#mcp-stdio-в-клиентах) |
| GitHub Copilot CLI | `copilot-cli` | `.github/mcp.json` и `.github/hooks/*.json` | [Есть](integrations.ru.md#mcp-stdio-в-клиентах) |
| OpenCode | `opencode` | `opencode.jsonc` с картой `mcp.servers` | [Есть](integrations.ru.md#mcp-stdio-в-клиентах) |
| Gemini CLI | `gemini-cli` | `.gemini/settings.json` с комментариями и MCP `httpUrl` | — |
| OpenClaw | `openclaw` | `openclaw.json` в JSON5 с `mcp.servers` | — |
| Grok CLI | `grok-cli` | MCP в `.grok/config.toml` и `.grok/hooks/*.json` | — |
| DeepSeek Harness | `deepseek-harness` | `.dsh/profiles/web/cordis.patch.yml` со вставкой MCP в Cordis | — |
| ZCode | `zcode` | MCP в `.zcode/config.json` и групповые хуки в `zcode.json` | — |
| Qwen Code | `qwen-code` | `.qwen/settings.json` с BOM, комментариями, MCP и групповыми хуками | — |
| Kimi Code | `kimi-code` | `[[hooks]]` в `.kimi-code/config.toml` и `.kimi-code/mcp.json` | — |

Матрица описывает статический разбор захваченных деклараций. Для общей
инвентаризации используйте `--agent all`. При совместном сканировании по умолчанию
используется автоматическое распознавание. Для снимка и разбора отдельного
файла с неоднозначным именем выбирайте конкретного агента.

## Расположения

По умолчанию выбраны домашний каталог текущего пользователя, текущий проект
и известные системные расположения. Повторяемый `--project` заменяет проект
по умолчанию; `--no-project` исключает проекты. Родители выбранного проекта
проверяются до ближайшей записи `.git`, выбранного домашнего каталога или корня
файловой системы. Пути из конфигураций агента не запускают обход других проектов.
Встроенные MCP-записи в `~/.claude.json` сопоставляются по написанию выбранного
пути проекта и пути после разрешения символических ссылок. Если файловая система
считает одинаковыми имена с разным регистром или нормализацией Unicode,
используйте написание из `projects`.

Расположения Codex:

- Пользовательские MCP-декларации в `~/.codex/config.toml`, навыки в
  `~/.agents/skills` и `~/.codex/skills`, включая группу `.system`.
- Проектные MCP-декларации в `.codex/config.toml` и навыки в `.agents/skills`.
- Плагины в `~/.codex/plugins/cache` с portable-манифестом `plugin.json`
  либо совместимым `.codex-plugin/plugin.json` / `.claude-plugin/plugin.json`.
- Системные `config.toml` и `skills` в `/etc/codex`, либо в стандартном
  `C:\ProgramData\OpenAI\Codex` на Windows.

Расположения Claude Code:

- Пользовательские MCP-декларации в `~/.claude.json`, включая встроенные записи
  выбранных проектов. Навыки и прежние Markdown-команды в `~/.claude/skills`
  и `~/.claude/commands`.
- Проектные `.mcp.json`, `.claude/skills`, `.claude/commands`,
  хуки в `.claude/settings.json` и `.claude/settings.local.json`.
- Плагины в `~/.claude/plugins/{cache,repos,synced}`.
- `managed-mcp.json` и `managed-settings.json` в
  `/Library/Application Support/ClaudeCode` на macOS, `/etc/claude-code` на Linux
  или `C:\Program Files\ClaudeCode` на Windows.

Для Cursor Scout читает MCP и хуки жизненного цикла в `~/.cursor` и проектной
`.cursor`, а также находит правила, агентов, команды и навыки. Пакеты в
`~/.cursor/plugins/local` и `plugins/cache` могут объявлять компоненты через
`.cursor-plugin/plugin.json`. Scout также читает системный файл хуков в известном
для платформы каталоге. [Справочник плагинов Cursor](https://cursor.com/docs/reference/plugins) · [Хуки Cursor](https://cursor.com/docs/hooks)

Для GitHub Copilot CLI Scout читает `~/.copilot/mcp-config.json`, находит
пользовательские навыки и агентов, а также пакеты в `~/.copilot/installed-plugins`.
Проектные `.mcp.json` и `.github/mcp.json` могут содержать как обёртку, так и
плоскую карту MCP. Scout читает проектные и пользовательские файлы хуков и встроенные хуки в
известных файлах настроек Copilot, включая команды оболочки и вызов через `exec`, находит агентов и навыки в `.github` и учитывает
прежние пути манифестов плагинов и каталог `com.github.copilot` в Agent Plugins 1.0.
[Справочник плагинов Copilot CLI](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)

Для OpenCode Scout читает `opencode.json` и `opencode.jsonc` в корне проекта,
проектной `.opencode`, `~/.config/opencode` и известных системных каталогах.
В инвентарь входят MCP-серверы с массивом аргументов и явным отключением в обеих
версиях формата, ссылки на плагины, локальные плагины и инструменты на JavaScript
или TypeScript, агенты, команды и навыки. Scout пропускает управляемые настройки
macOS и не загружает внешние зависимости.
[Конфигурация OpenCode](https://opencode.ai/docs/config/) · [MCP в OpenCode](https://opencode.ai/docs/mcp-servers/)

Для Gemini CLI Scout читает пользовательский и проектный
`.gemini/settings.json`, а также `settings.json` и `system-defaults.json` в
системном каталоге платформы. Настройки допускают комментарии и используют
обычные правила JSON для запятых. В инвентарь входят MCP-серверы, групповые
хуки, локальные навыки, агенты, TOML-команды и политики, а также `GEMINI.md` в
известных расположениях. Поддерживается каталог `.agents/skills`. Scout
записывает локальные объявления `mcp.allowed`, `mcp.excluded` и `skills.disabled`
без расчёта приоритетов. `--gemini-home` и `GEMINI_CLI_HOME` указывают на каталог,
который содержит `.gemini` и `.agents`.
[Конфигурация Gemini CLI](https://geminicli.com/docs/reference/configuration/)

Scout находит пакеты в `.gemini/extensions/` по `gemini-extension.json` и
учитывает `hooks/hooks.json` и локальные каталоги компонентов. Контекстные
файлы должны находиться внутри пакета. Статический анализ MCP распознаёт stdio,
SSE через `url` и Streamable HTTP через `httpUrl`. Пользовательские пути к
системным файлам, внешние ссылки и фактическое включение расширений находятся
за пределами этой поддержки. [Справочник расширений Gemini CLI](https://geminicli.com/docs/extensions/reference/)

Для OpenClaw Scout читает `openclaw.json` в формате JSON5 и ищет компоненты в
`skills`, `hooks` и `extensions` каталога состояния. По умолчанию это
`~/.openclaw`. Другой каталог можно указать через `--openclaw-home` или
`OPENCLAW_STATE_DIR`, если флаг `--home` опущен. В обычном `workspace` внутри
каталога состояния и в явно выбранном `--project` Scout проверяет `skills/`,
`.agents/skills/`, `hooks/` и `.openclaw/extensions/`. При стандартном
расположении состояния учитываются личные навыки в `~/.agents/skills/`.
[Конфигурация OpenClaw](https://docs.openclaw.ai/gateway/configuration/) · [Расположения навыков OpenClaw](https://docs.openclaw.ai/agent)

Scout разбирает `mcp.servers`, локальные настройки включения, манифесты
`openclaw.plugin.json`, метаданные OpenClaw в `package.json` и каталоги хуков с
`HOOK.md`. Навыки и точки входа плагинов должны находиться внутри пакета.
В инвентаре хуки названы по каталогам. При сканировании Scout связывает
захваченные обработчики по порядку имён файлов.
[Манифест плагина OpenClaw](https://docs.openclaw.ai/plugins/manifest) · [Обнаружение хуков OpenClaw](https://docs.openclaw.ai/automation/hooks/configuration)

Рабочую область в другом месте можно указать через `--project`. Директивы
`$include` отмечаются как неразрешённые, а discovery возвращает неполный
инвентарь. Пути из настроек загрузки, альтернативные имена конфигурации,
профили, пакеты по символическим ссылкам и загрузка совместимых форматов
других агентов остаются за пределами поддержки OpenClaw в discovery.
Хранилища сессий и учётных данных находятся вне известных расположений
discovery.

Для Grok CLI Scout читает `config.toml` в `~/.grok` и проектной `.grok`,
а также пользовательские и системные `managed_config.toml` и
`requirements.toml` в известных расположениях, включая `/etc/grok` на Unix.
`--grok-home` и `GROK_HOME` указывают непосредственно на каталог конфигурации.
В инвентарь входят MCP-серверы и локальные настройки включения плагинов.
Проектные хуки берутся из `.grok/hooks/*.json`. Встроенные хуки TOML
учитываются в пользовательской и системной областях. При сканировании
отдельного TOML-файла встроенные хуки могут попасть в отчёт со статусом
неизвестной активации. Ссылка на доказательство охватывает весь TOML-файл.
[Настройки Grok](https://docs.x.ai/build/settings) · [Хуки Grok](https://docs.x.ai/build/features/hooks)

Scout находит `lsp.json`, агентов, навыки, команды и файлы процессов Rhai
в известных каталогах Grok, включая пользовательские `~/.agents/skills`
и `~/.agents/commands`. В `.grok/plugins` Scout распознаёт
`.grok-plugin/plugin.json`, совместимые манифесты и локальные пакеты со
стандартной структурой. В пакетах учитываются `.mcp.json`, `.lsp.json` и
`hooks/hooks.json`. Анализ опирается на захваченные декларации и ссылки
внутри пакета. Выполнение хуков и Rhai, расчёт доверия и загрузка источников
marketplace находятся за пределами анализа.
[Плагины Grok](https://docs.x.ai/build/features/skills-plugins-marketplaces) · [Процессы Grok](https://docs.x.ai/build/modes-and-commands)

Для DeepSeek Harness Scout читает `~/.dsh/settings.yaml`, общий
`cordis.patch.yml` и `profiles/<имя>/{package.json,cordis.patch.yml}`. Флаг
`--deepseek-home` указывает непосредственно на каталог конфигурации. В
выбранных проектах Scout также читает корневые файлы разработки `cordis.yml`
и `cordis.patch.yml`. В `package.json` поле `dsh.bundle.patch` может указывать
на один или несколько YAML-файлов внутри пакета, а `dsh.profile.bundles`
перечисляет пакеты профиля. [Профили и пакеты DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness/blob/master/apps/cli/reference/README.md)

Scout разбирает строки MCP-клиентов, отдельные серверы менеджера и карту
`config.servers`, в том числе внутри `insert` и групп Cordis. Выражения
`!!js` остаются непрозрачными, а ссылки на учётные данные сохраняются без
подстановки. Scout учитывает явно заданное отключение и отклоняет YAML с
повторяющимися ключами, псевдонимами и несколькими документами. Подключаемые
файлы отмечаются как неразрешённые. Итоговое объединение слоёв и разрешение
npm-пакетов находятся за пределами статической проверки.
[MCP в DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/mcp.md)

В известных каталогах `.dsh/skills` и `.agents/skills` поддерживаются
`<имя>/SKILL.md` и отдельные файлы `<имя>.md`. Scout учитывает общие
пользовательские `AGENTS.md` и проектные файлы инструкций на основе
`AGENTS.md` и `CLAUDE.md`. Хранилища учётных данных и состояние запущенных
сессий остаются вне области discovery.
[Навыки DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/skills.md) · [Файлы инструкций](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/context/agent-instructions/README.md)

Для ZCode Scout читает `~/.zcode/cli/config.json`, а в выбранных проектах
находит `zcode.json` и `.zcode/config.json`. Флаг `--zcode-home` указывает
непосредственно на каталог `.zcode`. В инвентарь входят `mcp.servers`,
групповые хуки `hooks.events` и локальные настройки плагинов. В одной
области нативная карта MCP с распознанным сервером имеет приоритет над совместимой
`.agents/mcp.json`. Пользовательские и проектные декларации учитываются
отдельно. [Настройки MCP в ZCode](https://zcode.z.ai/en/docs/mcp-services) · [Хуки ZCode](https://zcode.z.ai/en/docs/hooks)

В известных пользовательских и проектных каталогах Scout находит навыки,
команды Markdown, субагентов и `AGENTS.md`. Для плагинов учитываются
`.zcode-plugin/plugin.json` и совместимый `.claude-plugin/plugin.json`,
реестр установок и версии из `cli/plugins/cache`. Локальные каталоги
плагинов должны оставаться внутри выбранного корня. Чекауты marketplace и
каталоги данных плагинов находятся вне области discovery. При статической
проверке учитываются `hooks/hooks.json`, объявленные файлы хуков и MCP.
Ссылки через `${ZCODE_PLUGIN_ROOT}` сопоставляются с захваченными файлами
пакета. Фактическая активация, доверие и значения шаблонов остаются
неизвестными.
[Форматы плагинов ZCode](https://zcode.z.ai/en/docs/plugin) · [Хранилище ZCode CLI](https://github.com/zai-org/ZCode/blob/main/apps/zcode-cli/docs/usage/10-plugins.md)

Переменные `CODEX_HOME` и `CLAUDE_CONFIG_DIR` процесса сканирования могут менять
каталоги конфигурации. Явный `--home` отключает эти неявные переопределения;
`--codex-home` и `--claude-home` выбирают каталоги явно. Для остальных
клиентов используются `CURSOR_CONFIG_DIR`, `COPILOT_HOME` и `OPENCODE_CONFIG_DIR`
и соответствующие флаги `--cursor-home`, `--copilot-home` и `--opencode-home`. Прежний `~/.claude.json`
и перенесённый `.claude.json` включаются в инвентарь, если существуют оба.

Совместимые манифесты плагинов могут добавлять внутренние каталоги навыков и
MCP-конфигурации, встроенные либо указанные файлом. Пути должны оставаться внутри
плагина. Для Agent Plugins 1.0 и 1.1 в кеше Codex Scout читает корневые
`plugin.json` и `mcp.json`, а также навыки `skills/<имя>/SKILL.md`. Версия 1.1
также использует корневой `hooks.json`. Конфигурации компонентов указывают ту же
версию схемы, что и манифест. При инвентаризации и сканировании настройки Codex
берутся из объекта `extensions.com.openai`, если он есть, или из
`.codex-plugin/plugin.json`. Фильтр `--kind hook` выбирает пакеты с переносимыми
или нативными хуками Codex, включая стандартный `hooks/hooks.json`, если в
настройках пакета не объявлены нативные хуки.
Каталоги marketplace не обходятся как установленные плагины.

Плагины Claude могут не содержать `.claude-plugin/plugin.json`. Их стандартные
`skills/` и `.mcp.json` всё равно обнаруживаются; обычная структура кеша —
`cache/<marketplace>/<plugin>/<version>`. Корневой `SKILL.md` становится единственным
навыком плагина при отсутствии каталога `skills/` и поля `skills` в манифесте.
Для пакета без манифеста имя-кандидат берётся из каталога, а ссылка на источник —
из захваченного стандартного компонента.

## Инвентарь и результаты сканирования

При прямом сканировании каталога Scout распознаёт известные нативные пути.
Для отдельного `hooks.json`, `mcp.json` или `.mcp.json` укажите
`--harness cursor` или `--harness copilot-cli` в зависимости от формата. При сканировании и записи
снимка через `discover` по умолчанию используется единственный выбранный агент.
При прямом сканировании отдельного `settings.json` или `system-defaults.json`
Gemini CLI укажите `--harness gemini-cli`.

JSON использует `scout.environment/v1`. Компоненты сохраняют агента, тип, область,
путь, конфигурацию-источник, ключ в форме JSON Pointer, где он применим, и локально
объявленное состояние. `sources` содержит SHA-256 прочитанных байтов.
`scan_targets` содержит конфигурации и корни навыков/плагинов без вложенных
дубликатов. `enablement` хранит настройки включения плагинов, навыков и MCP
отдельно от деклараций компонентов.
Проектные списки Claude `disabledMcpServers` и `enabledMcpServers` читаются из
`projects.<путь>` в `.claude.json` для выбранных проектов. Их ключи-источники
сохраняются отдельно от настроек подтверждения
`enabledMcpjsonServers` / `disabledMcpjsonServers`.

Имена и пути — недоверенные метаданные. Значения команд, аргументов, заголовков,
учётных данных, URL и содержимое навыков не копируются в инвентарь. Сами пути,
селекторы и хеши тоже могут быть чувствительными.

`enabled`, `disabled` и `unknown` описывают только декларации. Обнаружение не
вычисляет приоритеты конфигураций, подтверждения, доверие к проекту и фактический
набор инструментов агента. Версии плагинов в кеше могут быть отключены или устареть.

Код 0 при выводе инвентаря означает завершённое обнаружение документированной
области. Код 2 означает некорректный вход, непрочитанную/неподдержанную часть,
исчерпанный лимит, отмену или ошибку вывода. Неполный инвентарь сохраняет найденные
компоненты и явные `issues`. Инвентарь не является заключением о безопасности.

`--output` инвентаря должен находиться вне выбранных каталогов конфигурации агентов,
корней навыков и файлов конфигурации, включая пропущенные из-за лимитов, ошибок
чтения или отмены. Для проектов консервативно защищаются известные расположения
конфигурации в пределах 64 родителей выбранного пути и его канонического алиаса,
в том числе выше границы репозитория. Существующий отчёт в другом месте домашнего
каталога или проекта по-прежнему можно заменить частичным инвентарём.

`--scan` требует полного обнаружения и от 1 до 32 выбранных корней.
Большой инвентарь можно отфильтровать перед сканированием либо разделить по агентам/проектам:

```sh
scout discover --agent codex --kind skill \
  --include-path /home/operator/.agents/skills \
  --exclude-path /home/operator/.agents/skills/archived \
  --scan -- --format markdown
```

`--kind` принимает `skill`, `plugin`, `mcp-server`, `command`, `hook`, `agent`, `rule`, `tool`, `lsp-server`, `workflow` и `channel`. Он и фильтры путей
повторяемы, до 32 значений каждого. Включение пересекается с известными корнями
и не добавляет внешние входы. Исключение удаляет целые пересекающиеся корни;
для выбора отдельных компонентов вместо общего каталога навыков/кеша задайте тип.
Тип `hook` выбирает пакеты с переносимыми hooks, чтобы сканер мог найти обработчики.
Существующие алиасы путей сопоставляются по правилам файловой системы для регистра
и Unicode. У отсутствующего суффикса разрешаются существующие предки-симлинки;
другие ошибки разрешения пути, включая битые и зацикленные ссылки, отменяют выборку.
Компоненты, хеши источников и ошибки инвентаря не фильтруются. Дополнительное поле
`selection` описывает выбранную область; неполное обнаружение по-прежнему запрещает
автоматическое сканирование. Запись отчётов защищает все известные расположения
конфигурации, включая исключённые из сканирования.

Режим выводит существующий отчёт `scout.report/v1` с обычной политикой
и кодами завершения. Проверяются также отключённые декларации. Корни могут
содержать вспомогательные файлы помимо найденных компонентов; действуют обычные
лимиты захвата и анализа. Scanner заново захватывает исходники, поэтому между
обнаружением и захватом возможны изменения.
Известные кеши плагинов с файлами остаются целями проверки, даже если метаданные
поддержанных компонентов не распознаны. Деревья каталогов без файлов исключаются.

Для явного совместного анализа передайте `--environment` после `--`, выберите один
`--agent` и не более одного проектного контекста. Наблюдения и ограничения описаны
в [руководстве анализа окружения](environment-analysis.ru.md).

## Ограничения и охват

По умолчанию: 10 секунд, 10 000 проб и записей каталогов, глубина 12 и 8 МиБ суммарных
байтов конфигураций/манифестов. Один файл ограничен 256 КиБ. Лимиты, отвергнутые
символические ссылки, некорректные конфигурации, неподдержанные ссылки плагинов
и ошибки чтения делают обнаружение неполным. Явно выбранные корни канонизируются;
вложенные ссылки не обходятся. Подкаталоги `.git`, `node_modules`, `.venv`
и `__pycache__` рекурсивно не проверяются на наличие компонентов.
Отмена при финализации также делает инвентарь неполным с кодом 2; публикация
частичного результата не сбрасывает ошибку обнаружения.

Обнаружение не охватывает cloud- и MDM-конфигурации, профильные overlays,
настройки времени выполнения/CLI, плагины вне известных кешей, дополнительные
кеши и seed-каталоги из переменных окружения плагинов, корпоративные навыки Claude,
навыки по ссылкам, MCP bundles и удалённые ссылки плагинов. Полный инвентарь не
устанавливает охват этих расположений и совместимость со всеми версиями хостов.
Описания инструментов у работающих серверов не запрашиваются. Сравнение снимков
в эту команду не входит.

[Навыки Codex](https://developers.openai.com/codex/skills) · [Упаковка плагинов Codex](https://developers.openai.com/plugins/build/plugins) · [Области MCP в Claude](https://code.claude.com/docs/en/mcp) · [Навыки Claude](https://code.claude.com/docs/en/skills) · [Манифесты плагинов Claude](https://code.claude.com/docs/en/plugins-reference)

### Qwen Code

`discover --agent qwen-code` находит пользовательский и проектный
`.qwen/settings.json`, проектные `.mcp.json` и `.lsp.json`, а при включённом
системном поиске и стандартные системные настройки. Каталог пользователя
задают `--qwen-home` или `QWEN_HOME`. Scout собирает объявления MCP-серверов и
групповых хуков, команды Markdown и TOML, субагентов, правила, навыки первого
уровня из `.qwen/skills` и `.agents/skills`, JavaScript-сценарии и стандартные
файлы инструкций.
[Настройки Qwen Code](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/) · [Хуки Qwen Code](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/) · [Навыки Qwen Code](https://qwenlm.github.io/qwen-code-docs/en/users/features/skills/)

Scout читает нативные `qwen-extension.json` и переносимые пакеты Agent Plugins v1
в пользовательском каталоге расширений. Нативный пакет может объявлять
MCP-серверы, хуки и LSP-серверы во встроенном или отдельном файле, контекст,
команды, субагентов, навыки, сценарии и точки входа каналов. Для отдельного
файла настроек или переносимого пакета вне структуры каталогов Qwen Code
используйте `scout scan --harness qwen-code PATH`. Сканирование фиксирует
декларации в захваченных файлах. Действующие разрешения, состояние установки
расширений, окружение процесса и внешние пути зависят от среды выполнения.
[Формат расширений Qwen Code](https://qwenlm.github.io/qwen-code-docs/en/users/extension/introduction/) · [Agent Plugins v1 в Qwen Code](https://qwenlm.github.io/qwen-code-docs/en/users/extension/agent-plugins/)

### Kimi Code

`discover --agent kimi-code` находит пользовательские хуки в
`~/.kimi-code/config.toml`, пользовательские и проектные `.kimi-code/mcp.json`,
инструкции, навыки и субагентов в каталогах Kimi и общих каталогах `.agents`.
Каталог данных задают `--kimi-home` или `KIMI_CODE_HOME`. По умолчанию Scout
также читает хуки, настройки MCP и навыки предыдущего CLI в `~/.kimi`.
Для отдельного файла конфигурации используйте `scout scan --harness kimi-code PATH`.
[Каталоги Kimi Code](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/configuration/data-locations.md) · [Хуки](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/customization/hooks.md) · [MCP](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/customization/mcp.md)

Scout читает состояние плагинов из `plugins/installed.json` и находит
зарегистрированные пакеты внутри `plugins/managed` выбранного каталога.
Поддерживаются `kimi.plugin.json` и `.kimi-plugin/plugin.json` с объявлениями
MCP-серверов, хуков, команд, субагентов, навыков и инструкций к промпту.
Сканирование фиксирует декларации и связи с захваченными обработчиками.
Эффективные настройки, удалённые окружения, дополнительные каталоги поиска
и активация плагинов зависят от среды выполнения.
[Манифест плагина Kimi](https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/customization/plugins.md)
