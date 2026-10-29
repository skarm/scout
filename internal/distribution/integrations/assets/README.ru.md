# Reviewer-пакет Scout

[English](README.md) · Русский

Установите доверенный бинарник Scout отдельно, затем выберите формат пакета.
Пакет содержит адаптированный процесс NVIDIA Skill Inspector, не запускает
установщик и не выполняет проверяемый код.

## Выбор формата

- `agent-skill`: скопируйте `skill-inspector` в каталог навыков, поддерживаемый host.
- `claude-code`: загрузите доверенный skill-only плагин с `.claude-plugin/plugin.json`.
- `codex`: загрузите доверенный skill-only плагин с `.codex-plugin/plugin.json`.
- `pi`: выполните `pi install /absolute/trusted/bundle`, затем перезагрузите Pi.
- `opencode`: скопируйте `.opencode` в выбранный доверенный каталог конфигурации или проекта.
- `review-materials`: изучайте встроенные prompts и пояснения без сети.

Сохраняйте `references/`, LICENSE и NOTICE. Устанавливайте интеграцию вне
недоверенного пакета. Используйте SDK самого host; не запускайте npm install в проверяемом входе.

## Настройки оператора

```sh
export SCOUT_BIN=/absolute/trusted/scout
export SCOUT_TARGETS='{"candidate":{"path":"/absolute/review/candidate","harness":"claude-code"}}'
```

Модель передаёт `{"target":"candidate","semantic":false}` в `scout_scan`.
OpenCode также предоставляет `/scout candidate`. Аргументы не выбирают произвольные
пути, executable или flags. Корни входов должны оставаться неизменными при проверке.

По умолчанию выбран standard. Недоступность обязательного движка вызывает ошибку
до сканирования. `SCOUT_REDUCED_CORE=1` явно выбирает сокращённый custom.
Инструмент возвращает ограниченную сводку и число пропусков; для полного отчёта
выполните разрешённый CLI-вызов с `--output`. Обёртка не создаёт baseline,
не вызывает OSV, не добавляет YARA rules и не устанавливает проверяемый пакет.

## Семантическая проверка

```sh
export SCOUT_REVIEWER='{"provider":"chat-completions","endpoint":"https://review.example/v1/chat/completions","model":"YOUR_MODEL","keyEnv":"REVIEW_API_KEY"}'
```

Endpoint в примере — заполнитель. Обёртка поддерживает chat-completions,
anthropic и anthropic-proxy. HTTP на числовом loopback требует `allowLoopback:true`.
`semantic:true` также требует отдельного разрешения на передачу исходников.
В них могут быть секреты; полное удаление не гарантируется. Credentials читаются
после разрешений, не берутся из target и не возвращаются модели.

## Разрешения и проверка

Pi требует интерактивного подтверждения, OpenCode использует `context.ask`.
Отказ предотвращает запуск. Scanner запускается через argv без shell во временном
каталоге, с лимитами времени и вывода. Отмена завершает процесс. Валидные отчёты
с кодами 1/2 сохраняются. Другие инструменты host не изолируются.

`.scout-bundle.json` хранит размеры и хеши файлов пакета. При распространении
сохраняйте LICENSE/NOTICE. SDK fixtures проверяют контракты адаптеров;
совместимость с реальным host проверяйте отдельно.
