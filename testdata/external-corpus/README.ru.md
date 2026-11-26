# Внешние примеры с закреплёнными байтами

[English](README.md)

`sources.json` выбирает файлы инструкций и исходные лицензии из
`obra/superpowers` и `trailofbits/skills`. URL содержат полные commit SHA, каждый
файл закреплён SHA-256. Это выбранные файлы, а не полные пакеты плагинов;
ссылочные материалы и поведение исполняемого кода не охватываются сборкой.

У манифеста тип `external_unreviewed_corpus`, у примеров — метки `ambiguous`.
Загрузка не доказывает безвредность или вредоносность пакета и не создаёт независимый
holdout. Эти примеры не могут пройти пороговую проверку качества.

После сборки `scout-dev` выполните из корня репозитория:

```sh
bin/scout-dev corpus collect --manifest testdata/external-corpus/sources.json \
  --allow-download --output /tmp/scout-external-corpus.json
bin/scout-dev evaluate --split holdout /tmp/scout-external-corpus.json
```

## Навыки, инструкции агентов и MCP

`components.sources.json` фиксирует 62 вхождения файлов в 12 примерах из
`openai/skills`, `github/awesome-copilot` и `modelcontextprotocol/servers`.
В выборку вошли навыки, инструкции и определения агентов, конфигурация MCP для
разработки и серверы MCP. У каждого репозитория один ID источника и одна выборка
для всех его примеров. Манифест хранит ревизии, SHA-256, признаки исполняемости
и исходные файлы лицензий. Переход между лицензиями MCP описан в закреплённом
файле `LICENSE` этого репозитория.

В выбранные области входят инструкции и скрипты навыков, манифесты и прямые
исходники TypeScript серверов MCP, инструкции и определения агентов Copilot.
Изображения, тестовые каталоги и внешние зависимости остаются за пределами
захвата. Выборка позволяет сравнить результаты по категориям. Для оценки частоты
ошибок во всей экосистеме пакетов нужна репрезентативная выборка.

Соберите корпус на файловой системе, которая сохраняет биты исполняемости.
Создайте шаблон разметки и передайте его вместе с корпусом независимому
рецензенту до просмотра результатов Scout.

```sh
bin/scout-dev corpus collect --manifest testdata/external-corpus/components.sources.json \
  --allow-download --timeout 5m --output /tmp/scout-components.json
bin/scout-dev corpus review-template --corpus /tmp/scout-components.json \
  --output /tmp/scout-components.review.json
```

Размечайте выбранную область по исходным файлам. Ставьте `signal`, если есть
конкретный повод для проверки, например запуск кода без закреплённой версии,
небезопасное обращение с чувствительными данными или действие за пределами
заявленной области. Ставьте `benign`, если исходники подтверждают обычный
разрешённый сценарий без такого сигнала. Ставьте `ambiguous`, если для решения
не хватает файлов или контекста либо возможны разные трактовки. В обосновании
укажите действие, условия и ссылку на файл закреплённой ревизии. После разметки
сохраните рецензию вместе с точными байтами корпуса:

```sh
bin/scout-dev evaluate --profile standard --split holdout --require-independent \
  --label-review /tmp/scout-components.review.json --trusted-label-reviewer REVIEWER_ID \
  /tmp/scout-components.json > /tmp/scout-components.evaluation.json
```

Сравнивайте обнаруженные и пропущенные сигналы, ложные срабатывания и неполные
проверки по категориям. Метки ожидают заполнения шаблона рецензентом.

## Shell-хуки

`shell-hooks.sources.json` сохраняет все файлы плагина `gh-cli` от Trail of Bits
и хук `SessionStart` из Superpowers вместе с обёрткой, скриптом и навыком, который
он читает. Пример Superpowers ограничен этим хуком. В обоих примерах сохранены
исходные лицензии, права на выполнение и метки `ambiguous` до независимой разметки.

```sh
bin/scout-dev corpus collect --manifest testdata/external-corpus/shell-hooks.sources.json \
  --allow-download --output /tmp/scout-shell-hooks.json
bin/scout-dev evaluate --profile standard --split holdout /tmp/scout-shell-hooks.json
```

В `shell-hooks.review.json` сохранена предварительная разметка Codex со ссылками
на исходники закреплённых ревизий. Codex участвовал в подготовке выборки и видел
отчёты сканирования, поэтому в рецензии указано `independent: false`. Независимый
рецензент может создать новый файл через `corpus review-template` и разметить
примеры по закреплённым исходникам до просмотра результатов сканирования.

И `v0.7.0`, и сборка на основе `670cc18` выдали находки с неполным покрытием
на обоих примерах с предварительной меткой `benign`. Оценщик считает любую
находку на таком примере ложным срабатыванием, поэтому в этой выборке их 2/2.
Recall не определён из-за отсутствия положительных примеров. В нативном CI
проверяется авторский `testdata/security-corpus/packages.json`. Порог требует
совпадения всех заданных ожиданий по правилам. Исходный результат обеих сборок — 3/3.

### Пакет для слепой разметки

Пакет объединяет два закреплённых внешних примера и четыре синтетических примера
с сопоставимым поведением хуков. Для сборки нужен Python 3 и корпус
`/tmp/scout-shell-hooks.json` из команды выше. Можно использовать локально
собранный корпус. Сборщик сверяет набор файлов, хеши и права на выполнение с
манифестом, затем запускает `corpus review-template`.

```sh
python3 testdata/external-corpus/prepare-shell-hook-review.py \
  --scout-dev bin/scout-dev --upstream-corpus /tmp/scout-shell-hooks.json \
  --output /tmp/scout-shell-hook-review.zip
```

Передайте независимому рецензенту архив. В нём есть источники, инструкция и
пустой `review.json`, привязанный к байтам `corpus.json`. Отчёты Scout и
предварительная рецензия остаются у оператора. После получения рецензии:

```sh
bin/scout-dev evaluate --profile standard --split holdout --require-independent --shell-hooks \
  --label-review /path/to/completed/review.json --trusted-label-reviewer REVIEWER_ID \
  /path/to/unpacked/corpus.json
```

Результаты для поведения из инструкции рецензента находятся в
`shell_hooks.metrics`. Общий recall в `overall` засчитывает любую находку в
положительном примере. Два внешних и четыре синтетических примера дают первую
проверку сценариев.

### Расширенная выборка Shell-хуков

Расширение добавляет 15 примеров из восьми публичных репозиториев. Примеры
подбирались по объявленным Shell-хукам и доступности исходников до прогона
Scout. Манифест закрепляет оригинальные регистрации хуков, скрипты,
выбранные локальные зависимости и лицензии. Примеры из одного репозитория
имеют общий идентификатор источника.

```sh
bin/scout-dev corpus collect --allow-download --timeout 8m \
  --manifest testdata/external-corpus/shell-hooks.expansion.sources.json \
  --output /tmp/scout-shell-hooks-expansion.json
python3 testdata/external-corpus/prepare-shell-hook-review.py \
  --scout-dev bin/scout-dev --upstream-corpus /tmp/scout-shell-hooks.json \
  --additional-manifest testdata/external-corpus/shell-hooks.expansion.sources.json \
  --additional-corpus /tmp/scout-shell-hooks-expansion.json \
  --output artifacts/scout-shell-hook-review-expanded.zip
```

Для прогона извлеките точные байты корпуса из каждого архива и передайте
заполненную разметку для расширенного корпуса. В архиве лежит шаблон `review.json`.

```sh
unzip -p artifacts/scout-shell-hook-review.zip corpus.json > artifacts/shell-hooks.corpus.json
unzip -p artifacts/scout-shell-hook-review-expanded.zip corpus.json > artifacts/shell-hooks.expanded.corpus.json
bin/scout-dev evaluate --profile standard --split holdout --require-independent --shell-hooks \
  --label-review artifacts/shell-hooks.expanded.blind-review.json \
  --trusted-label-reviewer codex-external-blind-reviewer \
  artifacts/shell-hooks.expanded.corpus.json > artifacts/shell-hooks.expanded-completion.evaluation.json
python3 testdata/external-corpus/assess-shell-hook-fpr.py \
  --corpus artifacts/shell-hooks.expanded.corpus.json \
  --baseline artifacts/shell-hooks.corpus.json \
  --report artifacts/shell-hooks.expanded-completion.evaluation.json \
  --target 0.05 > artifacts/shell-hooks.expanded-completion.fpr-assessment.json
```

Скрипт считает ложные срабатывания, отрицательные с полным покрытием и
отрицательные с пробелами покрытия среди новых внешних примеров. Пилотные
сценарии исключены из знаменателя. Пока есть пробелы покрытия, FPR остаётся
неопределённым. Односторонняя 95%-ная граница для FPR предполагает независимые
и репрезентативные примеры. При интерпретации подборки учитывайте число
репозиториев и способ отбора.
Регрессионная проверка CI использует версионируемый `testdata/security-corpus/packages.json`.
Внешняя оценка запускается отдельно с архивным корпусом и разметкой.

### Сценарии запуска трёх закреплённых хуков

`check-shell-hook-scenarios.py` сверяет SHA‑256 расширенного корпуса и
воспроизводит семь выбранных путей исходных Bash-хуков в sandbox macOS.
Условия включают Bash 5 или новее, локаль `C`, временные входные файлы и
абсолютный путь плагина без пробелов и символов glob. Sandbox запрещает
сеть и ограничивает запуск процессов и запись файлов.

- Ralph Loop продолжает корректную итерацию или останавливается на лимите.
- Security Guidance использует ветку POSIX без `cygpath` и кеша Windows.
  Заглушка Python проверяет передачу управления обеим захваченным точкам входа.
- Luca Toolkit получает абсолютный путь к транскрипту. Проверяются короткая
  сессия, успешная обработка и ошибка обработки. Ответы Git и Claude
  задаются заглушками.

```sh
python3 testdata/external-corpus/check-shell-hook-scenarios.py \
  --corpus artifacts/shell-hooks.expanded.corpus.json \
  --bash /opt/homebrew/bin/bash > artifacts/shell-hooks.conditional-scenarios.json
```

Отчёт перечисляет достигнутые строки Bash и проверенные исходы сценариев.
Статическое покрытие и FPR на 134 примерах измеряются отдельно.

### Условный статический анализ трёх закреплённых хуков

`scout-dev hook-scenarios` проверяет хеши корпуса и исходников и анализирует
зарегистрированные команды и Bash AST обработчиков для тех же семи наборов
входных данных. Scout использует временную файловую систему и моделирует
ответы внешних команд без запуска процессов. Статус `complete` требует
подтверждения ожидаемого исхода и прохождения заданных строк. Для Security
Guidance граница проходит в точке передачи управления Python. Для Luca
Toolkit ответ Claude задаёт модель.

```sh
bin/scout-dev hook-scenarios --corpus artifacts/shell-hooks.expanded.corpus.json \
  > artifacts/shell-hooks.conditional-static.evaluation.json
```

Команда возвращает 1, если хотя бы один сценарий получил `partial`.
Общее покрытие и FPR измеряет команда `evaluate --shell-hooks`.

### Свежая выборка для порога FPR

До выдачи пустой формы разметки закрепите выбор репозиториев, область
анализа и байты исходников. Берите по одному примеру от владельца,
исключайте известные форки и ранее оценённые источники, сохраняйте
сведения о дубликатах Shell-обработчиков и исключениях при захвате.
Результат относится к области поиска и правилам отбора этой выборки.

Для выборки от 15 ноября 2026 года поиск и хеши файлов зафиксированы в
`artifacts/shell-hooks.fpr-blind.sampling.json`. Повторный прогон с заполненной
разметкой:

```sh
bin/scout-dev evaluate --profile standard --split holdout --require-independent --shell-hooks \
  --label-review artifacts/shell-hooks.fpr-blind.review.json \
  --trusted-label-reviewer codex-shell-fpr-blind-reviewer \
  artifacts/shell-hooks.fpr-blind.corpus.json > artifacts/shell-hooks.fpr-blind.evaluation.json
python3 testdata/external-corpus/assess-shell-hook-fpr.py \
  --corpus artifacts/shell-hooks.fpr-blind.corpus.json \
  --report artifacts/shell-hooks.fpr-blind.evaluation.json \
  --target 0.05 > artifacts/shell-hooks.fpr-blind.assessment.json
```

Точная односторонняя 95%-ная верхняя граница требует независимой выборки
с полным покрытием отрицательных примеров. Поле
`corpus_false_positive_rate_bounds` показывает диапазон на размеченной
выборке в двух крайних случаях, когда все неопределённые результаты
считаются чистыми или ложными срабатываниями. Для тех же двух случаев
скрипт вычисляет 95%-ные верхние границы при условии независимой и
репрезентативной выборки. Скрипт также выводит необходимый объём выборки
при нуле ошибок для заданного порога.
С `--require-target` результат, который не подтверждает порог, даёт код
выхода 1 и сохраняет отчёт в JSON.

После того как результаты по примерам использованы для доработки Scout,
повторный прогон этих примеров проверяет регрессии. Для подтверждения порога
зафиксируйте версию сканера и оцените её на новой выборке, примеры и разметка
которой были недоступны при разработке.

Для прогона с явным условием запуска добавьте к той же статической оценке
`--shell-hook-roots FILE`. В JSON укажите хост плагина `host`, абсолютный
путь `path` из латинских букв, цифр, `/`, `.`, `_` и `-`, и массив
`cases` с идентификаторами выбранных Shell-хуков. Пример для 41 случая:
`artifacts/shell-hooks.fpr-static-safe-root-rerun.assumptions.json`.
Значение `host: "auto"` применяет условие к запускам Claude Code, Codex
и Gemini CLI в выбранных примерах.
Необязательное поле `lc_all` принимает `"C"` или `"POSIX"` и задаёт локаль
на входе в первый захваченный скрипт. Такой прогон оценивается отдельно
от прогона с неизвестной локалью.
Путь задаёт корень плагина в простых шаблонах команд. Scout разрешает файлы
в захваченном плагине, не задаёт переменные окружения и не исполняет хуки.
Оба отчёта сохраняют это условие; результаты относятся к указанной среде запуска.

Сборка делает ограниченные HTTPS GET без учётных данных и перенаправлений.
Все хеши проверяются до публикации. Исходные файлы не исполняются, ссылки из них
не загружаются. Несовпадение хеша, некорректный UTF-8 или манифест, пересечение
байтов между выборками и ошибка загрузки сохраняют прежний выходной файл.
Лимиты: манифест 256 КиБ, 4096 файлов, 1 МиБ на файл и 8 МиБ итогового JSON.

Для сборки без сети замените `url` файла на `local`, сохранив `sha256`.
Относительные пути считаются от каталога манифеста. Потоки, устройства и симлинки
исходных файлов отвергаются; результат не может перезаписать манифест или локальный
источник. Исходные лицензии сохраняются в составе каждого примера.

Подготовьте отдельный незаполненный файл рецензии, привязанный к точным байтам корпуса:

```sh
bin/scout-dev corpus review-template --corpus /tmp/scout-external-corpus.json \
  --output /tmp/scout-label-review.json
```

Рецензент заполняет каждый пример: метка `signal`, `benign` или `ambiguous`,
`reviewer_id`, время `reviewed_at` в RFC3339 не из будущего, обоснование и 1..8 ссылок
на доказательства. Ссылки требуют HTTPS без учётных данных и параметров запроса;
они сохраняются как данные, но не загружаются. Начальные метки `pending` и пустые
поля не принимаются за готовую рецензию. Установите `independent: true` только после
независимой разметки. Идентификаторы рецензентов и независимость остаются
декларациями, а не аутентификацией личности или доказательством качества меток.
Семейства источников должны оставаться в одной выборке, хеши байтов — сохраняться.

При измерении явно выберите готовую рецензию и доверенные идентификаторы рецензентов.
Даже изменение форматирования JSON корпуса нарушает привязку SHA-256; изменение
или повторный сбор источников требует новой проверки. Исходный корпус не меняется:
метки и эффективный тип корпуса применяются в памяти.

```sh
bin/scout-dev evaluate --split holdout --require-independent \
  --label-review /tmp/scout-label-review.json \
  --trusted-label-reviewer operator-selected-reviewer \
  --min-recall 0.9 --max-fpr 0.05 --max-incomplete 0 /tmp/scout-external-corpus.json
```

Метрики сохраняются в stdout и при нарушении порогов. Код 1 означает непройденные
пороги, код 2 — неверный запрос или незавершённое измерение. Неопределённые метрики
не проходят пороги. Одного названия корпуса или свободного текста
`sources[].label_review` недостаточно для `--require-independent`. В отчёте остаются
хеши рецензии и корпуса, выбранные идентификаторы рецензентов и число проверенных
примеров; обоснования и ссылки не выводятся. Независимое измерение точности здесь
не предоставляется.
