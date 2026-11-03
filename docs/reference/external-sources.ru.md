# Внешние источники, registry и подписи

[English](external-sources.md) · Русский

Эти возможности требуют явной конфигурации оператора. Проверяемый пакет
не может включить сеть или выбрать доверенный ключ.

## Ограниченный обход ссылок

```sh
scout scan --allow-download --follow-external \
  --external-origin https://raw.githubusercontent.com \
  --external-depth 2 --external-max-requests 16 --external-max-bytes 4194304 \
  --format json ./my-plugin
```

Обход требует `--follow-external` и `--allow-download`.
Повторяемый `--external-origin` заменяет стандартные origin GitHub точным списком разрешённых origin.
Origin включает схему, узел и необязательный порт; путь должен быть пустым или `/`.
Обход не проверяет, что буквальный URL файла указывает на неизменяемый коммит.
Для загрузки корня GitHub-репозитория как отдельного входа нужен полный SHA коммита через `--revision`.

Поддерживаемые URL, записанные буквально, захватываются в `.scout-external/` и проходят обычное
сканирование. Отчёт сохраняет ссылки на исходные данные, хеши и результаты.
Циклы исключаются; ошибки чтения и исчерпанные квоты остаются пробелами.
Динамические URL и разрешение зависимостей менеджером пакетов в обход не входят.

## MCP Registry

```sh
scout registry fetch --allow-download --name org.example/tool --latest \
  --endpoint https://registry.modelcontextprotocol.io/v0.1/servers \
  --output /ci/registry-current.json
scout registry compare --output /ci/registry-delta.json \
  /ci/registry-previous.json /ci/registry-current.json
scout scan --format json /ci/registry-current.json
```

Команда fetch создаёт ограниченный снимок данных. `--latest` использует утверждение
реестра `isLatest`. Сравнение сопоставляет имя и версию, отвергая неполные снимки.
Запись реестра не является разрешением установки.

## Проверка DSSE/in-toto

```sh
scout attestation verify --public-key /ci/trusted-signer.pem \
  --envelope ./bundle.oms.sig --artifact ./bundle.zip --subject bundle.zip
```

Проверяются хеш выбранного артефакта и субъект по одному явно доверенному
открытому ключу в формате PKIX. Поддерживаются Ed25519, P-256 ECDSA и RSA-PSS.
Поддерживаются отдельный DSSE и OMS `dsseEnvelope` для in-toto Statement v1/v0.1.

Код 0 означает согласованность подписи, ключа и артефакта, 1 — несовпадение подписи
или субъекта, 2 — некорректный вход или операционную ошибку. Полная проверка
идентичности Sigstore, журнала прозрачности и политики отзыва не реализована.

## AISOP/AISP и OMS

Декларации AISOP/AISP становятся хешированными метаданными с привязкой к исходнику.
Содержимое OMS и выбранные утверждения X.509 извлекаются как недоверенные данные.
Разбор сертификата не проверяет доверие к подписанту.
