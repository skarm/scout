# Внешние источники, registry и подписи

[English](external-sources.md) · Русский

Эти возможности требуют явной конфигурации оператора. Проверяемый пакет
не может включить сеть или выбрать доверенный ключ.

## Ограниченный обход ссылок

```sh
scout scan --allow-download --follow-external \
  --external-origin https://raw.githubusercontent.com \
  --external-depth 2 --external-max-requests 16 --external-max-bytes 4194304 \
  --format json -- ./my-plugin
```

Обход требует `--follow-external` и `--allow-download`.
Повторяемый `--external-origin` заменяет стандартные GitHub origins точным allowlist.
GitHub-репозитории требуют неизменяемый commit.

Поддержанные буквальные URL захватываются в `.scout-external/` и проходят обычное
сканирование. Отчёт сохраняет source references, хеши и результаты.
Циклы исключаются; ошибки чтения и исчерпанные квоты остаются пробелами.
Динамические URL и разрешение зависимостей package manager в обход не входят.

## MCP Registry

```sh
scout registry fetch --allow-download --name org.example/tool --latest \
  --endpoint https://registry.modelcontextprotocol.io/v0.1/servers \
  --output /ci/registry-current.json
scout registry compare --output /ci/registry-delta.json \
  /ci/registry-previous.json /ci/registry-current.json
scout scan --format json -- /ci/registry-current.json
```

Fetch создаёт ограниченный снимок данных. `--latest` использует утверждение
registry `isLatest`. Сравнение сопоставляет name/version и отвергает неполные снимки.
Запись registry не является разрешением установки.

## Проверка DSSE/in-toto

```sh
scout verify-attestation --public-key /ci/trusted-signer.pem \
  --envelope ./bundle.oms.sig --artifact ./bundle.zip --subject bundle.zip
```

Проверяются выбранный artifact digest и subject по одному явно доверенному
PKIX public key. Поддержаны Ed25519, P-256 ECDSA и RSA-PSS.
Standalone DSSE и OMS `dsseEnvelope` поддерживают in-toto Statement v1/v0.1.

Код 0 означает совпадение подписи/ключа/артефакта, 1 — signature/subject mismatch,
2 — некорректный вход или операционную ошибку. Полная Sigstore identity,
transparency-log и revocation policy не реализованы.

## AISOP/AISP и OMS

Декларации AISOP/AISP становятся хешированными metadata с привязкой к исходнику.
OMS payloads и выбранные X.509 claims извлекаются как недоверенное содержимое.
Разбор сертификата не проверяет доверие к подписанту.
