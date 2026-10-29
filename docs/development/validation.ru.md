# Проверки

[English](validation.md) · Русский

Запускайте команды из корня проекта. Полный набор требует
[нативных зависимостей](native-build.ru.md).

## Тесты

```sh
make test-core
make test
make race
make host-test
```

`test-core` проверяет сокращённую сборку и недоступность движков. `test` и `race`
проверяют нативные parsers и сигнатуры. `host-test` требует Node и проверяет
адаптеры на SDK fixtures и настоящем CLI. Go tests не требуют Python.

Make test-цели используют `-vet=off`; линтер запускается отдельно.

## Приёмка бинарника и исходников

```sh
make releasecheck
make acceptance
```

`releasecheck` проверяет linkage, metadata и нативные selftests бинарника.
`acceptance` сверяет состав исходников, IDs входов, replay, releasecheck
и разобранные изменения наблюдений с `testdata/provenance/scout-current-review.json`.
Native CI требует этой приёмки.

Receipt хеширует полные байты исходников: правка Go-комментариев тоже делает его
неактуальным. Получайте свежие доказательства через [provenance-команды](commands.ru.md#source-bound-provenance),
без подмены сохранённых хешей. Входы в `testdata/` сохраняются после `make clean`.

## Линтер

```sh
make lint
```

Матрица по умолчанию включает core для `darwin/arm64`, `linux/amd64`,
`freebsd/amd64`, `windows/amd64`, а также non-CGO и native на текущем host.
Каждый запуск включает tag `acceptance`. Матрицу меняет `LINT_PLATFORMS`.
Отдельные цели: `lint-core`, `lint-nocgo`, `lint-native`.

## Интерпретация результатов

Регрессии и scripted providers проверяют поведение реализации, без измерения
качества настоящей модели или независимой точности детекции.
См. [измерения](evaluation.ru.md) и [runtime-проверки знаний](../reference/knowledge-runtime.ru.md).
Реальные host и целевые платформы требуют отдельной приёмки.
