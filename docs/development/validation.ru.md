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

## Бинарник и сохранённые измерения

```sh
make releasecheck
make acceptance
```

`releasecheck` проверяет linkage, metadata и нативные selftests бинарника.
`acceptance` проверяет целостность сохранённых IDs входов, replay, releasecheck
и разобранных изменений наблюдений в `testdata/provenance/scout-current-review.json`.
Проверяется записанное измерение, без требования совпадения с сегодняшними исходниками.
Native CI выполняет эту проверку вместе с тестами текущего кода.

Правки кода и комментариев не требуют обновления receipts. Хеши исходников остаются
метаданными измеренной версии. Явная проверка `provenance verify --current-sources`
при необходимости сверяет запись с текущими исходниками. Новое измерение создаётся
через [provenance-команды](commands.ru.md#source-bound-provenance), когда нужно обновить
сохранённые результаты. Входы в `testdata/` сохраняются после `make clean`.

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
