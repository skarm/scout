# Проверка использования базы знаний

[English](knowledge-runtime.md) · Русский

Проверки используют локальный провайдер с заданными ответами. Они проверяют доставку
инструкций и привязку ссылок к исходникам, без измерения качества классификации настоящей модели.

## Что проверяется

- Статические находки получают ожидаемые встроенные пояснения.
- Цепочка сканирования, вызова провайдера, валидации, оценки и отчёта сохраняет тему и доказательства.
- Неизвестные темы, неверные режимы и поддельные ссылки на фрагменты отвергаются.
- Форматы отчёта сохраняют пояснения без копирования секретов в семантический вывод.

[Тестовый корпус](../../testdata/knowledge-runtime/README.md) содержит опасные
и допустимые примеры, включая SQL-темы. Их код не исполняется.

## Запуск

```sh
go test -mod=readonly -tags=coreonly -run 'TestKnowledge' -v ./tests/scan
go run -mod=readonly ./internal/dev/builddeps -- \
  go test -mod=readonly -tags=static_link -run 'TestKnowledge' -v ./tests/scan
go test -mod=readonly -tags=coreonly ./internal/analysis/semantic ./knowledge ./review
```

Тестовые HTTP-серверы требуют доступа к loopback-адресам. Чтобы сохранить JSON-отчёты бинарника:

```sh
go run -tags=coreonly ./cmd/scout-dev check-knowledge-runtime --binary "$(command -v scout)" --output /tmp/new-native-runtime-run
go run -tags=coreonly ./cmd/scout-dev check-knowledge-runtime --binary "$(command -v scout-core)" --output /tmp/new-core-runtime-run
```

Используйте новый каталог вывода. Входы передаются только локальному тестовому серверу.
Полные наборы core/native и проверки гонок запускайте отдельно без фильтров.
