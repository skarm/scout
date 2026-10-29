# Runtime-проверка базы знаний

[English](knowledge-runtime.md) · Русский

Проверки используют локальный scripted provider для доставки инструкций
и привязки ссылок к исходникам. Они не измеряют качество классификации настоящей модели.

## Что проверяется

- Статические находки получают ожидаемые встроенные пояснения.
- Цепочка scan/provider/validator/assessment/report сохраняет тему и доказательства.
- Неизвестные темы, неверные modes и поддельные citations отвергаются.
- Форматы отчёта сохраняют пояснения без копирования секретов в семантический вывод.

[Тестовый корпус](../../testdata/knowledge-runtime/README.md) содержит опасные
и допустимые примеры, включая SQL-темы. Их код не исполняется.

## Запуск

```sh
go test -mod=readonly -tags=coreonly -run 'TestKnowledge' -v ./tests/scan
go test -mod=readonly -tags=static_link -run 'TestKnowledge' -v ./tests/scan
go test -mod=readonly -tags=coreonly ./internal/analysis/semantic ./knowledge ./review
```

HTTP fixtures требуют доступа к loopback. Для сохранения JSON-отчётов бинарника:

```sh
go run -tags=coreonly ./cmd/scout-dev check-knowledge-runtime --binary "$(command -v scout)" --output /tmp/new-native-runtime-run
go run -tags=coreonly ./cmd/scout-dev check-knowledge-runtime --binary "$(command -v scout-core)" --output /tmp/new-core-runtime-run
```

Используйте новый каталог вывода. Входы передаются только локальному fixture server.
Полные core/native suites и race запускайте отдельно без фильтров.
