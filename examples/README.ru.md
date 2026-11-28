# Примеры

[English](README.md) · Русский

- [Конфигурации](configs/README.ru.md): обычная проверка, CI, несколько входов,
  core-сборка, поиск уязвимостей и шаблон LLM-review с командами запуска.
- [Пример использования Go API](go-api/README.ru.md).
- [Проверка пакета в GitHub Actions](scout-package-review.yml) со сводкой в PR и
  [настройкой одобрения по хешу](../docs/user/update-review.ru.md#сводка-в-pr-и-одобрение-пакета).
- [Проверка пакета в GitLab CI](scout-package-review.gitlab-ci.yml) со сводкой
  в [артефакте merge request](../docs/user/update-review.ru.md#merge-requests-в-gitlab).

Выполняйте команды из корня репозитория. Замените `./my-skill` путём к вашему навыку
или плагину. Храните конфигурацию и отчёты вне проверяемого входа.

Сканирование, сравнение, stdin, запись отчётов и baseline описаны
в [руководстве CLI](../docs/user/usage.ru.md), все флаги —
в [справочнике CLI](../docs/reference/cli.ru.md).
