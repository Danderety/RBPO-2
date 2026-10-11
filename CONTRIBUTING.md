# Добавление материалов в GitHub

Комплект разбит на шесть непересекающихся пакетов. Каждый содержит готовые файлы,
пути которых совпадают с путями будущего репозитория. Программы для загрузки
материалов запускать не требуется. Список файлов каждого пакета находится
в приложенном `PACKAGES.md` внешнего комплекта.

## Создание репозитория

Владелец создаёт пустой репозиторий `rbpo-pr2` в своём GitHub-аккаунте без README,
лицензии и gitignore, затем добавляет остальных участников как collaborators.
Ссылка заранее неизвестна; во всех командах замените OWNER на GitHub-логин владельца.
Ни URL, ни токены, ни чужие подписи не входят в комплект.

Участник 1 распаковывает содержимое своего пакета в новый каталог, переходит в него
и выполняет:

```bash
git init -b main
git add README.md CONTRIBUTING.md .gitignore projects/python/vulnmart projects/python/UPSTREAM.md projects/python/requirements-lock.txt scripts/common.py scripts/scan.py scripts/setup-arch.sh reports/Шмеркович
git diff --cached --stat
git commit -m "Добавить VulnMart, инфраструктуру и результаты SAST"
git remote add origin https://github.com/OWNER/rbpo-pr2.git
git push -u origin main
```

Почта и имя Git должны принадлежать самому участнику. Указание автора загрузки
файлов не меняет происхождение upstream-кода или авторство уже готовых материалов.

## Остальные пять пакетов

Проще добавлять пакеты последовательно: 2, 3, 4, 5, 6. Для каждого участника:

1. Клонировать актуальный репозиторий.
2. Создать свою ветку от текущей main.
3. Распаковать только свой пакет в корень клона, сохранив пути.
4. Заменить обозначение ответственного своим ФИО в собственном report.md.
5. Добавить только перечисленные файлы, сделать коммит и отправить ветку.
6. Открыть pull request; владелец проверяет изменения и объединяет его.

Пример для участника 2:

```bash
git clone https://github.com/OWNER/rbpo-pr2.git
cd rbpo-pr2
git switch -c Хрусталев
# Сейчас скопируйте содержимое Хрусталев.zip в этот каталог.
git add scripts/check_python.py scripts/check_xss_browser.cjs reports/Хрусталев
git diff --cached --stat
git commit -m "Добавить HTTP-проверки и отчёт по VulnMart"
git push -u origin Хрусталев
```

| Пакет | Пути для git add | Сообщение коммита |
|---|---|---|
| 3 | projects/cpp/vulnerable.cpp projects/cpp/harness.cpp projects/cpp/null_pointer.cpp scripts/check_cpp.py scripts/check_additions.py reports/Ульянов | Добавить C++-пример и доказательства дефектов памяти и команд |
| 4 | projects/javascript/vulnerable.js projects/javascript/package.json projects/javascript/package-lock.json projects/javascript/eslint.config.cjs scripts/check_js.py reports/Чихладзе | Добавить JavaScript-пример, ESLint и HTTP-проверки |
| 5 | projects/python/fixed projects/cpp/fixed.cpp projects/cpp/null_pointer_fixed.cpp projects/javascript/fixed.js scripts/verify.py scripts/run-all.sh reports/Шумков | Добавить исправления и результаты повторных проверок |
| 6 | datasets scripts/build_dataset.py scripts/validate_delivery.py expert_assessment.md ASSIGNMENT_COMPLIANCE.md reports/Прядко | Добавить датасеты и экспертную оценку |

Полная работоспособность ожидается после всех шести пакетов: отдельные пакеты
ссылаются на общие файлы, которые появятся позже. Ранние ссылки в README временно
могут вести на ещё не добавленные разделы.

## Перед сдачей

В репозитории должны присутствовать все шесть report.md, три проекта, фиксированные
варианты, датасеты и evidence. Замените имена участников и при необходимости название
группы. Экспертное заключение находится в expert_assessment.md и подробно разобрано в report.md участника 6.

Не добавляйте node_modules, .venv, базы данных, бинарники и core dumps. Они исключены
через .gitignore. Не меняйте даты и авторов готовых протоколов: они отражают одну
фактическую среду подготовки. Количество коммитов не является измерением вклада;
предлагаемые сообщения описывают добавление конкретных материалов.
