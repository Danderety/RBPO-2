# Экспертная оценка безопасности

Практическая работа 2. Анализ Python, C++ и JavaScript. Датасет содержит 12 находок и 9 классов CWE.

## Сводка найденных уязвимостей

| ID | Язык | Тип | CWE | OWASP 2021 | CVSS 3.1 | Критичность |
|---|---|---|---|---|---:|---|
| PY-01 | Python | SQL Injection | CWE-89 | A03:2021 | 8.2 | High |
| PY-02 | Python | Stored XSS | CWE-79 | A03:2021 | 6.1 | Medium |
| PY-03 | Python | Missing Authorization / IDOR | CWE-862 | A01:2021 | 6.5 | Medium |
| CPP-01 | C++ | Buffer Overflow | CWE-120 | N/A | 5.5 | Medium |
| CPP-02 | C++ | Format String | CWE-134 | N/A | 7.8 | High |
| CPP-03 | C++ | OS Command Injection | CWE-78 | N/A | 7.8 | High |
| JS-01 | JavaScript | SQL Injection | CWE-89 | A03:2021 | 5.3 | Medium |
| JS-02 | JavaScript | Reflected XSS | CWE-79 | A03:2021 | 6.1 | Medium |
| JS-03 | JavaScript | OS Command Injection | CWE-78 | A03:2021 | 9.8 | Critical |
| CPP-04 | C++ | NULL Pointer Dereference | CWE-476 | N/A | 5.5 | Medium |
| PY-04 | Python | Use of Hard-coded Cryptographic Key | CWE-321 | A02:2021 | 9.1 | Critical |
| PY-05 | Python | Plaintext Storage of a Password | CWE-256 | A04:2021 | 5.5 | Medium |

## Выводы и приоритеты

Сначала устраняются выполнение команд через JavaScript, известный ключ подписи сессий и SQL-инъекция входа. Далее закрываются доступ к чужим заказам, XSS и открытое хранение паролей. Приоритет C++ зависит от прав процесса и источника ввода.

## Рекомендации

Python: параметры SQL, автоэкранирование Jinja, проверка владельца, случайный ключ и хеширование паролей. C++: std::string, постоянный формат printf, отказ от system и проверка указателей. JavaScript: параметры SQLite, кодирование HTML и execFile с проверкой адреса.

## Основания оценок и ограничения

CVSS рассчитан по приведённым в CSV/JSON векторам для учебной модели; это не баллы сканеров и не оценки сторонних CVE. Категории C++ из методички сохранены в owasp_assignment, а техническая применимость обозначена N/A. PY-04 и PY-05 подтверждены статически, CPP-04 — отдельными запусками. Исходные 30 динамических проверок сохранены отдельно от дополнительных протоколов.

Подробности, допущения и источники: [отчёт участника 6](reports/participant-06/report.md). Соответствие каждому пункту задания: [сверка](ASSIGNMENT_COMPLIANCE.md).

## Доказательства и исправления

### PY-01 — SQL Injection

Имя admin' -- исключает проверку пароля из SQL; получен доступ к заказу администратора.

**Исправление:** Параметризованный запрос и check_password_hash.

**Подтверждение:** [confirmed_dynamic](reports/participant-02/evidence/vulnmart-sqli.json). SQLi подтверждена HTTP; изменение данных не проверялось, I:L учитывает действия под чужой учётной записью.

**CVE-аналог:** [CVE-2023-25157](https://geoserver.org/vulnerability/2023/02/20/ogc-filter-injection.html). SQL-инъекция GeoServer; аналог класса, другой продукт и путь ввода.

### PY-02 — Stored XSS

Комментарий с script сохраняется и возвращается другому клиенту без экранирования.

**Исправление:** Удалить фильтр safe; оставить автоэкранирование Jinja.

**Подтверждение:** [confirmed_http_and_browser_replay](reports/participant-02/evidence/vulnmart-stored-xss.json). Сохранённый HTTP-ответ исполнен в изолированном браузере; маркер XSS сработал. Повторный полный запуск веб-приложения в браузере не выполнялся.

**CVE-аналог:** [CVE-2020-11022](https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2). XSS в обработке HTML jQuery; аналог класса, не та же разновидность/реализация.

### PY-03 — Missing Authorization / IDOR

Пользователь sarah читает заказ admin по /order/1.

**Исправление:** Ограничить SQL по id заказа и user_id из серверной сессии.

**Подтверждение:** [confirmed_dynamic](reports/participant-02/evidence/vulnmart-idor.json). Подтверждена утечка чужого заказа; изменение заказа не проверялось.

**CVE-аналог:** [CVE-2023-22515](https://confluence.atlassian.com/security/cve-2023-22515-broken-access-control-vulnerability-in-confluence-data-center-and-server-1295682276.html). Аналог категории Broken Access Control; создание администратора в Confluence не тождественно IDOR.

### CPP-01 — Buffer Overflow

strcpy копирует 64 символа в буфер на 10 байт; ASan выявил stack-buffer-overflow.

**Исправление:** std::string вместо фиксированного буфера.

**Подтверждение:** [confirmed_dynamic](reports/participant-03/evidence/cpp-harness-copy-long.json). Подтверждены выход за границу стека и аварийное завершение. RCE не демонстрировалось.

**CVE-аналог:** [CVE-2021-3156](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit). Родственная ошибка безопасности памяти: в sudo переполнение кучи, в примере стек. Не точное совпадение CWE.

### CPP-02 — Format String

Ввод %% интерпретируется как формат и печатает один %.

**Исправление:** printf("%s", input) с постоянной строкой формата.

**Подтверждение:** [confirmed_dynamic](reports/participant-03/evidence/cpp-harness-format-short.json). Подтверждена интерпретация формата. Утечка памяти, запись через %n и RCE не выполнялись; C/I/A:H — потенциальное воздействие модели.

**CVE-аналог:** [CVE-2012-0809](https://nvd.nist.gov/vuln/detail/CVE-2012-0809). Форматная строка sudo_debug; sudo имеет иную модель привилегий.

### CPP-03 — OS Command Injection

Ввод x;printf RBPO_CMD приводит к выполнению второй команды.

**Исправление:** Для вывода текста не вызывать shell; использовать std::cout.

**Подтверждение:** [confirmed_dynamic](reports/participant-03/evidence/cpp-harness-command-short.json). Подтверждено выполнение безвредной команды; повышение привилегий не проверялось.

**CVE-аналог:** [CVE-2020-11981](https://github.com/advisories/GHSA-976r-qfjj-c24w). Инъекция команд через брокер Celery в Airflow; другой канал ввода.

### JS-01 — SQL Injection

Ввод ' OR 1=1 -- изменяет предикат и возвращает запись admin.

**Исправление:** Плейсхолдер ? и массив параметров SQLite.

**Подтверждение:** [confirmed_dynamic](reports/participant-04/evidence/vulnerable.js-sqli.json). Подтверждено изменение запроса и чтение записи; endpoint не является формой входа.

**CVE-аналог:** [CVE-2023-25157](https://geoserver.org/vulnerability/2023/02/20/ogc-filter-injection.html). SQL-инъекция GeoServer; аналог класса, другой продукт и путь ввода.

### JS-02 — Reflected XSS

Параметр name попадает в HTML без кодирования.

**Исправление:** Контекстное экранирование HTML-текста.

**Подтверждение:** [confirmed_http_and_browser_replay](reports/participant-04/evidence/vulnerable.js-xss.json). Сохранённый HTTP-ответ исполнен в изолированном браузере; маркер XSS сработал. Повторный полный запуск веб-приложения в браузере не выполнялся.

**CVE-аналог:** [CVE-2020-11022](https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2). XSS в обработке HTML jQuery; аналог класса, не та же разновидность/реализация.

### JS-03 — OS Command Injection

Параметр host содержит ; printf RBPO_CMD и запускает дополнительную команду.

**Исправление:** execFile без shell; проверка типа, IP и разрешённых адресов.

**Подтверждение:** [confirmed_dynamic](reports/participant-04/evidence/vulnerable.js-command.json). Подтвержден вывод маркера из shell; C/I/A:H — потенциальные права процесса.

**CVE-аналог:** [CVE-2020-11981](https://github.com/advisories/GHSA-976r-qfjj-c24w). Инъекция команд через брокер Celery в Airflow; другой канал ввода.

### CPP-04 — NULL Pointer Dereference

Передача nullptr в process_data вызывает нарушение доступа; обычный указатель обрабатывается.

**Исправление:** Проверить data на nullptr до разыменования.

**Подтверждение:** [confirmed_dynamic](reports/participant-03/evidence/null_pointer-null.json). Подтверждено аварийное завершение отдельного процесса; удалённая достижимость не заявляется.

**CVE-аналог:** [CVE-2023-3316](https://nvd.nist.gov/vuln/detail/CVE-2023-3316). NULL pointer в libtiff TIFFClose; совпадает класс ошибки, но не продукт и путь ввода.

### PY-04 — Use of Hard-coded Cryptographic Key

Ключ подписи Flask-сессии задан публичной строкой в исходнике.

**Исправление:** Случайный секрет вне исходников; в учебном fixed ключ создаётся при запуске.

**Подтверждение:** [confirmed_static](reports/participant-01/evidence/static-session-key.json). Подтверждено AST-проверкой и исходным B105; подделка сессии не выполнялась. C/I:H — допущение модели.

**CVE-аналог:** [CVE-2022-29960](https://cwe.mitre.org/data/definitions/321.html). Пример MITRE: постоянные криптографические ключи в инженерной станции; иной продукт и назначение ключа.

### PY-05 — Plaintext Storage of a Password

Учебные пароли напрямую записываются в users и сравниваются без хеширования.

**Исправление:** generate_password_hash при записи и check_password_hash при входе.

**Подтверждение:** [confirmed_static](reports/participant-01/evidence/static-plaintext-passwords.json). Подтверждён поток данных в исходнике; CVSS предполагает локальное чтение БД, а не самостоятельный сетевой обход.

**CVE-аналог:** [CVE-2022-30275](https://cwe.mitre.org/data/definitions/256.html). Пример MITRE: открытое хранение пароля в драйвере RTU; другой продукт, тот же класс хранения.

