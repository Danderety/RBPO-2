**Анализ JavaScript приложения**  
**Подготовка примера**  
Основа — Express и SQLite из методички, маршруты /user, /hello, /ping сохранены.  
   
 Добавлена таблица users с синтетическими записями admin и alice. Сервер начинает  
   
 слушать только после инициализации БД; ошибки запросов получают явные ответы.  
   
 Без этих дополнений SQL-пример не был бы воспроизводимым. Слушающий адрес ограничен  
   
 127.0.0.1, а выполнение команды имеет тайм-аут три секунды.  
Раздел включает vulnerable.js, package.json, package-lock.json,  
   
 eslint.config.cjs, scripts/check_js.py и результаты проверок. node_modules  
   
 не передаётся в Git. Lock-файл фиксирует именно учебную сборку, не означает,  
   
 что все транзитивные зависимости прошли аудит безопасности.  
npm ci --prefix projects/javascript  
 .venv/bin/python scripts/verify.py --only js  
   
**Найденные дефекты**  
**JS-01 SQL Injection**  
Исходник: [projects/javascript/vulnerable.js, строка **9**.  
   
 Классификация: **CWE-89**, OWASP  **A03:2021**.](../../projects/javascript/vulnerable.js "../../projects/javascript/vulnerable.js")  
Ввод ' OR 1=1 -- изменяет предикат и возвращает запись admin.  
**Доказательство:** [результат проверки. Подтверждено изменение запроса и чтение записи; endpoint не является формой входа.](../../reports/participant-04/evidence/vulnerable.js-sqli.json "../../reports/participant-04/evidence/vulnerable.js-sqli.json")  
**Исправление:** Плейсхолдер ? и массив параметров SQLite.  
**Модельная оценка:** CVSS 5.3 (Medium), CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N.  
   
 Допущения модели описаны в [разделе 6.](../participant-06/report.md "../participant-06/report.md")  
**Реальный пример:** [CVE-2023-25157. SQL-инъекция GeoServer; аналог класса, другой продукт и путь ввода.](https://geoserver.org/vulnerability/2023/02/20/ogc-filter-injection.html "https://geoserver.org/vulnerability/2023/02/20/ogc-filter-injection.html")  
**JS-02 Reflected XSS**  
Исходник: [projects/javascript/vulnerable.js, строка **16**.  
   
 Классификация: **CWE-79**, OWASP  **A03:2021**.](../../projects/javascript/vulnerable.js "../../projects/javascript/vulnerable.js")  
Параметр name попадает в HTML без кодирования.  
**Доказательство:** [результат проверки. Подтверждено отражение тега script в HTML; первоначально проверялся HTML, позднее добавлено браузерное воспроизведение (см. дополнение).](../../reports/participant-04/evidence/vulnerable.js-xss.json "../../reports/participant-04/evidence/vulnerable.js-xss.json")  
**Исправление:** Контекстное экранирование HTML-текста.  
**Модельная оценка:** CVSS 6.1 (Medium), CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N.  
   
 Допущения модели описаны в [разделе 6.](../participant-06/report.md "../participant-06/report.md")  
**Реальный пример:** [CVE-2020-11022. XSS в обработке HTML jQuery; аналог класса, не та же разновидность/реализация.](https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2 "https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2")  
**JS-03 OS Command Injection**  
Исходник: [projects/javascript/vulnerable.js, строка **21**.  
   
 Классификация: **CWE-78**, OWASP  **A03:2021**.](../../projects/javascript/vulnerable.js "../../projects/javascript/vulnerable.js")  
Параметр host содержит ; printf RBPO_CMD и запускает дополнительную команду.  
**Доказательство:** [результат проверки. Подтвержден вывод маркера из shell; C/I/A:H — потенциальные права процесса.](../../reports/participant-04/evidence/vulnerable.js-command.json "../../reports/participant-04/evidence/vulnerable.js-command.json")  
**Исправление:** execFile без shell; проверка типа, IP и разрешённых адресов.  
**Модельная оценка:** CVSS 9.8 (Critical), CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.  
   
 Допущения модели описаны в [разделе 6.](../participant-06/report.md "../participant-06/report.md")  
**Реальный пример:** [CVE-2020-11981. Инъекция команд через брокер Celery в Airflow; другой канал ввода.](https://github.com/advisories/GHSA-976r-qfjj-c24w "https://github.com/advisories/GHSA-976r-qfjj-c24w")  
**Статический анализ**  
ESLint 9.22.0 использован с eslint-plugin-security 3.0.1 и рекомендуемыми правилами.  
   
 В [eslint.json исходник получает security/detect-child-process  
   
 на вызов exec. SQLi и XSS этим набором правил не выявлены, поэтому их подтверждают  
   
 HTTP-сценарии и ручной разбор потока данных.](evidence/eslint.json "evidence/eslint.json")  
Исправленный файл получает security/detect-object-injection на таблицу HTML-сущностей.  
   
 Это ложное срабатывание: ключ ch приходит исключительно из регулярного выражения  
   
 [&<>"'], набор ключей ограничен пятью символами. Предупреждение сохранено и разобрано,  
   
 а не удалено из результата. Назначение и ограничения плагина описаны в  
   
 [репозитории правил.](https://github.com/eslint-community/eslint-plugin-security "https://github.com/eslint-community/eslint-plugin-security")  
**Динамические результаты и вывод**  
Шесть проверок исходника прошли: SQLi, обычное имя alice, отсутствующее имя,  
   
 небезопасный HTML, инъекция команды и обычное приветствие. В SQL-примере возвращается  
   
 строка пользователя, но сессия не создаётся; это изменение SQL-предиката, а не вход  
   
 в приложение. Для команды проверяется только безвредный маркер RBPO_CMD.  
В среде подготовки отсутствует ping. Уязвимая команда всё равно выполняет  
   
 добавленный после ; встроенный printf. Поэтому тест доказывает инъекцию, но  
   
 не работоспособность сетевой диагностики. В исправленной версии вредоносный адрес  
   
 отклоняется до запуска процесса. Положительный ICMP-сценарий не проверен;  
   
 Arch-скрипт устанавливает iputils для такого воспроизведения.  
**Вопросы к защите**  
- Почему одного ESLint недостаточно? Набор security-правил не является полноценным taint-анализом SQL и HTML.  
- Чем execFile отличается от exec? Аргументы передаются процессу отдельно, без разбора shell.  
- Зачем ещё проверять IP? Отсутствие shell не определяет, какие адреса приложение вправе проверять.  
**Дополнение браузерного подтверждения XSS**  
17 сентября 2026 года HTML из сохранённого HTTP-протокола был исполнен в новом  
   
 контексте Edge. Маркер window.RBPO_XSS сработал; внешние запросы блокировались.  
   
 [Браузерный протокол содержит версию браузера,  
   
 время, результат и SHA-256 исходного HTTP-протокола. Соответствующий исправленный  
   
 ответ проверен тем же способом: скрипт не исполняется.  
   
 Это дополняет прежнюю HTTP-проверку, но не является новым полным прогоном сервера.](evidence/vulnerable.js-xss-browser-replay.json "evidence/vulnerable.js-xss-browser-replay.json")  
