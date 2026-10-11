**Анализ уязвимостей C плюс плюс**  
**Исходный пример и запуск**  
Сохранены три функции и последовательный main из методички. Добавлены заголовок  
   
 cstdlib, комментарии с идентификаторами и условная компиляция для стенда.  
   
 harness.cpp вызывает исходные функции по отдельности: авария в strcpy не мешает  
   
 проверить printf и system. Код функций при этом не подменяется.  
Подготовлены projects/cpp/vulnerable.cpp, projects/cpp/harness.cpp и  
   
 scripts/check_cpp.py. Исправленная версия отнесена к разделу участника 5.  
g++ -Wall -Wextra -g -std=c++17 -o build/original projects/cpp/vulnerable.cpp  
 .venv/bin/python scripts/verify.py --only cpp  
   
Для первой команды каталог build должен существовать; полный скрипт создаёт его.  
   
 Диагностическая сборка harness использует AddressSanitizer и UndefinedBehaviorSanitizer.  
   
 -no-pie относится только к демонстрационной диагностической сборке.  
   
 Проверка утечек памяти отключена через ASAN_OPTIONS=detect_leaks=0, поскольку  
   
 LeakSanitizer не может читать нужные записи /proc в среде подготовки. Проверка  
   
 выхода за границы памяти остаётся включённой.  
**Найденные дефекты**  
**CPP-01 Buffer Overflow**  
Исходник: [projects/cpp/vulnerable.cpp, строка **10**.  
   
 Классификация: **CWE-120**, OWASP  **N/A**.](../../projects/cpp/vulnerable.cpp "../../projects/cpp/vulnerable.cpp")  
strcpy копирует 64 символа в буфер на 10 байт; ASan выявил stack-buffer-overflow.  
**Доказательство:** [результат проверки. Подтверждены выход за границу стека и аварийное завершение. RCE не демонстрировалось.](../../reports/Ульянов/evidence/cpp-harness-copy-long.json "../../reports/Ульянов/evidence/cpp-harness-copy-long.json")  
**Исправление:** std::string вместо фиксированного буфера.  
**Модельная оценка:** CVSS 5.5 (Medium), CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H.  
   
 Допущения модели описаны в [разделе 6.](../Прядко/report.md "../Прядко/report.md")  
**Реальный пример:** [CVE-2021-3156. Родственная ошибка безопасности памяти: в sudo переполнение кучи, в примере стек. Не точное совпадение CWE.](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit "https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit")  
**CPP-02 Format String**  
Исходник: [projects/cpp/vulnerable.cpp, строка **14**.  
   
 Классификация: **CWE-134**, OWASP  **N/A**.](../../projects/cpp/vulnerable.cpp "../../projects/cpp/vulnerable.cpp")  
Ввод %% интерпретируется как формат и печатает один %.  
**Доказательство:** [результат проверки. Подтверждена интерпретация формата. Утечка памяти, запись через %n и RCE не выполнялись; C/I/A:H — потенциальное воздействие модели.](../../reports/Ульянов/evidence/cpp-harness-format-short.json "../../reports/Ульянов/evidence/cpp-harness-format-short.json")  
**Исправление:** printf("%s", input) с постоянной строкой формата.  
**Модельная оценка:** CVSS 7.8 (High), CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H.  
   
 Допущения модели описаны в [разделе 6.](../Прядко/report.md "../Прядко/report.md")  
**Реальный пример:** [CVE-2012-0809. Форматная строка sudo_debug; sudo имеет иную модель привилегий.](https://nvd.nist.gov/vuln/detail/CVE-2012-0809 "https://nvd.nist.gov/vuln/detail/CVE-2012-0809")  
**CPP-03 OS Command Injection**  
Исходник: [projects/cpp/vulnerable.cpp, строка **19**.  
   
 Классификация: **CWE-78**, OWASP  **N/A**.](../../projects/cpp/vulnerable.cpp "../../projects/cpp/vulnerable.cpp")  
Ввод x;printf RBPO_CMD приводит к выполнению второй команды.  
**Доказательство:** [результат проверки. Подтверждено выполнение безвредной команды; повышение привилегий не проверялось.](../../reports/Ульянов/evidence/cpp-harness-command-short.json "../../reports/Ульянов/evidence/cpp-harness-command-short.json")  
**Исправление:** Для вывода текста не вызывать shell; использовать std::cout.  
**Модельная оценка:** CVSS 7.8 (High), CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H.  
   
 Допущения модели описаны в [разделе 6.](../Прядко/report.md "../Прядко/report.md")  
**Реальный пример:** [CVE-2020-11981. Инъекция команд через брокер Celery в Airflow; другой канал ввода.](https://github.com/advisories/GHSA-976r-qfjj-c24w "https://github.com/advisories/GHSA-976r-qfjj-c24w")  
**Результаты статического анализа**  
Запущен Cppcheck 2.17.1 с --enable=all --inconclusive --std=c++17 --library=std.  
   
 [XML-отчёт содержит предложения constParameterPointer  
   
 и информационные сообщения о стандартных заголовках. Ключевые три уязвимости  
   
 этот запуск автоматически не обнаружил. Приписывать ему находки ASan неправильно.](evidence/cppcheck-vulnerable.cpp.xml "evidence/cppcheck-vulnerable.cpp.xml")  
Компилятор с -Wformat=2 предупреждает об управляемой строке формата; диагностика  
   
 сохранена в [harness-compile.json. Вызов  
   
 strcpy подтверждён анализом исходника и аварией ASan на строке из 64 символов.  
   
 Короткая строка test успешно обрабатывается, что служит контрольной проверкой.](evidence/harness-compile.json "evidence/harness-compile.json")  
**Вывод**  
Четыре динамические проверки подтверждают нормальный короткий ввод и три опасных  
   
 шаблона. Вызов sprintf в vulnerable_system также ограничен размером локального  
   
 буфера и опасен на длинном вводе; отдельно как новый класс он не подсчитывается.  
   
 Результат не доказывает RCE через переполнение или форматную строку и не показывает  
   
 повышения привилегий. Для консольной программы указано OWASP N/A: категории веб-рисков  
   
 не присваиваются ей механически.  
**Вопросы к защите**  
- Почему harness нужен? Первая авария в исходном main скрывает поведение следующих функций.  
- Что доказывает %%? Управление форматом, но не утечку памяти и не выполнение кода.  
- Почему std::string удобнее strncpy? Не требует ручного расчёта буфера и нуль-терминатора для этой задачи.  
**Дополнение CPP-04 по разделу 3.5**  
Добавлен [null_pointer.cpp, строка 9:  
   
 process_data разыменовывает data без проверки. CWE-476, модельный CVSS 5.5,  
   
 CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H. Для консольной программы OWASP N/A;  
   
 значение A05:2021 из методички сохранено отдельно в owasp_assignment.](../../projects/cpp/null_pointer.cpp "../../projects/cpp/null_pointer.cpp")  
[NULL-ввод приводит к нарушению доступа;  
   
 ](evidence/null_pointer-null.json "evidence/null_pointer-null.json")[обычный указатель даёт 42.  
   
 Проверка выполнена на Windows 17 сентября 2026 года; команда, версия компилятора  
   
 и код завершения сохранены в протоколах. Для Windows ожидается именно  
   
 0xC0000005, для POSIX — SIGSEGV, а не произвольная ошибка запуска.](evidence/null_pointer-valid.json "evidence/null_pointer-valid.json")  
Исправление — проверка nullptr в [null_pointer_fixed.cpp.  
   
 ](../../projects/cpp/null_pointer_fixed.cpp "../../projects/cpp/null_pointer_fixed.cpp")[Результат подтверждает  
   
 корректное отклонение NULL; ](../Шумков/evidence/null_pointer_fixed-null.json "../Шумков/evidence/null_pointer_fixed-null.json")[контроль  
   
 сохраняет обработку обычного указателя.  
   
 Аналог: ](../Шумков/evidence/null_pointer_fixed-valid.json "../Шумков/evidence/null_pointer_fixed-valid.json")[CVE-2023-3316, libtiff;  
   
 совпадает класс NULL pointer, но отличается приложение и путь ввода.](https://nvd.nist.gov/vuln/detail/CVE-2023-3316 "https://nvd.nist.gov/vuln/detail/CVE-2023-3316")  
