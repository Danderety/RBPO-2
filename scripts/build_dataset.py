#!/usr/bin/env python3
"""Build a traceable dataset; no scanner findings or run results are invented."""
from pathlib import Path
from report_paths import report_dir, report_relative
import csv, hashlib, json, math
R=Path(__file__).resolve().parents[1]
def cvss(vector):
 m=dict(x.split(':') for x in vector.split('/')[1:]);changed=m['S']=='C'
 av={'N':.85,'A':.62,'L':.55,'P':.2}[m['AV']];ac={'L':.77,'H':.44}[m['AC']]
 pr=({'N':.85,'L':.68,'H':.5} if changed else {'N':.85,'L':.62,'H':.27})[m['PR']]
 ui={'N':.85,'R':.62}[m['UI']];impact={'N':0,'L':.22,'H':.56}
 iss=1-(1-impact[m['C']])*(1-impact[m['I']])*(1-impact[m['A']])
 imp=7.52*(iss-.029)-3.25*(iss-.02)**15 if changed else 6.42*iss
 exp=8.22*av*ac*pr*ui
 return 0.0 if imp<=0 else math.ceil((min(1.08*(imp+exp) if changed else imp+exp,10)-1e-10)*10)/10
CVE={
 'CWE-89':('CVE-2023-25157','https://geoserver.org/vulnerability/2023/02/20/ogc-filter-injection.html','SQL-инъекция GeoServer; аналог класса, другой продукт и путь ввода.'),
 'CWE-79':('CVE-2020-11022','https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2','XSS в обработке HTML jQuery; аналог класса, не та же разновидность/реализация.'),
 'CWE-120':('CVE-2021-3156','https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit','Родственная ошибка безопасности памяти: в sudo переполнение кучи, в примере стек. Не точное совпадение CWE.'),
 'CWE-134':('CVE-2012-0809','https://nvd.nist.gov/vuln/detail/CVE-2012-0809','Форматная строка sudo_debug; sudo имеет иную модель привилегий.'),
 'CWE-78':('CVE-2020-11981','https://github.com/advisories/GHSA-976r-qfjj-c24w','Инъекция команд через брокер Celery в Airflow; другой канал ввода.'),
 'CWE-862':('CVE-2023-22515','https://confluence.atlassian.com/security/cve-2023-22515-broken-access-control-vulnerability-in-confluence-data-center-and-server-1295682276.html','Аналог категории Broken Access Control; создание администратора в Confluence не тождественно IDOR.')}
# id,language,file,anchor,cwe,name,owasp,vector,description,fix,evidence,scope
specs=[
('PY-01','Python','projects/python/vulnmart/app.py','query = f"SELECT','CWE-89','SQL Injection','A03:2021','AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N','Имя admin\' -- исключает проверку пароля из SQL; получен доступ к заказу администратора.','Параметризованный запрос и check_password_hash.','02/vulnmart-sqli','SQLi подтверждена HTTP; изменение данных не проверялось, I:L учитывает действия под чужой учётной записью.'),
('PY-02','Python','projects/python/vulnmart/templates/product.html',"r['comment']|safe",'CWE-79','Stored XSS','A03:2021','AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N','Комментарий с script сохраняется и возвращается другому клиенту без экранирования.','Удалить фильтр safe; оставить автоэкранирование Jinja.','02/vulnmart-stored-xss','Подтверждены хранение и небезопасный HTML-вывод; браузерное исполнение не запускалось.'),
('PY-03','Python','projects/python/vulnmart/app.py','order = db.execute','CWE-862','Missing Authorization / IDOR','A01:2021','AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N','Пользователь sarah читает заказ admin по /order/1.','Ограничить SQL по id заказа и user_id из серверной сессии.','02/vulnmart-idor','Подтверждена утечка чужого заказа; изменение заказа не проверялось.'),
('CPP-01','C++','projects/cpp/vulnerable.cpp','strcpy(buffer','CWE-120','Buffer Overflow','N/A','AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H','strcpy копирует 64 символа в буфер на 10 байт; ASan выявил stack-buffer-overflow.','std::string вместо фиксированного буфера.','03/cpp-harness-copy-long','Подтверждены выход за границу стека и аварийное завершение. RCE не демонстрировалось.'),
('CPP-02','C++','projects/cpp/vulnerable.cpp','printf(input)','CWE-134','Format String','N/A','AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','Ввод %% интерпретируется как формат и печатает один %.','printf("%s", input) с постоянной строкой формата.','03/cpp-harness-format-short','Подтверждена интерпретация формата. Утечка памяти, запись через %n и RCE не выполнялись; C/I/A:H — потенциальное воздействие модели.'),
('CPP-03','C++','projects/cpp/vulnerable.cpp','system(command)','CWE-78','OS Command Injection','N/A','AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H','Ввод x;printf RBPO_CMD приводит к выполнению второй команды.','Для вывода текста не вызывать shell; использовать std::cout.','03/cpp-harness-command-short','Подтверждено выполнение безвредной команды; повышение привилегий не проверялось.'),
('JS-01','JavaScript','projects/javascript/vulnerable.js','db.get(`SELECT','CWE-89','SQL Injection','A03:2021','AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N','Ввод \' OR 1=1 -- изменяет предикат и возвращает запись admin.','Плейсхолдер ? и массив параметров SQLite.','04/vulnerable.js-sqli','Подтверждено изменение запроса и чтение записи; endpoint не является формой входа.'),
('JS-02','JavaScript','projects/javascript/vulnerable.js','res.send(`<h1>','CWE-79','Reflected XSS','A03:2021','AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N','Параметр name попадает в HTML без кодирования.','Контекстное экранирование HTML-текста.','04/vulnerable.js-xss','Подтверждено отражение тега script в HTML; браузерное исполнение не проверялось.'),
('JS-03','JavaScript','projects/javascript/vulnerable.js','exec(`ping','CWE-78','OS Command Injection','A03:2021','AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','Параметр host содержит ; printf RBPO_CMD и запускает дополнительную команду.','execFile без shell; проверка типа, IP и разрешённых адресов.','04/vulnerable.js-command','Подтвержден вывод маркера из shell; C/I/A:H — потенциальные права процесса.')]
CVE.update({
 'CWE-476':('CVE-2023-3316','https://nvd.nist.gov/vuln/detail/CVE-2023-3316','NULL pointer в libtiff TIFFClose; совпадает класс ошибки, но не продукт и путь ввода.'),
 'CWE-321':('CVE-2022-29960','https://cwe.mitre.org/data/definitions/321.html','Пример MITRE: постоянные криптографические ключи в инженерной станции; иной продукт и назначение ключа.'),
 'CWE-256':('CVE-2022-30275','https://cwe.mitre.org/data/definitions/256.html','Пример MITRE: открытое хранение пароля в драйвере RTU; другой продукт, тот же класс хранения.')})
specs.extend([
 ('CPP-04','C++','projects/cpp/null_pointer.cpp','*data = 42','CWE-476','NULL Pointer Dereference','N/A','AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H','Передача nullptr в process_data вызывает нарушение доступа; обычный указатель обрабатывается.','Проверить data на nullptr до разыменования.','03/null_pointer-null','Подтверждено аварийное завершение отдельного процесса; удалённая достижимость не заявляется.'),
 ('PY-04','Python','projects/python/vulnmart/app.py','app.secret_key =','CWE-321','Use of Hard-coded Cryptographic Key','A02:2021','AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N','Ключ подписи Flask-сессии задан публичной строкой в исходнике.','Случайный секрет вне исходников; в учебном fixed ключ создаётся при запуске.','01/static-session-key','Подтверждено AST-проверкой и исходным B105; подделка сессии не выполнялась. C/I:H — допущение модели.'),
 ('PY-05','Python','projects/python/vulnmart/app.py','password TEXT NOT NULL','CWE-256','Plaintext Storage of a Password','A04:2021','AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N','Учебные пароли напрямую записываются в users и сравниваются без хеширования.','generate_password_hash при записи и check_password_hash при входе.','01/static-plaintext-passwords','Подтверждён поток данных в исходнике; CVSS предполагает локальное чтение БД, а не самостоятельный сетевой обход.')])
ASSIGNMENT_OWASP={'CWE-120':'A06:2021','CWE-134':'A03:2021','CWE-78':'A03:2021','CWE-476':'A05:2021'}
IMPACT={
 'CWE-89':'Утечка данных, обход аутентификации',
 'CWE-79':'Выполнение JavaScript в браузере жертвы, действия от её имени',
 'CWE-862':'Чтение чужих объектов без разрешения',
 'CWE-120':'Повреждение памяти, отказ в обслуживании; потенциально выполнение кода',
 'CWE-134':'Утечка или изменение памяти, потенциально выполнение кода',
 'CWE-78':'Выполнение команд с правами процесса',
 'CWE-476':'Аварийное завершение, отказ в обслуживании',
 'CWE-321':'Подделка подписанных сессий, обход контроля доступа',
 'CWE-256':'Раскрытие паролей при чтении хранилища'}

def main():
 rows=[]
 for vid,lang,file,anchor,cwe,name,owasp,vector,desc,fix,evidence,scope in specs:
  lines=(R/file).read_text(encoding='utf-8').splitlines();matches=[i for i,l in enumerate(lines,1) if anchor in l]
  if len(matches)!=1:raise ValueError((file,anchor,matches))
  part,test=evidence.split('/');evidence=report_relative(part, 'evidence', f'{test}.json').as_posix()
  run=json.loads((R/evidence).read_text(encoding='utf-8'));assert run['passed'],vid
  score=cvss('CVSS:3.1/'+vector);example,url,relation=CVE[cwe]
  rows.append(dict(vuln_id=vid,language=lang,file=file,line=matches[0],source_sha256=hashlib.sha256((R/file).read_bytes()).hexdigest(),severity='Critical' if score>=9 else 'High' if score>=7 else 'Medium' if score>=4 else 'Low',cwe_id=cwe,cwe_name=name,owasp=owasp,owasp_version='2021',cve_example=example,cve_source=url,cve_relation=relation,cvss=score,cvss_version='3.1',cvss_vector='CVSS:3.1/'+vector,cvss_type='illustrative_model_not_measured_local_risk',description=desc,recommendation=fix,evidence=evidence,status='confirmed_http_output' if cwe=='CWE-79' else 'confirmed_dynamic',evidence_scope=scope))
  rows[-1]['owasp_assignment']=ASSIGNMENT_OWASP.get(cwe,owasp)
  rows[-1]['owasp_note']='Категория из методички приведена для сравнения; OWASP Top 10 не классифицирует этот консольный стенд напрямую.' if lang=='C++' else 'Сопоставление с редакцией OWASP 2021; CWE-256 входит в A04:2021, CWE-321 — A02:2021.'
  rows[-1]['verification_method']=run.get('method','dynamic_http' if lang!='C++' else 'dynamic_process')
  if run.get('method')=='static_source_review':rows[-1]['status']='confirmed_static'
  rows[-1]['browser_evidence']=''
  if cwe=='CWE-79':
   browser_evidence=evidence.replace('.json','-browser-replay.json')
   browser_run=json.loads((R/browser_evidence).read_text(encoding='utf-8'))
   assert browser_run['passed'] and browser_run['source_sha256']==hashlib.sha256((R/evidence).read_bytes()).hexdigest(),vid
   rows[-1]['browser_evidence']=browser_evidence
   rows[-1]['status']='confirmed_http_and_browser_replay'
   rows[-1]['evidence_scope']='Сохранённый HTTP-ответ исполнен в изолированном браузере; маркер XSS сработал. Повторный полный запуск веб-приложения в браузере не выполнялся.'
 (R/'datasets/vulnerabilities.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 with (R/'datasets/vulnerabilities.csv').open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
 mapping=[]
 for cwe in sorted(CVE):
  entries=[r for r in rows if r['cwe_id']==cwe]
  mapping.append({'cwe_id':cwe,'cwe_name':entries[0]['cwe_name'],'rank_2025':{'CWE-79':1,'CWE-89':2,'CWE-862':4,'CWE-78':9,'CWE-120':11}.get(cwe,''),'rank_source':'https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html','owasp_category':'; '.join(sorted(set(r['owasp'] for r in entries))),'cwe_source':f'https://cwe.mitre.org/data/definitions/{cwe.split("-")[1]}.html','note':'N/A для консольного C++; CWE-120 уточняется CWE-121 для стека' if cwe in ['CWE-120','CWE-134','CWE-78'] else 'Сопоставление относится к веб-приложению'})
  mapping[-1]['typical_impact']=IMPACT[cwe]
  mapping[-1]['owasp_assignment']='; '.join(sorted(set(r['owasp_assignment'] for r in entries)))
  if cwe=='CWE-476':mapping[-1]['rank_2025']=13
  if cwe=='CWE-79':mapping[-1]['cwe_name']='Cross-site Scripting'
  mapping[-1]['note']='OWASP: см. owasp_category и отдельное сопоставление образца owasp_assignment; CVE являются аналогами.'
 with (R/'datasets/cwe_mapping.csv').open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=mapping[0].keys());w.writeheader();w.writerows(mapping)
 assert len({r['cwe_id'] for r in rows})>=6
 validation={'records':len(rows),'classes':len(mapping),'source_lines_and_hashes_checked':True,'evidence_assertions_passed':True,'csv_json_equivalent':True}
 with (R/'datasets/vulnerabilities.csv').open(encoding='utf-8') as f:
  csvrows=list(csv.DictReader(f))
 assert len(rows)==len(csvrows)
 assert all(str(row[k])==csvrow[k] for row,csvrow in zip(rows,csvrows) for k in row)
 (report_dir(6)/'evidence/dataset-validation.json').write_text(json.dumps(validation,indent=2)+'\n')
 # The requested standalone expert assessment is generated from the same rows.
 lines=['# Экспертная оценка безопасности','',
  'Практическая работа 2. Анализ Python, C++ и JavaScript. Датасет содержит '+str(len(rows))+' находок и '+str(len(mapping))+' классов CWE.', '',
  '## Сводка найденных уязвимостей','',
  '| ID | Язык | Тип | CWE | OWASP 2021 | CVSS 3.1 | Критичность |',
  '|---|---|---|---|---|---:|---|']
 for row in rows:lines.append(f"| {row['vuln_id']} | {row['language']} | {row['cwe_name']} | {row['cwe_id']} | {row['owasp']} | {row['cvss']} | {row['severity']} |")
 lines.extend(['','## Выводы и приоритеты','',
  'Сначала устраняются выполнение команд через JavaScript, известный ключ подписи сессий и SQL-инъекция входа. Далее закрываются доступ к чужим заказам, XSS и открытое хранение паролей. Приоритет C++ зависит от прав процесса и источника ввода.', '',
  '## Рекомендации','',
  'Python: параметры SQL, автоэкранирование Jinja, проверка владельца, случайный ключ и хеширование паролей. C++: std::string, постоянный формат printf, отказ от system и проверка указателей. JavaScript: параметры SQLite, кодирование HTML и execFile с проверкой адреса.', '',
  '## Основания оценок и ограничения','',
  'CVSS рассчитан по приведённым в CSV/JSON векторам для учебной модели; это не баллы сканеров и не оценки сторонних CVE. Категории C++ из методички сохранены в owasp_assignment, а техническая применимость обозначена N/A. PY-04 и PY-05 подтверждены статически, CPP-04 — отдельными запусками. Исходные 30 динамических проверок сохранены отдельно от дополнительных протоколов.', '',
  f'Подробности, допущения и источники: [отчёт участника 6]({report_relative(6, "report.md").as_posix()}). Соответствие каждому пункту задания: [сверка](ASSIGNMENT_COMPLIANCE.md).', '',
  '## Доказательства и исправления',''])
 for row in rows:lines.extend([f"### {row['vuln_id']} — {row['cwe_name']}", '', row['description'], '', f"**Исправление:** {row['recommendation']}", '', f"**Подтверждение:** [{row['status']}]({row['evidence']}). {row['evidence_scope']}", '', f"**CVE-аналог:** [{row['cve_example']}]({row['cve_source']}). {row['cve_relation']}", ''])
 (R/'expert_assessment.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
 print(json.dumps(validation))
if __name__=='__main__':main()
