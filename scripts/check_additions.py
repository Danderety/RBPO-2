#!/usr/bin/env python3
"""Additional checks, saved separately from the original Ubuntu protocols."""
import ast
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from report_paths import report_dir

R = Path(__file__).resolve().parents[1]

def save(part, name, value):
    path = report_dir(part) / 'evidence' / f'{name}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def command(args):
    p = subprocess.run([str(a) for a in args], cwd=R, capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=30)
    return dict(command=[str(a) for a in args], returncode=p.returncode,
                stdout=p.stdout, stderr=p.stderr)

def main():
    tests = []
    environment = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
                       platform=platform.platform(), python=sys.version,
                       compiler=command(['g++', '--version']))
    def record(part, name, passed, details, method):
        value = dict(test=name, passed=bool(passed), method=method,
                     environment=environment, details=details)
        tests.append(value)
        save(part, name, value)
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)

    build = R / 'build'; build.mkdir(exist_ok=True)
    for fixed in (False, True):
        stem = 'null_pointer_fixed' if fixed else 'null_pointer'
        exe = build / (stem + ('.exe' if os.name == 'nt' else ''))
        compile_result = command(['g++', '-std=c++17', '-Wall', '-Wextra', '-O0',
                                  R / 'projects/cpp' / (stem + '.cpp'), '-o', exe])
        save(5 if fixed else 3, stem + '-compile', compile_result)
        if compile_result['returncode'] != 0:
            raise RuntimeError(compile_result)
        for mode in ('valid', 'null'):
            run = command([exe, mode])
            if mode == 'valid':
                passed = run['returncode'] == 0 and run['stdout'].strip() == '42'
            elif fixed:
                passed = run['returncode'] == 0 and run['stdout'].strip() == 'null rejected'
            else:
                # Require an access violation / segmentation fault, not any error.
                passed = ((run['returncode'] & 0xffffffff) == 0xc0000005 if os.name == 'nt'
                          else run['returncode'] == -signal.SIGSEGV)
            record(5 if fixed else 3, stem + '-' + mode, passed, run, 'dynamic_process')

    source = R / 'projects/python/vulnmart/app.py'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    assignments = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    keys = [n for n in assignments if any(isinstance(t, ast.Attribute) and
            isinstance(t.value, ast.Name) and t.value.id == 'app' and t.attr == 'secret_key'
            for t in n.targets)]
    key_ok = len(keys) == 1 and isinstance(keys[0].value, ast.Constant) and isinstance(keys[0].value.value, str)
    record(1, 'static-session-key', key_ok, dict(file=source.relative_to(R).as_posix(),
        line=keys[0].lineno if keys else None, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        observation='AST: app.secret_key assigned a string literal; existing Bandit B105 corroborates this.',
        limitation='Static confirmation; session forgery not executed.'), 'static_source_review')
    seeds = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == 'executemany' and len(n.args) == 2
             and isinstance(n.args[0], ast.Constant) and 'INSERT INTO users' in str(n.args[0].value)]
    rows = ast.literal_eval(seeds[0].args[1]) if len(seeds) == 1 else []
    logins = [n for n in ast.walk(tree) if isinstance(n, ast.JoinedStr)
              and any(isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name)
                      and v.value.id == 'password' for v in n.values)]
    record(1, 'static-plaintext-passwords', bool(rows) and all(isinstance(p, str) for _, p in rows) and bool(logins),
        dict(file=source.relative_to(R).as_posix(), line=seeds[0].lineno if seeds else None,
             source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
             observation='Literal passwords inserted directly into users; login compares submitted password directly.',
             limitation='Static data-flow confirmation; database extraction not executed.'), 'static_source_review')
    summary = dict(environment=environment, tests=tests, passed=sum(t['passed'] for t in tests), total=len(tests))
    save(5, 'verification-additions', summary)
    return 0 if all(t['passed'] for t in tests) else 1

if __name__ == '__main__':
    raise SystemExit(main())
