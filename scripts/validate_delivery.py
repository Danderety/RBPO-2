#!/usr/bin/env python3
"""Read-only consistency checks for the lab deliverables."""
import ast
import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote
from build_dataset import cvss
from report_paths import report_dir

R=Path(__file__).resolve().parents[1]

def main():
    rows=json.loads((R/'datasets/vulnerabilities.json').read_text(encoding='utf-8'))
    with (R/'datasets/vulnerabilities.csv').open(encoding='utf-8',newline='') as f:
        csvrows=list(csv.DictReader(f))
    assert len(rows)==len(csvrows)==12
    assert len({r['vuln_id'] for r in rows})==12
    assert len({r['cwe_id'] for r in rows})==9
    for row,csvrow in zip(rows,csvrows):
        assert all(str(v)==csvrow[k] for k,v in row.items()),row['vuln_id']
        source=R/row['file']
        assert hashlib.sha256(source.read_bytes()).hexdigest()==row['source_sha256']
        assert 0<row['line']<=len(source.read_text(encoding='utf-8').splitlines())
        assert cvss(row['cvss_vector'])==row['cvss']
        assert json.loads((R/row['evidence']).read_text(encoding='utf-8'))['passed']
        if row['browser_evidence']:
            proof=json.loads((R/row['browser_evidence']).read_text(encoding='utf-8'))
            assert proof['passed']
            assert proof['source_sha256']==hashlib.sha256((R/proof['source']).read_bytes()).hexdigest()
    with (R/'datasets/cwe_mapping.csv').open(encoding='utf-8',newline='') as f:
        mapping=list(csv.DictReader(f))
    assert {r['cwe_id'] for r in mapping}=={r['cwe_id'] for r in rows}
    assert all(r['typical_impact'] and r['owasp_category'] for r in mapping)
    assert next(r for r in mapping if r['cwe_id']=='CWE-476')['rank_2025']=='13'
    for script in (R/'scripts').glob('*.py'):
        ast.parse(script.read_text(encoding='utf-8'),filename=str(script))
    # Generated reports and our own README links; upstream documentation remains unmodified.
    markdown=[R/'README.md',R/'expert_assessment.md',R/'ASSIGNMENT_COMPLIANCE.md',
              R/'datasets/README.md',*(R/'reports').glob('*/report.md')]
    for document in markdown:
        for target in re.findall(r'\]\(([^)]+)\)',document.read_text(encoding='utf-8')):
            target = re.sub(r'''\s+(?:"[^"]*"|'[^']*')\s*$''', '', target).strip('<>')
            if '://' in target or target.startswith('#'):continue
            assert (document.parent/unquote(target.split('#')[0])).exists(),(document,target)
    series={}
    for name,expected in [('all',30),('additions',6),('browser-replay',4)]:
        summary=json.loads((report_dir(5)/'evidence'/f'verification-{name}.json').read_text(encoding='utf-8'))
        assert summary['passed']==summary['total']==expected
        assert all(test['passed'] for test in summary['tests'])
        series[name]=expected
    assert (R/'expert_assessment.md').exists()
    print(json.dumps({'records':12,'cwe_classes':9,'series':series,
                      'csv_json_hashes_links_syntax':'passed'},ensure_ascii=False))

if __name__=='__main__':main()
