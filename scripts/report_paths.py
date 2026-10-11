"""Shared report paths; folder names are configured in report_folders.json."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_FOLDERS = json.loads(Path(__file__).with_name('report_folders.json').read_text(encoding='utf-8'))
if set(REPORT_FOLDERS) != {f'{i:02d}' for i in range(1, 7)}:
    raise ValueError('report_folders.json must map participant IDs 01 through 06')
if len(set(REPORT_FOLDERS.values())) != 6:
    raise ValueError('Report folder names must be unique')
for folder in REPORT_FOLDERS.values():
    if not isinstance(folder, str) or not folder or folder in {'.', '..'} or '/' in folder or chr(92) in folder:
        raise ValueError('Report folder must be a single nonempty directory name')

def report_relative(part, *parts):
    key = f'{int(part):02d}'
    if key not in REPORT_FOLDERS:
        raise ValueError(f'Unknown participant ID: {part!r}')
    return Path('reports', REPORT_FOLDERS[key], *parts)

def report_dir(part):
    return ROOT / report_relative(part)
