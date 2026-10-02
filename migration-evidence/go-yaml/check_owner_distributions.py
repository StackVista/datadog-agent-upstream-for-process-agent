#!/usr/bin/env python3
"""Verify complete immutable owner distributions and reviewed patch boundaries."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name('remaining-owner-distributions.json')


def verify(root=ROOT):
    for name, owner in json.loads(MANIFEST.read_text()).items():
        directory = root / 'third_party' / name
        actual = {str(p.relative_to(directory)): p for p in directory.rglob('*') if p.is_file()}
        expected = owner['candidate_files']
        if root == ROOT:
            tracked = subprocess.check_output(['git', 'ls-files', '--', str(directory)], cwd=root, text=True).splitlines()
            tracked = {str(Path(p).relative_to(Path('third_party') / name)) for p in tracked}
            assert tracked == set(expected), f'{name}: distribution files absent from Git index'
        assert set(actual) == set(expected), f'{name}: omitted or unexpected distribution files'
        for rel, receipt in expected.items():
            p = actual[rel]
            assert hashlib.sha256(p.read_bytes()).hexdigest() == receipt['sha256'], f'{name}: changed {rel}'
            assert p.stat().st_mode & 0o777 == receipt['mode'], f'{name}: wrong mode {rel}'
        for rel, source in owner['files'].items():
            if rel not in owner['allowed_changes']:
                assert expected[rel] == source, f'{name}: unreviewed source change {rel}'
        for p in directory.rglob('*.go'):
            text = p.read_text()
            assert '"gopkg.in/yaml.' not in text and '"github.com/ghodss/yaml"' not in text, f'{name}: wrong parser {p}'


if __name__ == '__main__':
    verify()
    print('Complete owner distributions, licenses, modes and parser boundaries verified')
