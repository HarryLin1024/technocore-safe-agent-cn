"""Read-only repository gate: 0 clean, 1 finding, 2 incomplete/failed scan.

Never prints matching values or private paths. Covers reachable blobs, metadata,
index and tracked working files. Patterns are heuristics, not a secrecy proof.
"""
import json
import re
import subprocess
import sys
from pathlib import Path


PATTERNS = {
    "private_material": re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"private_key_hex"\s*:\s*"[0-9a-fA-F]{64}"'),
    "credential": re.compile(rb'gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}'),
    "local_path": re.compile(rb'/(?:Users|home)/[^/\s]+'),
}
EMAIL = re.compile(rb'[A-Za-z0-9_.+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')


def findings(data):
    result = [name for name, pattern in PATTERNS.items() if pattern.search(data)]
    if any(not email.endswith((b'@example.com', b'.invalid', b'@users.noreply.github.com'))
           for email in EMAIL.findall(data)):
        result.append("email")
    return result


def git(*args):
    return subprocess.run(['git', *args], check=True, capture_output=True).stdout


def sensitive_name(name):
    return bool(re.search(r'(^|/)(flop_agent_identity\.json.*|\.agent-state|\.identity-[^/]*|\.env(?:\..*)?|[^/]+\.(?:pem|key|p12|pfx|age|gpg|enc|backup|bak|jsonl))($|/)', name))


def scan():
    root = Path(git('rev-parse', '--show-toplevel').decode().strip())
    revisions = git('rev-list', '--all').decode().split()
    if not revisions:
        raise ValueError('no history')
    blobs, names = set(), set()
    for revision in revisions:
        for entry in git('ls-tree', '-rz', revision).split(b'\0'):
            if entry:
                fields, name = entry.split(b'\t', 1)
                _, kind, oid = fields.split()
                if kind == b'blob':
                    blobs.add(oid.decode())
                    names.add(name.decode())
    current = set()
    for entry in git('ls-files', '--stage', '-z').split(b'\0'):
        if entry:
            fields, name = entry.split(b'\t', 1)
            _, oid, stage = fields.split()
            if stage != b'0':
                raise ValueError('unmerged index')
            blobs.add(oid.decode()); names.add(name.decode()); current.add(name.decode())
    counts = {}
    def count(data):
        for category in findings(data):
            counts[category] = counts.get(category, 0) + 1
    for oid in blobs:
        count(git('cat-file', 'blob', oid))
    for name in current:
        path = root / name
        if path.is_symlink():
            raise ValueError('tracked symlink requires review')
        if path.exists():
            count(path.read_bytes())
    metadata = git('log', '--all', '--format=%an%n%ae%n%cn%n%ce')
    count(metadata)
    if b'mandy' in metadata.lower():
        counts['contributor_name'] = 1
    if any(sensitive_name(name) for name in names):
        counts['sensitive_filename'] = 1
    return {'commits': len(revisions), 'unique_blobs': len(blobs), 'findings': counts}


def main():
    try:
        report = scan()
    except Exception:
        print('SCAN ERROR: inspection incomplete; publication blocked', file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 1 if report['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
