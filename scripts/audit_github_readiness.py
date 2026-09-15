"""
Audit GitHub Readiness script.
Scans for secrets, credentials, large files, unignored caches, git tracking issues.
"""

import os
import re
import subprocess
from pathlib import Path

root = Path('.')
SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["\'][^\'"]{8,}["\']'),
    re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^\'"]{6,}["\']'),
    re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----'),
    re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}'),
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
]

SKIP_DIRS = {'.git', '.venv', 'venv'}

findings = []
large_files = []
pycache_files = []
node_modules = []

for p in root.rglob('*'):
    if any(part in SKIP_DIRS for part in p.parts):
        continue
    if '__pycache__' in p.parts or p.suffix in {'.pyc', '.pyo'}:
        pycache_files.append(str(p))
    if 'node_modules' in p.parts:
        node_modules.append(str(p))
    if p.is_file():
        sz = p.stat().st_size
        if sz > 10 * 1024 * 1024:  # > 10MB
            large_files.append((str(p), sz / (1024 * 1024)))
        if sz < 2 * 1024 * 1024 and p.suffix in {
            '.py', '.json', '.yaml', '.yml', '.env', '.example', '.sh', '.md', '.txt', '.js', '.html', '.ts'
        }:
            try:
                content = p.read_text(encoding='utf-8', errors='ignore')
                for pat in SECRET_PATTERNS:
                    for m in pat.finditer(content):
                        val = m.group(0)
                        if not any(
                            placeholder in val.lower()
                            for placeholder in ['your_', 'placeholder', 'dummy', 'change_me', 'example', 'none', 'false', 'true', 'test', 'os.getenv']
                        ):
                            findings.append((str(p), val[:60]))
            except Exception:
                pass

print(f"=== SECRETS / SENSITIVE STRINGS ({len(findings)}) ===")
for f, snippet in findings[:30]:
    print(f"  {f}: {snippet}")

print(f"\n=== LARGE FILES > 10MB ({len(large_files)}) ===")
for f, sz in large_files:
    print(f"  {f}: {sz:.2f} MB")

print(f"\n=== PYCACHE FILES ({len(pycache_files)}) ===")
print(f"  Total pycache / pyc files: {len(pycache_files)}")

print(f"\n=== NODE MODULES ({len(node_modules)}) ===")
print(f"  Total node_modules entries: {len(node_modules)}")

# Check git-tracked ignored files
print("\n=== GIT TRACKED FILES THAT MATCH .GITIGNORE ===")
try:
    res = subprocess.run(["git", "ls-files", "-i", "-c", "--exclude-standard"], capture_output=True, text=True, check=True)
    tracked_ignored = res.stdout.strip().splitlines()
    print(f"  Total tracked but ignored: {len(tracked_ignored)}")
    for ti in tracked_ignored[:15]:
        print(f"    {ti}")
except Exception as e:
    print(f"  Error checking git ls-files: {e}")
