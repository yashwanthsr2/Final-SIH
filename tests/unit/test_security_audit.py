import os, re

def test_passive_security():
    forbidden = [
        r'\.send\(', r'\.sendp\(', r'\.sendto\(', r'sr\(', r'sr1\(',
        r'iptables', r'nftables', r'tc qdisc', r'drop ', r'block ',
        r'decrypt\(', r'AES\.', r'RSA\.', r'nmap'
    ]
    violations = []
    for root, dirs, files in os.walk('backend'):
        for file in files:
            if file.endswith('.py'):
                p = os.path.join(root, file)
                with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                    for idx, line in enumerate(fh, 1):
                        if line.strip().startswith('#'): continue
                        for pat in forbidden:
                            if re.search(pat, line):
                                violations.append((p, idx, line.strip()))
    assert len(violations) == 0, f"Violations found: {violations}"
    print("Zero active/intrusive network calls confirmed. Passive compliance PASS.")

if __name__ == "__main__":
    test_passive_security()
