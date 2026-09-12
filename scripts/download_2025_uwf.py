#!/usr/bin/env python
"""Download CSV shards from the official UWF Summer-2025 Zeek datasets.

Default downloads the compact CSV trees for UWF-ZeekDataSum25-1, keeping the
project portable. Use --dataset 2 or --dataset both for Sum25-2/both.
"""
from __future__ import annotations
import argparse
import re
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

BASE = "https://datasets.uwf.edu/data/UWF-ZeekDataSum25-{}/csv/"
FOLDERS = ["Benign", "Defense_Evasion", "Discovery", "Initial_Access", "Lateral_Movement", "Privilege_Escalation", "Reconnaissance"]

class HrefParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)

def get_files(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "CODEZILLA-2025-validator/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        html = r.read().decode("utf-8", errors="ignore")
    p = HrefParser(); p.feed(html)
    return sorted({x for x in p.hrefs if re.search(r"part-.*\.csv$", x)})

def download(url: str, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "CODEZILLA-2025-validator/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r, dest.open("wb") as f:
        f.write(r.read())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["1", "2", "both"], default="1")
    ap.add_argument("--output", default="data/modern_2025")
    ap.add_argument("--folders", default=",".join(FOLDERS), help="Comma-separated folders to fetch")
    args = ap.parse_args()
    datasets = [1, 2] if args.dataset == "both" else [int(args.dataset)]
    folders = [x.strip() for x in args.folders.split(",") if x.strip()]
    out = Path(args.output)
    for ds in datasets:
        for folder in folders:
            url = BASE.format(ds) + folder + "/"
            try:
                names = get_files(url)
            except Exception as exc:
                print(f"WARN: cannot inspect {url}: {exc}")
                continue
            for name in names:
                target = out / f"UWF-ZeekDataSum25-{ds}" / folder / Path(name).name
                if target.exists():
                    print("skip", target)
                    continue
                full = url + name
                print("download", full)
                try:
                    download(full, target)
                except Exception as exc:
                    print(f"WARN: failed {full}: {exc}")
    print(f"Done. Dataset root: {out.resolve()}")

if __name__ == "__main__":
    main()
