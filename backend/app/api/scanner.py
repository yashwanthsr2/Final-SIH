"""
CyberSentinel Threat Intelligence Scanner API Router.
VirusTotal-style static file & URL threat detection module.
Calculates cryptographic hashes, Shannon entropy, structural features,
heuristic signatures, and generates explainable evidence with confidence scores.
"""

from __future__ import annotations

import hashlib
import math
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

router = APIRouter(prefix="/api/scan", tags=["Threat Scanner"])


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0.0
    total = len(data)
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _detect_file_type(data: bytes, filename: str) -> str:
    """Identify file type via magic bytes and extension."""
    if data.startswith(b"MZ"):
        return "Win32/PE Executable (.exe/.dll)"
    elif data.startswith(b"\x7fELF"):
        return "Linux ELF Binary"
    elif data.startswith(b"PK\x03\x04"):
        return "ZIP / Java Archive / Office Document (.zip/.jar/.docx)"
    elif data.startswith(b"%PDF"):
        return "PDF Document"
    elif data.startswith(b"\x1f\x8b"):
        return "GZIP Compressed Archive"
    elif data.startswith(b"#!/") or any(ext in filename.lower() for ext in [".sh", ".bash"]):
        return "Shell Script (.sh)"
    elif any(ext in filename.lower() for ext in [".ps1", ".bat", ".cmd", ".vbs"]):
        return "Windows Script / Batch (.ps1/.bat)"
    elif any(ext in filename.lower() for ext in [".py", ".pyw"]):
        return "Python Script (.py)"
    elif any(ext in filename.lower() for ext in [".js", ".ts", ".html"]):
        return "Web Script (.js/.html)"
    elif b"<html" in data[:200].lower():
        return "HTML Document"
    return "Binary / Data File"


def _analyze_file_content(data: bytes, filename: str) -> Dict[str, Any]:
    """Perform static heuristics and feature extraction on file content."""
    size = len(data)
    md5_hash = hashlib.md5(data).hexdigest()
    sha1_hash = hashlib.sha1(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    entropy = _calculate_entropy(data)
    file_type = _detect_file_type(data, filename)

    text_sample = ""
    try:
        text_sample = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        pass

    evidence: List[Dict[str, Any]] = []
    mitre_tags: List[Dict[str, str]] = []
    risk_points = 0.0

    # 1. Entropy Check (High entropy > 7.2 indicates packing/encryption)
    if entropy >= 7.2:
        risk_points += 30.0
        evidence.append({
            "feature": "shannon_entropy",
            "value": entropy,
            "contribution": 0.35,
            "direction": "increases_risk",
            "human_label": f"Extremely High Shannon Entropy ({entropy:.2f}/8.0) — indicates packed, encrypted, or obfuscated payload"
        })
        mitre_tags.append({"id": "T1027", "name": "Obfuscated/Encrypted Files"})
    elif entropy >= 6.4:
        risk_points += 15.0
        evidence.append({
            "feature": "shannon_entropy",
            "value": entropy,
            "contribution": 0.15,
            "direction": "increases_risk",
            "human_label": f"Elevated Entropy ({entropy:.2f}/8.0) — compressed or moderately obfuscated code"
        })
    else:
        evidence.append({
            "feature": "shannon_entropy",
            "value": entropy,
            "contribution": -0.1,
            "direction": "decreases_risk",
            "human_label": f"Normal Code Entropy ({entropy:.2f}/8.0) — typical plain-text or standard binary"
        })

    # 2. Suspicious string signatures
    suspicious_patterns = [
        (r"(powershell|pwsh)\s+(-enc|-encodedcommand|-w\s+hidden|-nop)", 28.0, "Obfuscated PowerShell execution invocation", "T1059.001"),
        (r"(cmd\.exe|bash\s+-i|/bin/sh\s+-i)", 22.0, "Interactive reverse shell invocation command", "T1059.004"),
        (r"(downloadstring|iwr\s+|curl\s+http|wget\s+http)", 24.0, "Stager payload download cradle (C2 beaconing)", "T1105"),
        (r"(invoke-expression|iex\s*\(|eval\s*\()", 20.0, "Dynamic memory code execution (IEX/eval)", "T1059"),
        (r"(certutil\s+-urlcache|bitsadmin\s+/transfer)", 25.0, "Living-off-the-land binary (LOLBin) transfer utility", "T1105"),
        (r"(virtualalloc|createremotethread|writeprocessmemory)", 30.0, "Process injection API calls identified in binary", "T1055"),
        (r"(mimikatz|sekurlsa|lsass|wdigest)", 35.0, "Credential dumping artifact signature", "T1003"),
        (r"(vssadmin\s+delete\s+shadows|wbadmin\s+delete)", 35.0, "Ransomware shadow copy destruction command", "T1490"),
        (r"(base64_decode|frombase64string)", 15.0, "Base64 payload decoding routine", "T1027"),
    ]

    for pat, pts, label, mitre_id in suspicious_patterns:
        if re.search(pat, text_sample):
            risk_points += pts
            evidence.append({
                "feature": pat,
                "value": "Detected",
                "contribution": round(pts / 100.0, 3),
                "direction": "increases_risk",
                "human_label": label
            })
            if not any(m["id"] == mitre_id for m in mitre_tags):
                mitre_tags.append({"id": mitre_id, "name": label.split(" — ")[0]})

    # 3. Executable in non-standard disguise
    lower_fn = filename.lower()
    if (data.startswith(b"MZ") or data.startswith(b"\x7fELF")) and not (lower_fn.endswith(".exe") or lower_fn.endswith(".dll") or lower_fn.endswith(".elf")):
        risk_points += 30.0
        evidence.append({
            "feature": "file_disguise",
            "value": f"Header={file_type}, Ext={lower_fn.split('.')[-1] if '.' in lower_fn else 'none'}",
            "contribution": 0.3,
            "direction": "increases_risk",
            "human_label": "Double extension / Masqueraded binary disguised as non-executable"
        })
        mitre_tags.append({"id": "T1036", "name": "Masquerading"})

    # Final scoring and verdict calculation
    risk_score = min(100, max(0, int(round(risk_points))))
    if risk_score >= 65:
        verdict = "MALICIOUS"
        severity = "CRITICAL" if risk_score >= 85 else "HIGH"
        confidence = min(0.99, round(0.70 + (risk_score / 350.0), 3))
        threat_class = "C2_DROPPER" if "T1105" in [m["id"] for m in mitre_tags] else (
            "RANSOMWARE" if "T1490" in [m["id"] for m in mitre_tags] else "MALWARE / TROJAN"
        )
    elif risk_score >= 35:
        verdict = "SUSPICIOUS"
        severity = "MEDIUM"
        confidence = round(0.55 + (risk_score / 250.0), 3)
        threat_class = "SUSPICIOUS_SCRIPT"
    else:
        verdict = "CLEAN"
        severity = "LOW"
        confidence = round(0.95 - (risk_score / 100.0), 3)
        threat_class = "BENIGN"

    # Default MITRE fallback
    if not mitre_tags:
        mitre_tags = [{"id": "T1000", "name": "Passive Verification"}]

    return {
        "filename": filename,
        "size_bytes": size,
        "file_type": file_type,
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "entropy": entropy,
        "verdict": verdict,
        "severity": severity,
        "threat_class": threat_class,
        "risk_score": risk_score,
        "confidence": confidence,
        "evidence": evidence,
        "mitre_attack": mitre_tags,
        "scan_time": datetime.now(timezone.utc).isoformat(),
    }


def _analyze_url_content(raw_url: str) -> Dict[str, Any]:
    """Perform static heuristics and domain reputation checks on a URL."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL format")

    host = parsed.netloc.split(":")[0].lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    scheme = parsed.scheme.lower()

    evidence: List[Dict[str, Any]] = []
    mitre_tags: List[Dict[str, str]] = []
    risk_points = 0.0

    # 1. Domain Shannon Entropy (DGA detection)
    host_without_tld = host.rsplit(".", 1)[0]
    domain_entropy = _calculate_entropy(host_without_tld.encode("utf-8"))
    if domain_entropy >= 3.8 and len(host_without_tld) >= 12:
        risk_points += 35.0
        evidence.append({
            "feature": "domain_dga_entropy",
            "value": domain_entropy,
            "contribution": 0.35,
            "direction": "increases_risk",
            "human_label": f"High Domain Entropy ({domain_entropy:.2f}) — Algorithmically Generated Domain (DGA/C2)"
        })
        mitre_tags.append({"id": "T1568.002", "name": "Domain Generation Algorithms"})
    else:
        evidence.append({
            "feature": "domain_entropy",
            "value": domain_entropy,
            "contribution": -0.05,
            "direction": "decreases_risk",
            "human_label": f"Standard Domain Entropy ({domain_entropy:.2f}) — consistent with human-readable brand"
        })

    # 2. Raw IP address in host (Direct C2/botnet connection)
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ip_pattern, host):
        risk_points += 25.0
        evidence.append({
            "feature": "direct_ip_destination",
            "value": host,
            "contribution": 0.25,
            "direction": "increases_risk",
            "human_label": "Direct IP connection without valid domain name (classic C2/phishing indicator)"
        })
        mitre_tags.append({"id": "T1071", "name": "Application Layer Protocol"})

    # 3. Suspicious Top-Level Domains (TLDs)
    risky_tlds = [".top", ".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".buzz"]
    if any(host.endswith(tld) for tld in risky_tlds):
        risk_points += 20.0
        matched_tld = next(tld for tld in risky_tlds if host.endswith(tld))
        evidence.append({
            "feature": "suspicious_tld",
            "value": matched_tld,
            "contribution": 0.2,
            "direction": "increases_risk",
            "human_label": f"High-risk, low-reputation top-level domain ({matched_tld})"
        })

    # 4. Phishing / credential harvesting keywords
    phish_keywords = ["login", "verify", "secure", "account", "update", "banking", "wallet", "recovery", "paypal", "auth", "signin"]
    found_keywords = [kw for kw in phish_keywords if kw in path or kw in host or kw in query]
    if found_keywords:
        risk_points += min(35.0, len(found_keywords) * 15.0)
        evidence.append({
            "feature": "phishing_keywords",
            "value": ", ".join(found_keywords),
            "contribution": 0.3,
            "direction": "increases_risk",
            "human_label": f"Suspicious credential-targeting keywords in URL ({', '.join(found_keywords)})"
        })
        mitre_tags.append({"id": "T1566.002", "name": "Spearphishing Link"})

    # 5. C2 Gate or Exfiltration Paths
    c2_paths = ["gate.php", "panel", "c2", "beacon", "command", "task.php", "exfil", "upload.php", "sink.php"]
    if any(cp in path for cp in c2_paths):
        risk_points += 30.0
        evidence.append({
            "feature": "c2_path_pattern",
            "value": path,
            "contribution": 0.3,
            "direction": "increases_risk",
            "human_label": "Known Command & Control (C2) endpoint / gate URL structure"
        })
        mitre_tags.append({"id": "T1071.001", "name": "Web Protocols C2"})

    # 6. Non-standard ports
    if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
        risk_points += 15.0
        evidence.append({
            "feature": "non_standard_port",
            "value": parsed.port,
            "contribution": 0.15,
            "direction": "increases_risk",
            "human_label": f"Non-standard HTTP port ({parsed.port}) often used for bypass or testing"
        })

    # 7. Unencrypted HTTP with sensitive keywords
    if scheme == "http" and found_keywords:
        risk_points += 15.0
        evidence.append({
            "feature": "insecure_transport",
            "value": "http://",
            "contribution": 0.15,
            "direction": "increases_risk",
            "human_label": "Unencrypted HTTP transport used with credential-harvesting keywords"
        })

    # Scoring & classification
    risk_score = min(100, max(0, int(round(risk_points))))
    if risk_score >= 60:
        verdict = "MALICIOUS"
        severity = "CRITICAL" if risk_score >= 80 else "HIGH"
        confidence = min(0.99, round(0.70 + (risk_score / 350.0), 3))
        threat_class = "C2_ENDPOINT" if "T1071.001" in [m["id"] for m in mitre_tags] else (
            "DGA_DOMAIN" if "T1568.002" in [m["id"] for m in mitre_tags] else "PHISHING_URL"
        )
    elif risk_score >= 30:
        verdict = "SUSPICIOUS"
        severity = "MEDIUM"
        confidence = round(0.55 + (risk_score / 250.0), 3)
        threat_class = "SUSPICIOUS_URL"
    else:
        verdict = "CLEAN"
        severity = "LOW"
        confidence = round(0.96 - (risk_score / 100.0), 3)
        threat_class = "BENIGN_URL"

    if not mitre_tags:
        mitre_tags = [{"id": "T1000", "name": "Passive Verification"}]

    return {
        "url": url,
        "scheme": scheme,
        "host": host,
        "path": path,
        "verdict": verdict,
        "severity": severity,
        "threat_class": threat_class,
        "risk_score": risk_score,
        "confidence": confidence,
        "evidence": evidence,
        "mitre_attack": mitre_tags,
        "scan_time": datetime.now(timezone.utc).isoformat(),
    }


class URLScanRequest(BaseModel):
    url: str


@router.post("/file")
async def scan_file_endpoint(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Upload and inspect a suspicious file (PE, Script, Document, Archive)."""
    try:
        content = await file.read()
        if len(content) > 20 * 1024 * 1024:  # 20MB limit
            raise HTTPException(status_code=413, detail="File too large. Maximum supported size is 20MB.")
        return _analyze_file_content(content, file.filename or "unknown")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")


@router.post("/url")
def scan_url_endpoint(req: URLScanRequest) -> Dict[str, Any]:
    """Inspect and evaluate a suspicious URL or domain."""
    if not req.url or len(req.url.strip()) < 3:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return _analyze_url_content(req.url)
