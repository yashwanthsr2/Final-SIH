# Contributing to CyberSentinel

Thank you for your interest in contributing to **CyberSentinel**! 

CyberSentinel is an AI-powered cyber threat intelligence platform developed for the **Smart India Hackathon (NTRO SIH26-26145)** problem statement: *"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic"*.

---

## ⚠️ Mandatory Compliance: Passive-Only Constraint

All contributions **must** adhere strictly to the passive monitoring guidelines mandated by NTRO SIH26-26145:

1. **Zero Packet Transmission:** CyberSentinel is a passive observer (Data Diode / TAP compatible). Code must **never** transmit SYN packets, ARP requests, ICMP pings, DNS probes, or active scanner requests.
2. **No Payload Decryption:** CyberSentinel does **not** perform TLS interception, SSL stripping, or MITM decryption. Encrypted traffic analysis must rely purely on observable flow metadata (packet timing, burst entropy, byte ratios, and TLS handshake records).
3. **No Active Mitigation Commands:** The core ingest and detection engines must never issue blocking/firewall drop commands directly from the sensor thread.

Any PR that introduces active network probing or payload decryption will be rejected immediately.

---

## Getting Started

### 1. Prerequisites
- **Python:** 3.11 or higher (Python 3.11 - 3.14 tested)
- **Git:** Version 2.30+
- **Docker & Docker Compose:** (Optional, for containerized deployments)
- **libpcap:** (`libpcap-dev` on Linux/Debian; Npcap on Windows if running live capture)

### 2. Fork and Clone
```bash
git clone https://github.com/your-username/CyberSentinel.git
cd CyberSentinel
```

### 3. Set Up Virtual Environment
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies
```bash
pip install --upgrade pip
pip install -r backend/requirements.txt
pip install pytest flake8
```

### 5. Configure Environment
```bash
# Linux / macOS
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

### 6. Initialize Database & Run Server
```bash
# Initialize SQLite database
python -c "import backend.app.database as db; db.init_db()"

# Start CyberSentinel backend
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Access the live dashboard at `http://127.0.0.1:8000/`.

---

## Development Standards

### Code Style & Formatting
- Follow **PEP 8** style guidelines for all Python code.
- Provide explicit **Type Hints** (`typing` module / Python 3.10+ syntax) for all function signatures.
- Write clear docstrings for classes and public API methods.
- Run linter before pushing:
  ```bash
  flake8 backend ml tests --count --select=E9,F63,F7,F82 --show-source --statistics
  ```

### Zero Mock Data Policy
Production code, backend APIs, and dashboard views must consume actual telemetry. Mock data, fake random risk scores, or hardcoded threat predictions are strictly prohibited in production branches. Test mocks must be isolated exclusively within `tests/` directories.

---

## Testing & Quality Assurance

Before submitting any Pull Request, run the complete automated test suite:

```bash
# 1. Run integration tests
python tests/integration/test_integration.py

# 2. Run all six detector validation tests
python tests/integration/test_six_detectors.py

# 3. Run canonical 4-input pipeline convergence test
python tests/integration/test_canonical_pipeline_convergence.py

# 4. Run API endpoint validation suite (34 endpoints)
python tests/e2e/test_all_apis.py

# 5. Run clean installation test
python scripts/verify_clean_installation.py

# 6. Run full pytest suite
pytest -v tests/
```

Ensure all tests pass with zero failures.

---

## Pull Request Guidelines

1. **Branch Naming:**
   - Features: `feat/feature-name`
   - Bug fixes: `fix/issue-description`
   - Documentation: `docs/doc-update`
   - Refactoring: `refactor/component-name`

2. **Commit Messages:**
   - Write clear, imperative commit messages:
     - `feat: add temporal jitter extraction to feature pipeline`
     - `fix: resolve division by zero in flow entropy calculation`
     - `docs: update deployment guide for Docker Compose v2`

3. **Checklist Before Submitting:**
   - [ ] No secrets, passwords, or API keys committed
   - [ ] `.env` and SQLite database files (`db/*.db`) are excluded
   - [ ] Automated test suite passes 100%
   - [ ] Passive compliance verified (`assert_passive_compliance()` passes)
   - [ ] Documentation updated to reflect changes

---

## Reporting Security Issues

If you discover a security vulnerability or credential exposure within CyberSentinel, please **do not open a public GitHub issue**. Instead, report it privately to the maintainers at `security@cybersentinel.local` or via GitHub Security Advisories.
