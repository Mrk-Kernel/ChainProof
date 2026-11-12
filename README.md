# 🛡️ ChainProof - Tamper-Evident Chain-of-Custody Toolkit

A Python-based digital forensics tool built for tracking evidence and chain of custody.  
Hashes evidence (SHA-256 + SHA-3-256), writes every action to a hash-chained, Ed25519-signed audit log, supports RFC 3161 trusted timestamps, and exports custody reports in JSON or PDF.  
Designed around ISO/IEC 27037 and ENFSI guidelines — but keep reading, this is a student/educational prototype, not a certified forensic product.

## ✨ Features

- 📁 **File Hashing** — SHA-256 + SHA-3-256 for every evidence file
- 🔐 **Tamper-Evident Log** — Hash-chained, Ed25519-signed audit entries
- ⏱️ **Trusted Timestamps** — Optional RFC 3161 TSA timestamps per entry and on the head hash
- 🔍 **Verify Evidence** — Re-hash files on disk and compare with logged hashes
- 📄 **Custody Reports** — JSON or PDF with public key fingerprint + head hash
- 🛡️ **Crash-Safe** — File lock + fsync on every log append
- 🧪 **Tested** — 9 pytest tamper tests + GitHub Actions CI

## ⚠️ Security — read this first

By default the Ed25519 signing key lives **inside** the case directory (`case/keys/`). Anyone with access to that folder can recompute every entry hash and re-sign the whole chain — verification would still pass on a fake log.

**Use `--key-dir` to store the key outside the case directory and protect it separately.**

Also: deleting the last N log entries leaves a valid chain (truncation is a known limitation). See `THREAT_MODEL.md` and `LIMITATIONS.md` for the full honest picture.

## 📦 Requirements

- Python 3.10+
- `cryptography`, `fpdf2`
- `pytest`, `pytest-cov` (for tests)

## 🚀 Install

```bash
git clone https://github.com/Mrk-Kernel/ChainProof.git
cd ChainProof
python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate
pip install -e ".[dev]"
```

Or install the console script:
```bash
pip install -e .
chainproof --help
```

## 🖥️ Usage

```bash
# Initialize a new case
chainproof init mycase --actor analyst --key-dir /secure/keys/mycase

# Add evidence
chainproof add mycase\evidence\file.bin --case-dir mycase --actor analyst

# With RFC 3161 trusted timestamp (try https://freetsa.org)
chainproof add mycase\evidence\file.bin --case-dir mycase \
  --actor analyst --tsa-url https://freetsa.org/tsr

# Log a custody action
chainproof action TRANSFER analyst "handed to lab #2" --case-dir mycase

# Verify the chain
chainproof verify --case-dir mycase

# Also re-hash evidence files on disk and compare
chainproof verify --case-dir mycase --evidence

# Export a custody report
chainproof report --case-dir mycase --format pdf --out mycase\reports\custody.pdf

# Anchor the head hash with a TSA before exporting
chainproof report --case-dir mycase --format json --anchor \
  --tsa-url https://freetsa.org/tsr --out mycase\reports\custody.json

# Show standards alignment
chainproof standards
```

## 📄 Report Output

PDF reports are saved to the `reports/` folder:
```
reports/custody_report.pdf
```

Reports include: case directory, public key fingerprint (SHA-256), head hash, chain verification result, head anchor (if `--anchor` was used), and all log entries.

## 🖥️ Platform

- Kali Linux / Windows / macOS (Python 3.10+)

## 🧪 Tests

```bash
python -m pytest
```

Tests cover: untouched chain, entry edit, middle-entry deletion, truncation (known limitation), reordering, key replacement, evidence tampering, genesis signature, and head-hash change on append. Runs on every push via GitHub Actions.

## 📜 Standards Alignment

ChainProof is **aligned with** (not compliant to):

- **ISO/IEC 27037:2012** — identification, collection, acquisition, preservation
- **ISO/IEC 27041/27042/27043** — analysis, evaluation, reporting, testimony
- **ENFSI** — integrity, documentation, traceability, reproducibility, independence

## 👤 Author

Mrk-Kernel  
GitHub: https://github.com/Mrk-Kernel

## ⚖️ License

MIT License. See `LICENSE`.

## 🛑 Disclaimer

Educational prototype. Not a certified forensic product. Hash chains and signatures are supporting evidence, not proof of legal admissibility.
