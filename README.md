# quick-bugtool

**Quick prototype static scanner** — a single-file, regex-based tool to find common insecure patterns in source code.  
Designed as a fast submission artifact you can run locally and upload to GitHub.

---

## What this project contains

- `quick_bugtool.py` — the scanner script (single-file prototype).
- `targets/` — (optional) example target files (e.g., `targets/sampleapp/vuln.py`).
- `out/` — output folder produced after scanning:
  - `out/findings.json` — machine-readable findings (JSON array).
  - `out/report.txt` — human-readable summary.
  - `out/hackerone_preview.json` — preview payloads for HackerOne report(s).
- `README.md` — this file.

---

## Purpose / Scope

`quick-bugtool` is a **lightweight prototype** for detecting insecure code patterns (examples: `eval()`, `subprocess(..., shell=True)`, hardcoded secrets, weak hashing). It is:

- **Fast** and easy to run locally.
- **Passive**: only scans files on disk (no network/DAST scanning).
- **Prototype-level**: uses regex heuristics and will produce false positives. It is intended as a starter tool to demonstrate capability in a task submission.

---

## Usage (run locally)

### Prerequisites
- Python 3.7+ installed.

### Run scanner
```bash
# from project root
python3 quick_bugtool.py /path/to/target --out out
