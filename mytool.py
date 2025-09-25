#!/usr/bin/env python3
"""
quick_bugtool.py
Quick scanner: finds common insecure patterns and produces JSON + HackerOne preview.
Usage:
  python quick_bugtool.py /path/to/target --out outdir
"""
import os, re, json, sys, argparse
from pathlib import Path

PATTERNS = {
    "eval_usage": {
        "pattern": re.compile(r"\beval\s*\("),
        "severity": "high",
        "cwe": "CWE-94",
        "desc": "Use of eval() - dynamic code execution risk"
    },
    "subprocess_shell_true": {
        "pattern": re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"),
        "severity": "high",
        "cwe": "CWE-78",
        "desc": "subprocess(...) with shell=True - shell injection risk"
    },
    "hardcoded_secret": {
        "pattern": re.compile(r"(?i)(password|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
        "severity": "high",
        "cwe": "CWE-798",
        "desc": "Hardcoded credential or secret literal"
    },
    "sql_concat": {
        "pattern": re.compile(r"(SELECT|UPDATE|DELETE|INSERT).*(\+|\%|\$|\)|format\()"),
        "severity": "medium",
        "cwe": "CWE-89",
        "desc": "Possible SQL built by string concatenation/formatting"
    },
    "weak_crypto": {
        "pattern": re.compile(r"\b(MD5|md5|SHA1|sha1)\b"),
        "severity": "medium",
        "cwe": "CWE-327",
        "desc": "Use of weak hashing function"
    }
}

IGNORED_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}

def scan_file(path, relpath):
    findings = []
    try:
        txt = path.read_text(errors="ignore")
    except Exception:
        return findings
    for rule, info in PATTERNS.items():
        for m in info["pattern"].finditer(txt):
            line = txt[:m.start()].count("\n") + 1
            snippet = txt.splitlines()[line-1].strip()[:300]
            findings.append({
                "tool": "quick_bugtool",
                "rule": rule,
                "description": info["desc"],
                "file": relpath,
                "line": line,
                "snippet": snippet,
                "severity": info["severity"],
                "cwe": info["cwe"]
            })
    return findings

def scan_dir(target):
    t = Path(target)
    all_findings = []
    if t.is_file():
        all_findings += scan_file(t, str(t))
        return all_findings
    for root, dirs, files in os.walk(t):
        # prune ignored dirs
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for f in files:
            if f.endswith(('.py','.js','.java','.php','.go','.rb','.ts','.scala','.sh','.env','.yml','.yaml')):
                p = Path(root) / f
                rel = os.path.relpath(p, start=t)
                all_findings += scan_file(p, rel)
    return all_findings

def build_hackerone_preview(findings):
    reports = []
    for f in findings:
        title = f"Automated: {f['rule']} in {f['file']}:{f['line']}"
        steps = f"File: {f['file']}\nLine: {f['line']}\nSeverity: {f['severity']}\nSnippet:\n{f['snippet']}\n\nDescription: {f['description']}"
        reports.append({
            "title": title,
            "vulnerability_information": f["description"],
            "weakness": f.get("cwe","N/A"),
            "impact": "Potential security impact; verify in context.",
            "steps_to_reproduce": steps
        })
    return reports

def pretty_text(findings):
    if not findings:
        return "No findings found.\n"
    lines = []
    for i,f in enumerate(findings,1):
        lines.append(f"{i}. {f['rule']} - {f['description']}")
        lines.append(f"   File: {f['file']}:{f['line']}  Severity: {f['severity']}  CWE: {f['cwe']}")
        lines.append(f"   Snippet: {f['snippet']}")
        lines.append("")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Target file or directory to scan")
    ap.add_argument("--out","-o", default="out", help="Output folder (created if needed)")
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Scanning {args.target} ...")
    findings = scan_dir(args.target)
    print(f"[+] {len(findings)} finding(s) discovered.")

    # Save JSON
    fjson = outdir / "findings.json"
    fjson.write_text(json.dumps(findings, indent=2))
    print(f"[+] Wrote {fjson}")

    # Save human report
    freport = outdir / "report.txt"
    freport.write_text(pretty_text(findings))
    print(f"[+] Wrote {freport}")

    # HackerOne preview
    hpreview = outdir / "hackerone_preview.json"
    hreports = build_hackerone_preview(findings)
    hpreview.write_text(json.dumps(hreports, indent=2))
    print(f"[+] Wrote {hpreview}")

    print("[+] Done. Attach the 'out' folder to your submission.")

if __name__ == "__main__":
    main()
