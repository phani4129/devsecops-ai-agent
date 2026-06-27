"""
cli_scan.py
-------------
Thin command-line wrapper around the same LangGraph pipeline used by app.py.
This is what n8n's "Execute Command" node calls, and it's also useful for
CI/CD pipelines (GitHub Actions, GitLab CI) where you want a security gate
that fails the build on CRITICAL findings without needing a browser.

Usage:
    python cli_scan.py --path test_configs/vulnerable --output /tmp/result.json
    python cli_scan.py --path test_configs/vulnerable --fail-on CRITICAL

Exit codes:
    0 = scan completed, no findings at or above --fail-on threshold
    1 = scan completed, findings at or above --fail-on threshold found
    2 = pipeline error
"""

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from agents.graph import run_pipeline  # noqa: E402

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def collect_files(target_path: str) -> dict:
    """Read all .tf/.yaml/.yml files under target_path into a dict."""
    path = Path(target_path)
    raw_files = {}

    if path.is_file():
        raw_files[str(path)] = path.read_text()
    else:
        for ext in ("*.tf", "*.yaml", "*.yml"):
            for f in path.rglob(ext):
                raw_files[str(f)] = f.read_text()

    return raw_files


def main():
    parser = argparse.ArgumentParser(description="Run the DevSecOps AI Agent pipeline from the CLI.")
    parser.add_argument("--path", required=True, help="File or directory to scan")
    parser.add_argument("--output", default=None, help="Path to write JSON result (default: stdout)")
    parser.add_argument(
        "--fail-on",
        default="CRITICAL",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"],
        help="Exit with code 1 if any finding at or above this severity is found. Use NONE to never fail.",
    )
    args = parser.parse_args()

    raw_files = collect_files(args.path)
    if not raw_files:
        print(f"No .tf/.yaml/.yml files found under {args.path}", file=sys.stderr)
        sys.exit(2)

    scan_target = "kubernetes" if any(f.endswith((".yaml", ".yml")) for f in raw_files) else "terraform"

    try:
        result = run_pipeline(raw_files, scan_target=scan_target)
    except Exception as exc:  # noqa: BLE001
        print(f"Pipeline failed: {exc}", file=sys.stderr)
        sys.exit(2)

    findings = result.get("all_findings", [])
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    output_payload = {
        "scan_target": scan_target,
        "files_scanned": len(raw_files),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "critical_count": severity_counts["CRITICAL"],
        "report_markdown": result.get("final_report_markdown", ""),
        "errors": result.get("errors", []),
    }

    output_json = json.dumps(output_payload, indent=2)

    if args.output:
        Path(args.output).write_text(output_json)
        print(f"Result written to {args.output}")
    else:
        print(output_json)

    if args.fail_on != "NONE":
        threshold = SEVERITY_RANK[args.fail_on]
        triggered = any(SEVERITY_RANK.get(f["severity"], 0) >= threshold for f in findings)
        if triggered:
            print(
                f"\nFAIL: found findings at or above {args.fail_on} severity.",
                file=sys.stderr,
            )
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
