from __future__ import annotations

import argparse
from pathlib import Path

from auditor import audit
from reports.render import render_report

def main() -> None:
    p = argparse.ArgumentParser(description="Generate a domain security posture report (HTML + JSON).")
    p.add_argument("domain", help="Domain to audit (e.g., example.com)")
    p.add_argument("--no-subdomains", action="store_true", help="Disable common subdomain existence checks.")
    p.add_argument("--out", default="report.html", help="Output HTML file path.")
    p.add_argument("--json", default="", help="Optional JSON output file path.")
    args = p.parse_args()

    data = audit(args.domain, include_subdomains=not args.no_subdomains)
    html = render_report(data)
    Path(args.out).write_text(html, encoding="utf-8")
    print(f"Wrote HTML report: {args.out}")

    if args.json:
        import json
        Path(args.json).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Wrote JSON: {args.json}")

if __name__ == "__main__":
    main()
