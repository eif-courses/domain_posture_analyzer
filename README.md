# Domain Security Posture Analyzer (Workshop v1.4)

A **passive** domain security posture tool for education:
- DNS + Email authentication (SPF/DKIM/DMARC, MTA-STS, TLS-RPT)
- TLS certificate checks
- HTTP security headers & cookie flags
- Risk score + recommendations
- Outputs **HTML report** and **JSON**

> This is a posture assessment tool based on **public signals**. It is **not** a penetration test.

## Run (FastAPI)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

pip install -r requirements.txt
uvicorn app:app --reload
```

Open:
- Home: http://127.0.0.1:8000/
- HTML report: http://127.0.0.1:8000/report/example.com
- JSON: http://127.0.0.1:8000/audit/example.com

## Run (CLI)

```bash
python cli.py example.com --out report.html --json report.json
```

## Safe use policy

Allowed (no permission needed):
- DNS queries (MX/TXT/CAA/DNSKEY)
- HTTPS/TLS certificate info
- HTTP response headers
- Cookie flags from normal HTTP responses

Not allowed without explicit authorization:
- Active vulnerability scanning (e.g., OWASP ZAP active scan)
- Fuzzing, brute force, DoS
- High-intensity crawling

## Extending

Add checks under `checks/` and update scoring rules in `config.yaml`.
