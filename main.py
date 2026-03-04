from __future__ import annotations

from fastapi import FastAPI, Query, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from auditor import audit, derive_check_statuses
from reports.render import render_report

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Domain Security Posture Analyzer",
    description="""
Public-signal domain security posture assessment (DNS / Email auth / TLS / HTTP headers).

## REST API  — `/api/v1/{domain}/…`

| Endpoint | Returns |
|---|---|
| `GET /api/v1/{domain}` | Full audit JSON |
| `GET /api/v1/{domain}/summary` | Score + flat check statuses — ideal for dashboards |
| `GET /api/v1/{domain}/email` | Email checks: SPF · DKIM · DMARC · MTA-STS · TLS-RPT |
| `GET /api/v1/{domain}/web` | Web checks: TLS cert · HSTS · CSP · Cookies |
| `GET /api/v1/{domain}/dns` | DNS checks: CAA · DNSSEC · subdomains |
| `GET /api/v1/{domain}/score` | Risk score, level, reasons, OWASP tags |

Legacy endpoint `GET /audit/{domain}` remains for backwards compatibility.

All `/api/v1/` endpoints support CORS (`*`) so you can call them from any frontend.
""",
    version="1.6.0",
)

# ── CORS — allow any origin so students can call this from their own UIs ──────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── HTML pages ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home() -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(loader=FileSystemLoader("reports/templates"), autoescape=select_autoescape(["html", "xml"]))
    tpl = env.get_template("home.html")
    return tpl.render()


@app.get("/report/{domain}", response_class=HTMLResponse, include_in_schema=False)
def report_html_path(domain: str, request: Request, subdomains: bool = Query(True), theme: str = Query("light")):
    data = audit(domain, include_subdomains=subdomains)
    data["theme"] = theme if theme in ("light", "dark") else "light"
    return HTMLResponse(content=render_report(data))


@app.get("/report", response_class=HTMLResponse, include_in_schema=False)
def report_html_query(domain: str = Query(..., description="Domain to audit"), subdomains: bool = Query(True), theme: str = Query("light")):
    data = audit(domain, include_subdomains=subdomains)
    data["theme"] = theme if theme in ("light", "dark") else "light"
    return HTMLResponse(content=render_report(data))


# ── Legacy JSON endpoint (kept for backwards compatibility) ───────────────────

@app.get(
    "/audit/{domain}",
    response_class=JSONResponse,
    tags=["Legacy"],
    summary="Full audit (legacy — prefer /api/v1/{domain})",
)
def audit_json_legacy(
    domain: str,
    subdomains: bool = Query(True, description="Check common subdomains (existence only)."),
):
    return JSONResponse(content=audit(domain, include_subdomains=subdomains))


# ── API v1 ────────────────────────────────────────────────────────────────────

v1 = APIRouter(prefix="/api/v1", tags=["API v1"])


@v1.get(
    "/{domain}",
    summary="Full audit",
    description="Complete audit result: email, web/TLS, DNS, risk score, recommendations.",
)
def api_full(
    domain: str,
    subdomains: bool = Query(True, description="Include subdomain existence checks."),
):
    return audit(domain, include_subdomains=subdomains)


@v1.get(
    "/{domain}/summary",
    summary="Dashboard summary",
    description="""
Lightweight summary ideal for **building dashboards**.

Returns the risk score and a flat `checks` object where every key maps to
`{ "status": "good"|"warn"|"bad"|"info", "value": "<human string>" }`.

Checks included: `spf`, `dmarc`, `dkim`, `mta_sts`, `tls_rpt`,
`https_tls`, `http_to_https`, `hsts`, `csp`, `caa`, `dnssec`, `cookies`.
""",
)
def api_summary(domain: str):
    data = audit(domain, include_subdomains=False)
    return {
        "domain": data["domain"],
        "generated_at_utc": data["generated_at_utc"],
        "score": data["risk"]["score_0_100"],
        "level": data["risk"]["level"],
        "checks": derive_check_statuses(data),
        "recommendations": data["recommendations"],
    }


@v1.get(
    "/{domain}/email",
    summary="Email security checks",
    description="SPF · DKIM (best-effort) · DMARC · MTA-STS · TLS-RPT details.",
)
def api_email(domain: str):
    data = audit(domain, include_subdomains=False)
    return {
        "domain": data["domain"],
        "generated_at_utc": data["generated_at_utc"],
        "mx_provider": data["dns"]["mx_provider"],
        "provider": data["email"].get("provider", {}),
        "spf": data["email"]["spf"],
        "dkim": data["email"]["dkim"],
        "dmarc": data["email"]["dmarc"],
        "mta_sts": data["email"]["mta_sts"],
        "tls_rpt": data["email"]["tls_rpt"],
    }


@v1.get(
    "/{domain}/web",
    summary="Web & TLS checks",
    description="TLS certificate · HTTP→HTTPS redirect · HSTS · Security headers · CSP · Cookies.",
)
def api_web(domain: str):
    data = audit(domain, include_subdomains=False)
    return {
        "domain": data["domain"],
        "generated_at_utc": data["generated_at_utc"],
        "tls": data["web"]["tls"],
        "probe": data["web"]["probe"],
        "hsts_eval": data["web"]["hsts_eval"],
        "cookies_eval": data["web"]["cookies_eval"],
    }


@v1.get(
    "/{domain}/dns",
    summary="DNS posture checks",
    description="CAA records · DNSSEC · MX info · optional common-subdomain existence checks.",
)
def api_dns(
    domain: str,
    subdomains: bool = Query(True, description="Include subdomain existence checks."),
):
    data = audit(domain, include_subdomains=subdomains)
    return {
        "domain": data["domain"],
        "generated_at_utc": data["generated_at_utc"],
        "mx": data["dns"]["mx"],
        "mx_provider": data["dns"]["mx_provider"],
        "caa": data["dns"]["caa"],
        "dnssec": data["dns"]["dnssec"],
        "common_subdomains": data["osint"]["common_subdomains"],
    }


@v1.get(
    "/{domain}/score",
    summary="Risk score",
    description="Numerical risk score (0–100), level, contributing reasons, and OWASP category mapping.",
)
def api_score(domain: str):
    data = audit(domain, include_subdomains=False)
    return {
        "domain": data["domain"],
        "generated_at_utc": data["generated_at_utc"],
        "score": data["risk"]["score_0_100"],
        "level": data["risk"]["level"],
        "reasons": data["risk"].get("reasons", []),
        "owasp_tags": data["risk"].get("owasp_tags", []),
        "owasp_mapped": data["owasp_mapped"],
    }


app.include_router(v1)
