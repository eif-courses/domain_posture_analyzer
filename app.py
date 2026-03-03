from __future__ import annotations

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from auditor import audit
from reports.render import render_report

app = FastAPI(
    title="Domain Security Posture Analyzer",
    description="Public-signal domain security posture (DNS/Email auth/TLS/Headers) with JSON + HTML report.",
    version="1.5.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    # Render via the same report template folder for simplicity
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(loader=FileSystemLoader("reports/templates"), autoescape=select_autoescape(["html","xml"]))
    tpl = env.get_template("home.html")
    return tpl.render()


@app.get("/audit/{domain}", response_class=JSONResponse)
def audit_json(
    domain: str,
    subdomains: bool = Query(True, description="Check a small list of common subdomains (existence only)."),
):
    data = audit(domain, include_subdomains=subdomains)
    return JSONResponse(content=data)


@app.get("/report/{domain}", response_class=HTMLResponse)
def report_html_path(domain: str, request: Request, subdomains: bool = Query(True), theme: str = Query('light')):
    data = audit(domain, include_subdomains=subdomains)
    data['theme'] = theme if theme in ['light','dark'] else 'light'
    html = render_report(data)
    return HTMLResponse(content=html)


@app.get("/report", response_class=HTMLResponse)
def report_html_query(domain: str = Query(..., description="Domain to audit"), subdomains: bool = Query(True), theme: str = Query('light')):
    data = audit(domain, include_subdomains=subdomains)
    data['theme'] = theme if theme in ['light','dark'] else 'light'
    html = render_report(data)
    return HTMLResponse(content=html)
