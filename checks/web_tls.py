from __future__ import annotations

import datetime as dt
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

import httpx

def tls_certificate_info(host: str, *, timeout: float) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        exp: Optional[str] = None
        days_left: Optional[int] = None
        if not_after:
            dt_exp = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            exp = dt_exp.isoformat()
            days_left = (dt_exp - dt.datetime.now(tz=dt.timezone.utc)).days

        return {
            "https": True,
            "expires_at": exp,
            "days_left": days_left,
            "subject": cert.get("subject", []),
            "issuer": cert.get("issuer", []),
        }
    except Exception as e:
        return {"https": False, "error": str(e)}

def http_probe(domain: str, *, timeout: float, user_agent: str) -> Dict[str, Any]:
    """Probe HTTP/HTTPS behavior: redirects, headers, cookies."""
    headers_of_interest = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
        "server",
        "x-powered-by",
    ]

    def _req(url: str) -> Tuple[bool, Dict[str, Any]]:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": user_agent}) as client:
                r = client.get(url)
            found = {k: r.headers.get(k) for k in headers_of_interest if r.headers.get(k)}
            cookies = r.headers.get_list("set-cookie")
            return True, {
                "final_url": str(r.url),
                "status_code": r.status_code,
                "headers": found,
                "set_cookie": cookies[:20],
                "redirect_chain_len": len(r.history),
            }
        except Exception as e:
            return False, {"error": str(e)}

    ok_https, https_data = _req(f"https://{domain}/")
    ok_http, http_data = _req(f"http://{domain}/")

    # Determine HTTPS enforcement
    redirects_to_https = False
    if ok_http and isinstance(http_data.get("final_url"), str):
        redirects_to_https = http_data["final_url"].lower().startswith("https://")

    return {
        "https_ok": ok_https,
        "http_ok": ok_http,
        "http_to_https": redirects_to_https,
        "https": https_data,
        "http": http_data,
    }

def evaluate_hsts(hsts_value: Optional[str]) -> Dict[str, Any]:
    if not hsts_value:
        return {"present": False, "issues": ["HSTS not present"]}
    v = hsts_value.lower()
    issues: List[str] = []
    # weak if max-age < ~180 days
    max_age = None
    for part in v.split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=",1)[1])
            except Exception:
                pass
    if max_age is not None and max_age < 15552000:  # 180 days
        issues.append("HSTS max-age is relatively short (<180 days)")
    if "includesubdomains" not in v:
        issues.append("HSTS missing includeSubDomains (subdomains not protected)")
    return {"present": True, "max_age": max_age, "issues": issues}
