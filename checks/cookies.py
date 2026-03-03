from __future__ import annotations

from typing import Any, Dict, List

def analyze_set_cookie(set_cookie_headers: List[str]) -> Dict[str, Any]:
    """Basic cookie flag checks (best-effort)."""
    issues: List[str] = []
    cookies: List[Dict[str, Any]] = []
    for raw in set_cookie_headers or []:
        lower = raw.lower()
        cookies.append({
            "raw": raw,
            "secure": " secure" in lower or lower.endswith("secure"),
            "httponly": " httponly" in lower or lower.endswith("httponly"),
            "samesite": "samesite=" in lower,
        })
    insecure = [c for c in cookies if not c["secure"] or not c["httponly"]]
    if cookies and insecure:
        issues.append("Some cookies are missing Secure and/or HttpOnly flags")
    if cookies and any(not c["samesite"] for c in cookies):
        issues.append("Some cookies are missing SameSite attribute")
    return {"cookies_seen": len(cookies), "issues": issues, "details": cookies[:10]}
