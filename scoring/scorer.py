from __future__ import annotations

from typing import Any, Dict, List, Tuple

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def score_findings(findings: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    pts = cfg["scoring"]["issues"]
    thresholds = cfg["scoring"]["thresholds"]

    score = 0
    reasons: List[str] = []
    owasp_tags: List[str] = []

    spf = findings["email"]["spf"]
    dmarc = findings["email"]["dmarc"]
    caa = findings["dns"]["caa"]
    dnssec = findings["dns"]["dnssec"]
    tls = findings["web"]["tls"]
    web_probe = findings["web"]["probe"]
    hsts_eval = findings["web"]["hsts_eval"]
    headers = findings["web"]["probe"].get("https", {}).get("headers", {}) if web_probe.get("https_ok") else {}
    cookie_eval = findings["web"].get("cookies_eval", {})

    # SPF
    if not spf.get("present"):
        score += pts["no_spf"]; reasons.append("No SPF record"); owasp_tags.append("A05")
    else:
        pol = (spf.get("policy") or "").lower()
        if "softfail" in pol:
            score += pts["spf_softfail"]; reasons.append("SPF is softfail (~all)"); owasp_tags.append("A05")
        if "neutral" in pol:
            score += pts["spf_neutral"]; reasons.append("SPF is neutral (?all)"); owasp_tags.append("A05")
        if "allow all" in pol:
            score += pts["spf_allow_all"]; reasons.append("SPF allows all (+all)"); owasp_tags.append("A05")
        if any("Multiple SPF" in x for x in spf.get("issues", [])):
            score += pts["spf_multiple_records"]; reasons.append("Multiple SPF records"); owasp_tags.append("A05")
        le = spf.get("lookup_estimate")
        if isinstance(le, int) and le > 10:
            score += pts["spf_lookup_over_10_risk"]; reasons.append("SPF may exceed 10 DNS lookup limit"); owasp_tags.append("A05")

    # DMARC
    if not dmarc.get("present"):
        score += pts["no_dmarc"]; reasons.append("No DMARC record"); owasp_tags.append("A05")
    else:
        pol = (dmarc.get("policy") or "").lower()
        if pol == "none":
            score += pts["dmarc_none"]; reasons.append("DMARC policy is p=none"); owasp_tags.append("A05")
        elif pol == "quarantine":
            score += pts["dmarc_quarantine"]; reasons.append("DMARC policy is p=quarantine"); owasp_tags.append("A05")
        tags = dmarc.get("tags", {})
        if isinstance(tags, dict):
            if "rua" not in tags:
                score += pts["dmarc_no_rua"]; reasons.append("DMARC has no rua reporting"); owasp_tags.append("A05")
            if "pct" in tags:
                try:
                    pct = int(tags["pct"])
                    if pct < 100:
                        score += pts["dmarc_pct_lt_100"]; reasons.append(f"DMARC pct={pct}"); owasp_tags.append("A05")
                except Exception:
                    pass

    # HTTPS/TLS
    if not tls.get("https"):
        score += pts["no_https"]; reasons.append("HTTPS/TLS not reachable"); owasp_tags.append("A02")
    else:
        days = tls.get("days_left")
        if isinstance(days, int):
            if days < 0:
                score += pts["cert_expired"]; reasons.append("TLS certificate expired"); owasp_tags.append("A02")
            elif days < 14:
                score += pts["cert_expires_soon_14d"]; reasons.append("TLS certificate expires soon (<14 days)"); owasp_tags.append("A02")

    # HSTS / headers
    if not hsts_eval.get("present"):
        score += pts["no_hsts"]; reasons.append("HSTS missing"); owasp_tags.append("A05")
    else:
        if hsts_eval.get("issues"):
            score += pts["weak_hsts"]; reasons.append("HSTS could be stronger"); owasp_tags.append("A05")

    if "content-security-policy" not in (headers or {}):
        score += pts["no_csp"]; reasons.append("CSP missing"); owasp_tags.append("A05")

    # Count missing headers
    critical_headers = [
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    missing = [h for h in critical_headers if h not in (headers or {})]
    score += pts["missing_security_headers"] * len(missing)
    if missing:
        reasons.append(f"Missing security headers: {', '.join(missing)}")
        owasp_tags.append("A05")

    # Cookies
    if cookie_eval.get("issues"):
        score += pts["insecure_cookies"]; reasons.append("Cookie flags could be stronger"); owasp_tags.append("A05")

    # DNSSEC / CAA
    if not caa:
        score += pts["no_caa"]; reasons.append("No CAA record (any CA may issue certs)"); owasp_tags.append("A05")
    if not dnssec.get("dnskey_present"):
        score += pts["dnssec_missing"]; reasons.append("DNSSEC not detected (DNSKEY missing)"); owasp_tags.append("A05")

    score = clamp(score, 0, 100)

    # Level
    level = "Low"
    if score >= thresholds["critical"]:
        level = "Critical"
    elif score >= thresholds["high"]:
        level = "High"
    elif score >= thresholds["moderate"]:
        level = "Moderate"

    # de-dup, keep order
    seen=set(); owasp_unique=[]
    for t in owasp_tags:
        if t not in seen:
            seen.add(t); owasp_unique.append(t)

    return {"score_0_100": score, "level": level, "reasons": reasons[:8], "owasp_tags": owasp_unique}
