from __future__ import annotations

from typing import Any, Dict, List

import yaml

from utils import utcnow_iso
from checks.dns_email import (
    normalize_domain,
    dns_txt,
    dns_mx,
    dns_caa,
    dns_dnskey_present,
    dns_exists,
    parse_spf,
    parse_dmarc,
    discover_dkim,
    classify_mx_provider,
    check_mta_sts,
    check_tls_rpt,
)
from checks.web_tls import tls_certificate_info, http_probe, evaluate_hsts, check_security_txt, check_robots_txt
from checks.cookies import analyze_set_cookie
from checks.provider_fingerprint import detect_email_provider
from scoring.scorer import score_findings
from scoring.owasp_map import map_tags


def load_config() -> Dict[str, Any]:
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def audit(domain: str, *, include_subdomains: bool = True) -> Dict[str, Any]:
    cfg = load_config()
    d = normalize_domain(domain)

    dns_timeout = float(cfg["dns"]["timeout_seconds"])
    http_timeout = float(cfg["http"]["timeout_seconds"])
    ua = str(cfg["http"]["user_agent"])

    txt_root = dns_txt(d, timeout=dns_timeout)
    spf = parse_spf(txt_root, timeout=dns_timeout)

    mx = dns_mx(d, timeout=dns_timeout)
    mx_provider = classify_mx_provider(mx)

    dmarc_txt = dns_txt(f"_dmarc.{d}", timeout=dns_timeout)
    dmarc = parse_dmarc(dmarc_txt)

    selectors = list(cfg["dkim"]["common_selectors"])
    dkim = discover_dkim(d, selectors, timeout=dns_timeout)

    mta_sts = check_mta_sts(d, timeout=dns_timeout)
    tls_rpt = check_tls_rpt(d, timeout=dns_timeout)

    dkim_cnames = [item["value"] for item in dkim.get("found", []) if item.get("type") == "CNAME/A"]
    email_provider = detect_email_provider(
        mx_hosts=[h for _, h in mx],
        spf_txt_records=txt_root,
        dkim_cnames=dkim_cnames,
    )

    caa = dns_caa(d, timeout=dns_timeout)
    dnssec = {"dnskey_present": dns_dnskey_present(d, timeout=dns_timeout)}

    tls = tls_certificate_info(d, timeout=http_timeout)
    probe = http_probe(d, timeout=http_timeout, user_agent=ua)

    # HSTS eval from HTTPS response
    hsts_value = None
    if probe.get("https_ok"):
        hsts_value = (probe.get("https", {}) or {}).get("headers", {}).get("strict-transport-security")
    hsts_eval = evaluate_hsts(hsts_value)

    # Cookie eval from HTTPS response
    cookies = []
    if probe.get("https_ok"):
        cookies = (probe.get("https", {}) or {}).get("set_cookie", []) or []
    cookies_eval = analyze_set_cookie(cookies)

    security_txt = check_security_txt(d, timeout=http_timeout, user_agent=ua)
    robots_txt = check_robots_txt(d, timeout=http_timeout, user_agent=ua)

    subdomains: List[Dict[str, Any]] = []
    if include_subdomains:
        for s in cfg["dns"]["common_subdomains"]:
            name = f"{s}.{d}"
            target = dns_exists(name, timeout=dns_timeout)
            subdomains.append({"name": name, "exists": target is not None, "target": target})

    findings: Dict[str, Any] = {
        "domain": d,
        "generated_at_utc": utcnow_iso(),
        "theme": "light",
        "app": cfg["app"],
        "dns": {"mx": mx, "mx_provider": mx_provider, "txt_root": txt_root, "caa": caa, "dnssec": dnssec},
        "email": {"spf": spf, "dmarc": dmarc, "dkim": dkim, "mta_sts": mta_sts, "tls_rpt": tls_rpt, "provider": email_provider},
        "web": {"tls": tls, "probe": probe, "hsts_eval": hsts_eval, "cookies_eval": cookies_eval,
                "security_txt": security_txt, "robots_txt": robots_txt},
        "osint": {"common_subdomains": subdomains},
        "limitations": [
            "Public-signal posture assessment only (DNS/HTTP/TLS). Not a penetration test.",
            "DKIM selector discovery is heuristic; absence does not prove DKIM is missing.",
            "Some sites block automated requests or serve different headers to non-browsers.",
        ],
    }

    risk = score_findings(findings, cfg)
    findings["risk"] = risk
    findings["owasp_mapped"] = map_tags(risk.get("owasp_tags", []))

    findings["recommendations"] = build_recommendations(findings)

    return findings


def derive_check_statuses(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a flat dict of check-name → {status, value} for every signal.

    Status values: "good" | "warn" | "bad" | "info"
    This mirrors the status logic used in the HTML report template so API
    consumers get consistent signal colours without re-implementing them.
    """
    spf   = data["email"]["spf"]
    dmarc = data["email"]["dmarc"]
    dkim  = data["email"]["dkim"]
    mta   = data["email"]["mta_sts"]
    tlsr  = data["email"]["tls_rpt"]
    tls   = data["web"]["tls"]
    probe = data["web"]["probe"]
    hsts  = data["web"]["hsts_eval"]
    ck    = data["web"]["cookies_eval"]
    dnssec = data["dns"]["dnssec"]
    caa    = data["dns"]["caa"]

    headers: Dict[str, Any] = {}
    if probe.get("https_ok"):
        headers = (probe.get("https") or {}).get("headers") or {}

    # ── SPF ──────────────────────────────────────────────────────────────
    spf_status = "good"
    if not spf.get("present"):
        spf_status = "bad"
    elif "allow all" in (spf.get("policy") or "").lower():
        spf_status = "bad"
    elif spf.get("issues") or "softfail" in (spf.get("resolved_policy") or spf.get("policy") or "").lower():
        spf_status = "warn"

    # ── DMARC ─────────────────────────────────────────────────────────────
    dmarc_status = "good"
    if not dmarc.get("present"):
        dmarc_status = "bad"
    elif (dmarc.get("policy") or "").lower() in ("none", "quarantine"):
        dmarc_status = "warn"

    # ── TLS ───────────────────────────────────────────────────────────────
    tls_status = "good"
    if not tls.get("https"):
        tls_status = "bad"
    elif tls.get("days_left") is not None and int(tls["days_left"]) < 14:
        tls_status = "warn"
    if tls.get("https") and tls.get("days_left") is not None:
        tls_value = f"expires in ~{tls['days_left']} days"
    elif not tls.get("https"):
        tls_value = "not reachable"
    else:
        tls_value = "unknown"

    hsts_status   = "good" if hsts.get("present") and not hsts.get("issues") else "warn"
    csp_status    = "good" if "content-security-policy" in headers else "warn"
    caa_status    = "good" if caa else "warn"
    dnssec_status = "good" if dnssec.get("dnskey_present") else "warn"
    mta_status    = "good" if mta.get("dns_present") else "info"
    tlsr_status   = "good" if tlsr.get("present") else "info"
    cookie_status = "good" if not ck.get("issues") else "warn"
    dkim_status   = "good" if dkim.get("present_likely") else "warn"

    sec_txt  = data["web"].get("security_txt", {})
    rob_txt  = data["web"].get("robots_txt", {})
    provider = data["email"].get("provider", {})

    dkim_value = "selectors found" if dkim.get("present_likely") else "selector not discovered"
    dkim_note = "DKIM discovery is best-effort; absence does not prove DKIM is missing" if not dkim.get("present_likely") else None

    sec_txt_note = None if sec_txt.get("present") else "Some organizations publish security.txt only on their primary domain"

    provider_name = provider.get("name", "Unknown")
    provider_conf = provider.get("confidence", "low")
    provider_value = f"{provider_name}" if provider_name != "Unknown" else "not identified"
    provider_note = "; ".join(provider.get("evidence", [])) or None

    return {
        "spf":           {"status": spf_status,    "value": spf.get("policy") if spf.get("present") else "missing"},
        "dmarc":         {"status": dmarc_status,   "value": dmarc.get("policy") if dmarc.get("present") else "missing"},
        "dkim":          {"status": dkim_status,    "value": dkim_value, "confidence": "low" if not dkim.get("present_likely") else "medium", "note": dkim_note},
        "mta_sts":       {"status": mta_status,     "value": "present" if mta.get("dns_present") else "not detected"},
        "tls_rpt":       {"status": tlsr_status,    "value": "present" if tlsr.get("present") else "not detected"},
        "https_tls":     {"status": tls_status,     "value": tls_value},
        "http_to_https": {"status": "good" if probe.get("http_to_https") else "warn", "value": "yes" if probe.get("http_to_https") else "no/unknown"},
        "hsts":          {"status": hsts_status,    "value": "present" if hsts.get("present") else "missing"},
        "csp":           {"status": csp_status,     "value": "present" if "content-security-policy" in headers else "missing"},
        "caa":           {"status": caa_status,     "value": "present" if caa else "missing"},
        "dnssec":        {"status": dnssec_status,  "value": "DNSKEY present" if dnssec.get("dnskey_present") else "not detected"},
        "cookies":       {"status": cookie_status,  "value": f"{ck.get('cookies_seen', 0)} seen, {len(ck.get('issues') or [])} issue(s)"},
        "security_txt":  {"status": "good" if sec_txt.get("present") else "info", "value": "present" if sec_txt.get("present") else "not found", "note": sec_txt_note},
        "robots_txt":    {"status": "good" if rob_txt.get("present") else "info", "value": "present" if rob_txt.get("present") else "not found"},
        "email_provider": {"status": "info", "value": provider_value, "confidence": provider_conf, "note": provider_note},
    }


def build_recommendations(f: Dict[str, Any]) -> List[str]:
    recs: List[str] = []
    spf = f["email"]["spf"]
    dmarc = f["email"]["dmarc"]
    mta = f["email"]["mta_sts"]
    tlsr = f["email"]["tls_rpt"]
    hsts_eval = f["web"]["hsts_eval"]
    tls = f["web"]["tls"]
    caa = f["dns"]["caa"]
    dnssec = f["dns"]["dnssec"]
    headers = (f["web"]["probe"].get("https", {}) or {}).get("headers", {}) if f["web"]["probe"].get("https_ok") else {}

    # Email
    if not spf.get("present"):
        recs.append("Publish an SPF TXT record authorizing your legitimate sending services.")
    else:
        if "softfail" in (spf.get("policy") or "").lower():
            recs.append("When ready, move SPF from ~all to -all after confirming all senders are included.")
        if any("Multiple SPF" in x for x in spf.get("issues", [])):
            recs.append("Ensure you have exactly ONE SPF TXT record (merge multiple records into one).")
        le = spf.get("lookup_estimate")
        if isinstance(le, int) and le > 10:
            recs.append("Reduce SPF DNS lookups (limit is 10): simplify includes or use a flattening strategy with care.")

    if not dmarc.get("present"):
        recs.append("Add a DMARC record at _dmarc. Start with p=none (monitor), then move to quarantine/reject.")
    else:
        pol = (dmarc.get("policy") or "").lower()
        if pol == "none":
            recs.append("Move DMARC from p=none to p=quarantine, then p=reject after reviewing reports.")
        tags = dmarc.get("tags", {})
        if isinstance(tags, dict) and "rua" not in tags:
            recs.append("Add DMARC rua=mailto:... to receive aggregate reports.")
        if isinstance(tags, dict) and "pct" in tags:
            try:
                pct = int(tags["pct"])
                if pct < 100:
                    recs.append("Set DMARC pct=100 once monitoring looks stable, to protect all mail.")
            except Exception:
                pass

    if not mta.get("dns_present"):
        recs.append("Consider enabling MTA-STS (plus a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt) to harden inbound mail TLS.")
    if not tlsr.get("present"):
        recs.append("Consider enabling TLS-RPT to receive reports about mail transport TLS issues.")

    # Web/TLS
    if not tls.get("https"):
        recs.append("Enable HTTPS with a valid certificate and redirect HTTP to HTTPS.")
    else:
        days = tls.get("days_left")
        if isinstance(days, int) and days < 14:
            recs.append("Renew TLS certificate soon (less than 14 days remaining).")

    if not hsts_eval.get("present"):
        recs.append("Enable HSTS (Strict-Transport-Security).")
    elif hsts_eval.get("issues"):
        recs.append("Strengthen HSTS (longer max-age and consider includeSubDomains).")

    if "content-security-policy" not in headers:
        recs.append("Add a Content-Security-Policy (CSP) to reduce XSS risk (start in report-only mode if needed).")

    # Disclosure
    sec_txt = f.get("web", {}).get("security_txt", {})
    if not sec_txt.get("present"):
        recs.append("Publish a security.txt file at /.well-known/security.txt (RFC 9116) so researchers can report vulnerabilities responsibly.")

    # DNS
    if not caa:
        recs.append("Add a CAA record to restrict which certificate authorities can issue certificates for your domain.")
    if not dnssec.get("dnskey_present"):
        recs.append("Consider enabling DNSSEC to reduce DNS spoofing risk (depends on registrar/DNS provider).")

    recs.append("For application email: do not forge From: use an approved sender and set Reply-To for end-user addresses.")
    recs.append("For deeper testing (OWASP ZAP active scan), get written authorization and prefer a staging/lab target.")

    # de-dup, keep order
    out=[]
    seen=set()
    for r in recs:
        if r not in seen:
            seen.add(r); out.append(r)
    return out
