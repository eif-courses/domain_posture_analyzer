from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver

_SPF_RE = re.compile(r"\bv=spf1\b", re.IGNORECASE)
_DMARC_RE = re.compile(r"\bv=DMARC1\b", re.IGNORECASE)

def normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        raise ValueError("Domain is empty")
    try:
        d_idna = d.encode("idna").decode("ascii")
    except Exception as e:
        raise ValueError(f"Invalid domain (IDNA error): {e}")
    if len(d_idna) > 253:
        raise ValueError("Domain too long")
    return d_idna

def _resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.lifetime = timeout
    r.timeout = min(timeout, 2.0)
    return r

def dns_txt(name: str, *, timeout: float) -> List[str]:
    try:
        r = _resolver(timeout)
        ans = r.resolve(name, "TXT")
        out: List[str] = []
        for rec in ans:
            # dnspython may store parts; join
            out.append("".join([b.decode("utf-8", "ignore") for b in rec.strings]))
        return out
    except Exception:
        return []

def dns_mx(name: str, *, timeout: float) -> List[Tuple[int, str]]:
    try:
        r = _resolver(timeout)
        ans = r.resolve(name, "MX")
        out: List[Tuple[int, str]] = []
        for rec in ans:
            out.append((int(rec.preference), str(rec.exchange).rstrip(".")))
        out.sort(key=lambda x: x[0])
        return out
    except Exception:
        return []

def dns_caa(name: str, *, timeout: float) -> List[str]:
    try:
        r = _resolver(timeout)
        ans = r.resolve(name, "CAA")
        return [f"{rec.flags} {rec.tag} {rec.value}" for rec in ans]
    except Exception:
        return []

def dns_dnskey_present(name: str, *, timeout: float) -> bool:
    """Best-effort DNSSEC hint: presence of DNSKEY record."""
    try:
        r = _resolver(timeout)
        _ = r.resolve(name, "DNSKEY")
        return True
    except Exception:
        return False

def dns_exists(name: str, *, timeout: float) -> Optional[str]:
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            r = _resolver(timeout)
            ans = r.resolve(name, rtype)
            rec = ans[0]
            if rtype == "CNAME":
                return str(rec.target).rstrip(".")
            return str(rec)
        except Exception:
            continue
    return None

def classify_mx_provider(mx: List[Tuple[int, str]]) -> str:
    if not mx:
        return "unknown"
    host = mx[0][1].lower()
    if ".google.com" in host or host.endswith("google.com"):
        return "Google Workspace"
    if "protection.outlook.com" in host or "outlook.com" in host:
        return "Microsoft 365"
    if "zoho" in host:
        return "Zoho"
    if "protonmail" in host or "proton" in host:
        return "Proton"
    if "hostinger" in host:
        return "Hostinger"
    if "mailgun" in host:
        return "Mailgun"
    return "other"

def _spf_policy(txt: str) -> str:
    t = " " + txt.lower().strip() + " "
    if " -all " in t or t.strip().endswith("-all"):
        return "hardfail (-all)"
    if " ~all " in t or t.strip().endswith("~all"):
        return "softfail (~all)"
    if " ?all " in t or t.strip().endswith("?all"):
        return "neutral (?all)"
    if " +all " in t or t.strip().endswith("+all"):
        return "allow all (+all)"
    return "unknown"

def estimate_spf_lookups(spf_record: str) -> int:
    """Rough estimate of SPF DNS lookup count.

    Per RFC 7208, mechanisms that typically cause lookups: include, a, mx, ptr, exists, redirect.
    This is an estimate (not a full evaluator), but good for warning students.
    """
    s = spf_record.lower()
    count = 0
    count += s.count("include:")
    count += s.count("redirect=")
    count += s.count("exists:")
    # 'a' and 'mx' mechanisms as standalone tokens
    count += len(re.findall(r"(?<![a-z0-9])a(?![a-z0-9])", s))
    count += len(re.findall(r"(?<![a-z0-9])mx(?![a-z0-9])", s))
    count += len(re.findall(r"(?<![a-z0-9])ptr(?![a-z0-9])", s))
    return count

def parse_spf(txt_records: List[str]) -> Dict[str, Any]:
    spf = [t.strip() for t in txt_records if _SPF_RE.search(t)]
    if not spf:
        return {"present": False, "records": [], "issues": ["No SPF TXT record found"]}

    issues: List[str] = []
    if len(spf) > 1:
        issues.append("Multiple SPF records found (can cause SPF PERMERROR)")

    policy = _spf_policy(spf[0])
    if "allow all" in policy:
        issues.append("SPF uses +all (allows any sender) — insecure")

    lookup_est = estimate_spf_lookups(spf[0])
    if lookup_est > 10:
        issues.append(f"Estimated SPF DNS lookups ~{lookup_est} (>10 limit) — may cause SPF failures")

    return {"present": True, "records": spf, "policy": policy, "issues": issues, "lookup_estimate": lookup_est}

def parse_dmarc(txt_records: List[str]) -> Dict[str, Any]:
    dmarc = [t.strip() for t in txt_records if _DMARC_RE.search(t)]
    if not dmarc:
        return {"present": False, "record": None, "issues": ["No DMARC TXT record at _dmarc"]}

    record = dmarc[0]
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    issues: List[str] = []
    if policy == "none":
        issues.append("DMARC policy is p=none (monitoring only; spoofing not blocked)")
    elif policy == "quarantine":
        issues.append("DMARC policy is p=quarantine (some spoofed mail may be delivered to spam)")
    elif policy == "reject":
        pass
    else:
        issues.append("DMARC policy p= is missing or unrecognized")

    if "rua" not in tags:
        issues.append("DMARC record has no rua= (no aggregate reports)")
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
            if pct < 100:
                issues.append(f"DMARC pct={pct} (policy not applied to all mail)")
        except Exception:
            pass

    return {"present": True, "record": record, "tags": tags, "policy": policy, "issues": issues}

def discover_dkim(domain: str, selectors: List[str], *, timeout: float) -> Dict[str, Any]:
    found: List[Dict[str, str]] = []
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txt = dns_txt(name, timeout=timeout)
        if txt:
            found.append({"selector": sel, "type": "TXT", "value": txt[0][:220]})
            continue
        target = dns_exists(name, timeout=timeout)
        if target:
            found.append({"selector": sel, "type": "CNAME/A", "value": target})

    return {
        "heuristic": True,
        "selectors_tested": selectors,
        "found": found,
        "present_likely": len(found) > 0,
        "notes": "DKIM selector discovery is best-effort; absence does not prove DKIM is missing.",
    }

def check_mta_sts(domain: str, *, timeout: float) -> Dict[str, Any]:
    # DNS TXT at _mta-sts.<domain>
    txt = dns_txt(f"_mta-sts.{domain}", timeout=timeout)
    present = any(t.lower().startswith("v=stsv1") for t in txt)
    return {"dns_present": present, "records": txt}

def check_tls_rpt(domain: str, *, timeout: float) -> Dict[str, Any]:
    # DNS TXT at _smtp._tls.<domain>
    txt = dns_txt(f"_smtp._tls.{domain}", timeout=timeout)
    present = any(t.lower().startswith("v=tlsrptv1") for t in txt)
    return {"present": present, "records": txt}
