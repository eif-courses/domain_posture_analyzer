from __future__ import annotations

from typing import Any, Dict, List, Optional


def detect_email_provider(
    mx_hosts: List[str],
    spf_txt_records: List[str],
    dkim_cnames: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Fingerprint the email provider from MX, SPF, and DKIM signals.

    Inputs:
      mx_hosts: list of MX hostnames (lowercased)
      spf_txt_records: list of SPF/TXT strings (lowercased)
      dkim_cnames: optional list of DKIM CNAME targets (lowercased)

    Returns:
      {"name": str, "confidence": "high"|"medium"|"low", "evidence": [str]}
    """
    mx = " ".join(mx_hosts).lower()
    spf = " ".join(spf_txt_records).lower()
    dkim = " ".join(dkim_cnames or []).lower()

    # (name, mx_needles, spf_needles, dkim_needles)
    rules = [
        (
            "Google Workspace",
            ("google.com",),
            ("_spf.google.com", "spf.google.com", "redirect=_spf.google.com"),
            ("dkim.mail.google.com",),
        ),
        (
            "Microsoft 365",
            ("outlook.com", "protection.outlook.com"),
            ("spf.protection.outlook.com",),
            ("onmicrosoft.com",),
        ),
        (
            "Hostinger",
            ("mail.hostinger.com", "mx1.hostinger.com", "mx2.hostinger.com"),
            ("_spf.mail.hostinger.com",),
            ("dkim.mail.hostinger.com",),
        ),
        (
            "Zoho Mail",
            ("zoho.com", "zohomail.com"),
            ("zoho.com", "zohomail.com"),
            ("zoho.com",),
        ),
        (
            "Proton Mail",
            ("protonmail.ch", "mail.protonmail.ch"),
            ("protonmail.ch",),
            ("protonmail.ch",),
        ),
        (
            "Fastmail",
            ("messagingengine.com",),
            ("messagingengine.com",),
            ("messagingengine.com",),
        ),
        (
            "Amazon SES",
            ("amazonses.com",),
            ("amazonses.com",),
            ("amazonses.com",),
        ),
        (
            "SendGrid",
            ("sendgrid.net",),
            ("sendgrid.net",),
            ("sendgrid.net",),
        ),
        (
            "Mailgun",
            ("mailgun.org",),
            ("mailgun.org",),
            ("mailgun.org",),
        ),
    ]

    best: Dict[str, Any] = {"name": "Unknown", "confidence": "low", "evidence": []}
    score_best = 0

    for name, mx_needles, spf_needles, dkim_needles in rules:
        score = 0
        evidence: List[str] = []

        matched_mx = [n for n in mx_needles if n in mx]
        if matched_mx:
            score += 2
            evidence.append(f"MX: {', '.join(matched_mx)}")

        matched_spf = [n for n in spf_needles if n in spf]
        if matched_spf:
            score += 2
            evidence.append(f"SPF: {', '.join(matched_spf)}")

        matched_dkim = [n for n in dkim_needles if n in dkim]
        if matched_dkim:
            score += 1
            evidence.append(f"DKIM: {', '.join(matched_dkim)}")

        if score > score_best:
            score_best = score
            best = {
                "name": name,
                "confidence": "high" if score >= 4 else ("medium" if score >= 2 else "low"),
                "evidence": evidence,
            }

    return best
