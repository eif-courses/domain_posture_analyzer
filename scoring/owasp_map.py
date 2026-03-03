from __future__ import annotations

from typing import List

# Simple mapping for posture findings (not a substitute for a full app-sec review)
OWASP = {
    "A02": "Cryptographic Failures",
    "A05": "Security Misconfiguration",
}

def map_tags(tags: List[str]) -> List[str]:
    out = []
    for t in tags:
        if t in OWASP:
            out.append(f"{t} – {OWASP[t]}")
    return out
