from __future__ import annotations

import datetime as dt

def utcnow_iso() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()
