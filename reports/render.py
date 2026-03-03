from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

def get_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )

def render_report(data: Dict[str, Any]) -> str:
    env = get_env()
    tpl = env.get_template("report.html")
    return tpl.render(**data)
