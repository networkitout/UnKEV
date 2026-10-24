"""Render the dashboard to a single static HTML file (CSS inlined) for review
without running the server.   python -m scripts.render_preview out.html"""
from __future__ import annotations

import sys

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import ROOT
from app.pipeline import Ctx
from app.views import dashboard_context, register_filters


def main(out: str, selected: str | None = None):
    env = Environment(loader=FileSystemLoader(str(ROOT / "app" / "templates")),
                      autoescape=select_autoescape(["html"]))
    register_filters(env)
    html = env.get_template("dashboard.html").render(**dashboard_context(Ctx(), selected), live=False)
    css = (ROOT / "app" / "static" / "app.css").read_text()
    css = "\n".join(l for l in css.splitlines() if "url(\"/static/vendor" not in l)
    html = html.replace('<link rel="stylesheet" href="/static/app.css">', f"<style>{css}</style>")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"wrote {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "preview.html", sys.argv[2] if len(sys.argv) > 2 else None)
