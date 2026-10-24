"""Render a view to a single static HTML file (CSS inlined) for review without
running the server.

    python -m scripts.render_preview out.html              # executive view
    python -m scripts.render_preview out.html --analyst     # analyst view
    python -m scripts.render_preview out.html --analyst php # analyst view, php selected
"""
from __future__ import annotations

import sys

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import ROOT
from app.pipeline import Ctx
from app.views import dashboard_context, exec_context, register_filters


def main(out: str, analyst: bool = False, selected: str | None = None):
    env = Environment(loader=FileSystemLoader(str(ROOT / "app" / "templates")),
                      autoescape=select_autoescape(["html"]))
    register_filters(env)
    ctx = Ctx()
    if analyst:
        html = env.get_template("dashboard.html").render(**dashboard_context(ctx, selected), live=False)
        sheet = "app.css"
    else:
        html = env.get_template("exec.html").render(**exec_context(ctx), live=False)
        sheet = "exec.css"
    css = (ROOT / "app" / "static" / sheet).read_text()
    css = "\n".join(l for l in css.splitlines() if "url(\"/static/vendor" not in l)
    html = html.replace(f'<link rel="stylesheet" href="/static/{sheet}">', f"<style>{css}</style>")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"wrote {out}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    main(args[0] if args else "preview.html", "--analyst" in sys.argv, args[1] if len(args) > 1 else None)
