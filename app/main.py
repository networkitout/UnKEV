from __future__ import annotations

import asyncio
import csv
import io
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import pipeline
from .config import ROOT, get_settings
from .views import dashboard_context, register_filters

security = HTTPBasic()
templates = Jinja2Templates(directory=str(ROOT / "app" / "templates"))  # autoescape on for .html
register_filters(templates.env)


def require_auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    s = get_settings()
    if not s.dashboard_password:
        raise HTTPException(503, "Set UNKEV_PASSWORD before exposing the dashboard.")
    user_ok = secrets.compare_digest(creds.username.encode(), s.dashboard_user.encode())
    pass_ok = secrets.compare_digest(creds.password.encode(), s.dashboard_password.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return creds.username


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = None
    if get_settings().inprocess_worker:
        from .worker import loop_forever
        task = asyncio.create_task(loop_forever())
    yield
    if task:
        task.cancel()


app = FastAPI(title="UnKEV", lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(ROOT / "app" / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        # style-src-attr allows style="" (bar widths, grid columns). All dynamic text is
        # autoescaped, and no script or <style> element is allowed inline.
        "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; font-src 'self'; "
        "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, c: str | None = None, _: str = Depends(require_auth)):
    ctx = pipeline.Ctx()
    return templates.TemplateResponse(request, "dashboard.html", dashboard_context(ctx, c) | {"live": True})


@app.get("/component/{cid}", response_class=HTMLResponse)
async def component(request: Request, cid: str, _: str = Depends(require_auth)):
    ctx = pipeline.Ctx()
    data = dashboard_context(ctx, cid)
    if not data["sel"] or data["sel"]["component_id"] != cid:
        raise HTTPException(404, "Unknown component")
    return templates.TemplateResponse(request, "partials/detail.html", data)


@app.post("/run/{job}", response_class=HTMLResponse)
async def run_job(request: Request, job: str, _: str = Depends(require_auth)):
    # CSRF: Basic auth is replayed by browsers on cross-site POSTs. Requiring the
    # HTMX header forces a CORS preflight that a foreign origin can't pass.
    if request.headers.get("HX-Request") != "true":
        raise HTTPException(400, "Missing HX-Request header")
    if job not in pipeline.JOBS and job != "all":
        raise HTTPException(404, "Unknown job")
    started = not pipeline._lock.locked()
    if started:
        asyncio.create_task(pipeline.run(job))
    msg = f"Started {job}. Refresh in a minute." if started else "A run is already in progress."
    return HTMLResponse(f'<span class="run-msg">{msg}</span>')


@app.get("/api/scores")
async def api_scores(_: str = Depends(require_auth)):
    ts, rows = pipeline.Ctx().db.latest_snapshot()
    return JSONResponse({"ts": ts, "scores": rows})


@app.get("/api/scores.csv")
async def api_scores_csv(_: str = Depends(require_auth)):
    ts, rows = pipeline.Ctx().db.latest_snapshot()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["snapshot", "rank", "component", "priority", "likelihood", "exposure", "exposure_status",
                "prior", "activity", "spillover", "exploit", "hosts", "internet_facing", "top_driver"])
    for r in rows:
        inv = r["inventory"]
        w.writerow([ts, r["rank"], r["name"], r["priority"], r["likelihood"], r["exposure"],
                    r["exposure_status"], *[r["points"][k] for k in ("prior", "activity", "spillover", "exploit")],
                    inv.get("hosts", 0), inv.get("internet_facing", 0),
                    r["drivers"][0]["label"] if r["drivers"] else ""])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=unkev-scores.csv"})
