import fcntl
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import httpx

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .catalogue import load_catalogue
from .core import Approval, Engagement, Orchestrator, Policy, Store, markdown_report, run_view
from .scanners import NMAP_SKILL, registry
from .recon_intelligence import fetch as fetch_recon_intelligence

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"


def create_app(data_dir: Path | None = None, cidrs: str | None = None) -> FastAPI:
    policy = Policy(os.environ.get("LAB_ALLOWED_CIDRS", "") if cidrs is None else cidrs)
    directory = data_dir if data_dir is not None else Path(os.environ.get("LAB_DATA_DIR", ROOT / "data"))
    store = Store(directory / "runs.sqlite3")
    nuclei_version = os.environ.get("LAB_NUCLEI_VERSION", "")
    nmap_version = os.environ.get("LAB_NMAP_VERSION", "")
    orchestrator = Orchestrator(store, policy, nuclei_version, nmap_version)
    token = secrets.token_urlsafe(32)
    catalogue = load_catalogue(ROOT / "references" / "AI-Agent")
    catalogue["execution_skills"] = [NMAP_SKILL]

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with store.path.with_suffix(".lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("Another backend owns this data directory; use one backend process") from exc
            store.recover()
            try:
                yield
            finally:
                await orchestrator.close()
                fcntl.flock(lock, fcntl.LOCK_UN)

    app = FastAPI(title="Lab Red Team", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.orchestrator = orchestrator
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        if request.client and request.client.host not in {"127.0.0.1", "::1", "testclient"}:
            return JSONResponse({"detail": "Dashboard access is loopback-only"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers.get('host')}":
            return JSONResponse({"detail": "Cross-origin access is prohibited"}, status_code=403)
        if request.method not in {"GET", "HEAD"}:
            if not secrets.compare_digest(request.headers.get("x-lab-token", ""), token):
                return JSONResponse({"detail": "Missing or invalid dashboard token"}, status_code=403)
            length = request.headers.get("content-length", "")
            if not length.isdecimal() or request.headers.get("transfer-encoding"):
                return JSONResponse({"detail": "A valid Content-Length is required"}, status_code=411)
            if int(length) > 16384:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(KeyError)
    async def missing(request: Request, exc: KeyError):
        return JSONResponse({"detail": "Run not found"}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(request: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return (STATIC / "index.html").read_text().replace("__LAB_TOKEN__", token)

    @app.get("/api/catalogue")
    async def get_catalogue():
        return catalogue

    @app.get("/api/tools")
    async def tools():
        return registry(nuclei_version, nmap_version)

    @app.get("/api/recon/intelligence/{assessment_id}")
    async def recon_intelligence(assessment_id: str):
        endpoint = os.environ.get("LAB_RECON_URL", "")
        token_path = os.environ.get("LAB_RECON_TOKEN_FILE", "")
        trusted_key = os.environ.get("LAB_RECON_PUBLIC_KEY", "")
        if not all((endpoint, token_path, trusted_key)):
            raise HTTPException(409, "Signed reconnaissance API integration is not configured")
        try:
            return await fetch_recon_intelligence(assessment_id, endpoint, Path(token_path), Path(trusted_key))
        except (OSError, httpx.HTTPError) as exc:
            raise HTTPException(502, "Reconnaissance publication unavailable; no assessment was started") from exc

    @app.get("/api/config")
    async def config():
        return {"allowed_cidrs": [str(network) for network in policy.networks],
                "network_enabled": bool(policy.networks), "request_budget": 32,
                "concurrent_engagements": 2, "queue_capacity": 32, "concurrent_model_calls": 1,
                "nuclei_version_approved": bool(nuclei_version),
                "nmap_version_approved": bool(nmap_version),
                "tcp_scope_budget": 128,
                "agents": ["planner", "policy_broker", "discovery_specialist",
                           "simulation_specialist", "evidence_reviewer", "local_model_reviewer", "reporter"]}

    @app.get("/api/runs")
    async def list_runs():
        return [run_view(run) for run in store.list()]

    @app.post("/api/runs", status_code=201)
    async def create_run(spec: Engagement):
        return run_view(orchestrator.create(spec))

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str):
        return run_view(store.get(run_id))

    @app.post("/api/runs/{run_id}/approve")
    async def approve_run(run_id: str, approval: Approval):
        if not approval.approve:
            raise HTTPException(400, "Explicit approval is required")
        return run_view(orchestrator.start(run_id))

    @app.post("/api/runs/{run_id}/stop")
    async def stop_run(run_id: str):
        return run_view(await orchestrator.stop(run_id))

    @app.get("/api/runs/{run_id}/report")
    async def report(run_id: str, format: str = "markdown"):
        run = store.get(run_id)
        if format == "json":
            return JSONResponse(run_view(run), headers={"Content-Disposition": 'attachment; filename="lab-report.json"'})
        if format != "markdown":
            raise HTTPException(400, "Supported formats: markdown, json")
        return PlainTextResponse(markdown_report(run), headers={"Content-Disposition": 'attachment; filename="lab-report.md"'})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
