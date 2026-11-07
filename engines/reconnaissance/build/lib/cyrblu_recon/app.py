import asyncio
import fcntl
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .agents.definitions import definitions
from .config.settings import Settings
from .database.store import MissingAssessment, Store
from .intelligence.signing import publish
from .orchestrator.engine import Engine
from .reporting.report import markdown, payload, port_lines
from .schemas.models import Assessment


def create_app(settings: Settings) -> FastAPI:
    store = Store(settings.data_dir / "recon.sqlite3")
    engine = Engine(settings, store)

    @asynccontextmanager
    async def lifespan(app):
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        with (settings.data_dir / "engine.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("Another reconnaissance backend owns this database") from exc
            store.recover()
            try:
                yield
            finally:
                await engine.shutdown()
                fcntl.flock(lock, fcntl.LOCK_UN)

    app = FastAPI(title="Cyrblu Independent Reconnaissance", version="0.1.0", lifespan=lifespan)
    app.state.store, app.state.engine = store, engine
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])

    @app.middleware("http")
    async def limits(request: Request, call_next):
        if request.client and request.client.host not in {"127.0.0.1", "::1", "testclient"}:
            return JSONResponse({"detail": "Reconnaissance dashboard is loopback-only"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers.get('host')}":
            return JSONResponse({"detail": "Cross-origin requests are prohibited"}, status_code=403)
        if request.method in {"POST", "PUT", "PATCH"}:
            size = 0
            parts = []
            async for chunk in request.stream():
                size += len(chunk)
                if size > 1024 * 1024:
                    return JSONResponse({"detail": "Request body exceeds 1 MiB"}, status_code=413)
                parts.append(chunk)
            request._body = b"".join(parts)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        return response

    def access(authorization: str = Header(default="")) -> str:
        role = settings.role(authorization.removeprefix("Bearer ")) if authorization.startswith("Bearer ") else None
        if role is None:
            raise HTTPException(401, "Independent reconnaissance credentials required")
        return role

    def operator(role: str = Depends(access)):
        if role != "operator":
            raise HTTPException(403, "Operator authorization required")

    @app.exception_handler(MissingAssessment)
    async def missing(request, exc):
        return JSONResponse({"detail": "Assessment not found"}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    static = Path(__file__).parent / "reporting/static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def dashboard():
        return FileResponse(static / "index.html")

    @app.get("/api/v1/recon/capabilities", dependencies=[Depends(access)])
    def capabilities():
        return {"agents": definitions(engine.registry), "skills": engine.registry.describe(),
                "limits": {"targets": settings.max_targets, "batch_size": settings.batch_size,
                           "scan_rate": settings.scan_rate, "max_parallelism": settings.max_parallelism, "http_requests": 128},
                "native_scan_golden_status": "not_certified", "modes": ["PASSIVE", "ACTIVE", "AUTHENTICATED"]}

    @app.get("/api/v1/recon/assessments", dependencies=[Depends(access)])
    def assessments():
        return store.list()

    @app.post("/api/v1/recon/assessments", status_code=202, dependencies=[Depends(operator)])
    async def create(spec: Assessment):
        return engine.create(spec)

    @app.get("/api/v1/recon/assessments/{identifier}", dependencies=[Depends(access)])
    def assessment(identifier: str):
        return {**store.assessment(identifier), "coverage": store.coverage(identifier)}

    @app.post("/api/v1/recon/assessments/{identifier}/cancel", dependencies=[Depends(operator)])
    async def cancel(identifier: str):
        return await engine.cancel(identifier)

    @app.get("/api/v1/recon/assessments/{identifier}/events", dependencies=[Depends(access)])
    def events(identifier: str, after: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=1000)):
        store.assessment(identifier)
        return store.events(identifier, after, limit)

    @app.get("/api/v1/recon/assessments/{identifier}/events/stream", dependencies=[Depends(access)])
    async def stream(identifier: str, request: Request, after: int = Query(0, ge=0)):
        store.assessment(identifier)

        async def messages():
            nonlocal after
            import json
            while not await request.is_disconnected():
                rows = store.events(identifier, after)
                for row in rows:
                    after = row["sequence"]
                    yield f"id: {after}\ndata: {json.dumps(row)}\n\n"
                if not rows and store.assessment(identifier)["status"] not in {"queued", "running"}:
                    return
                if not rows:
                    yield ": keepalive\n\n"
                    await asyncio.sleep(1)

        return StreamingResponse(messages(), media_type="text/event-stream")

    @app.get("/api/v1/recon/assessments/{identifier}/assets", dependencies=[Depends(access)])
    def assets(identifier: str):
        store.assessment(identifier)
        return store.assets(identifier)

    @app.get("/api/v1/recon/assessments/{identifier}/evidence", dependencies=[Depends(access)])
    def evidence(identifier: str):
        store.assessment(identifier)
        return store.evidence(identifier)

    @app.get("/api/v1/recon/assessments/{identifier}/ports", dependencies=[Depends(access)])
    def ports(identifier: str, offset: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=1000),
              state: str | None = Query(None, pattern=r"^(open|closed|filtered|open\|filtered|closed\|filtered|unfiltered|unknown)$")):
        store.assessment(identifier)
        return {"records": store.ports(identifier, offset, limit, state), "coverage": store.coverage(identifier)}

    @app.get("/api/v1/recon/assessments/{identifier}/ports/export", dependencies=[Depends(access)])
    def export_ports(identifier: str):
        assessment = store.assessment(identifier)
        if assessment["status"] in {"queued", "running"}:
            raise HTTPException(409, "Export requires terminal execution state")
        return StreamingResponse(port_lines(store, identifier), media_type="application/x-ndjson",
                                 headers={"Content-Disposition": f'attachment; filename="{assessment["id"]}-ports.jsonl"'})

    @app.get("/api/v1/recon/assessments/{identifier}/graph", dependencies=[Depends(access)])
    def graph(identifier: str):
        store.assessment(identifier)
        return store.graph(identifier)

    @app.get("/api/v1/recon/assessments/{identifier}/report", dependencies=[Depends(access)])
    def report(identifier: str):
        return PlainTextResponse(markdown(store, identifier), media_type="text/markdown")

    @app.get("/api/v1/recon/assessments/{identifier}/intelligence", dependencies=[Depends(access)])
    def intelligence(identifier: str):
        return publish(payload(store, identifier), settings.config_dir / "signing.pem")

    return app
