from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.routes import router
from app.config import get_settings
from app.db.session import get_engine, run_migrations
from app.services.agent import narrative_providers
from app.services.mitre import get_catalog

log = logging.getLogger("sentinelmind")


@asynccontextmanager
async def lifespan(_: FastAPI):
    run_migrations()
    get_catalog()  # fail fast if the ATT&CK catalog snapshot is missing
    yield


app = FastAPI(title="SentinelMind X API", version="0.1.0",
              description="AI security incident intelligence - Team SignalForge", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://127.0.0.1:3000",
                                                  "http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"], expose_headers=["X-Trace-Id"])


@app.middleware("http")
async def trace_id_middleware(request: Request, call_next):
    trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex[:16]
    request.state.trace_id = trace_id
    response = await call_next(request)
    response.headers["X-Trace-Id"] = trace_id
    return response


def _error(status: int, code: str, message, request: Request) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message,
                                                               "trace_id": getattr(request.state, "trace_id", None)}},
                        headers={"X-Trace-Id": getattr(request.state, "trace_id", "") or ""})


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return _error(exc.status_code, f"http_{exc.status_code}", exc.detail, request)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return _error(422, "validation_error", [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()][:20], request)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error")
    return _error(500, "internal_error", "internal server error", request)


@app.get("/health")
def health() -> dict:
    with get_engine().connect() as conn:
        conn.execute(text("SELECT 1"))
    s = get_settings()
    return {"status": "ok", "database": get_engine().dialect.name, "attack_catalog": get_catalog().version,
            "jev_configured": bool(s.typesafe_api_key),
            "narrative_providers": [f"{p.name}:{p.model}" for p in narrative_providers(s)] + ["template"]}


app.include_router(router)
