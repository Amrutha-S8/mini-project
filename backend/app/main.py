"""FastAPI application factory.

Wires configuration, logging, database engines, exception handlers, CORS and
the v1 router. Face recognition (M03-M06), the AccessEngine (M08) and the AI
tier (M15-M18) are NOT present — they belong to Days 3, 4 and 8-11.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.errors import DomainError, generic_envelope
from app.core.logging import configure_logging, get_logger
from app.core.rate_limit import LoginThrottle
from app.core.security_headers import SecurityHeadersMiddleware
from app.database.session import dispose_engines, init_engines

logger = get_logger(__name__)

API_V1_PREFIX = "/api/v1"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown.

    Engines are created here rather than at import time so that tests can
    point the application at a temporary database.
    """
    settings: Settings = app.state.settings
    configure_logging(settings.log_level)
    init_engines(settings)
    logger.info(
        "application started",
        extra={"context": {"env": settings.app_env}},
    )
    try:
        yield
    finally:
        dispose_engines()
        logger.info("application stopped")


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code, content=exc.to_envelope(), headers=exc.headers
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Unknown routes, wrong methods etc. use the standard envelope.

        ``exc.detail`` is not echoed; the standard status phrase is used.
        """
        codes = {404: "not_found", 405: "method_not_allowed"}
        try:
            phrase = HTTPStatus(exc.status_code).phrase
        except ValueError:
            phrase = "HTTP error"
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": codes.get(exc.status_code, "http_error"),
                    "message": phrase,
                }
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Field-level detail is safe and useful; the raw exception is not.
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed",
                    "details": {
                        "fields": [
                            {
                                "loc": [str(p) for p in err.get("loc", [])],
                                "msg": err.get("msg", ""),
                            }
                            for err in exc.errors()
                        ]
                    },
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
        # Logged server-side with the type only; the client gets nothing.
        logger.error("unhandled exception", exc_info=True)
        return JSONResponse(status_code=500, content=generic_envelope())


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Importable by tests without side effects."""
    settings = settings or get_settings()

    app = FastAPI(
        title=settings.app_name,
        version="0.2.0",
        description=(
            "Day 2 backend: operator authentication, identity registry and "
            "persistence. The deterministic AccessEngine arrives on Day 4 and "
            "remains the sole access decision authority."
        ),
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.state.settings = settings
    app.state.login_throttle = LoginThrottle(
        ip_limit=settings.login_ip_limit,
        ip_window_seconds=settings.login_ip_window_seconds,
        failure_limit=settings.login_failure_limit,
        failure_window_seconds=settings.login_failure_window_seconds,
        refresh_limit=settings.refresh_ip_limit,
        refresh_window_seconds=settings.refresh_ip_window_seconds,
    )

    origins = settings.cors_origins
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            # Bearer tokens travel in the Authorization header, never cookies.
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Authorization", "Content-Type"],
            expose_headers=["Retry-After"],
            max_age=600,
        )

    # Added last so it is outermost: CORS preflights and handled errors get
    # the headers too.
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production)

    _register_exception_handlers(app)
    app.include_router(api_router, prefix=API_V1_PREFIX)
    return app


app = create_app()
