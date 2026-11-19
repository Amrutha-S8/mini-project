"""Static route-authorisation guard (SR-AUTHZ-01, SR-AUTHZ-03; check V5).

Every route must require an authenticated user unless it is on an explicit,
reviewed allowlist. Admin-only operations must require the admin dependency.

This parses ``app/api/v1/*.py`` with ``ast`` rather than importing FastAPI, so
it runs in any environment. It fails closed: a new route with no recognised
auth dependency fails the suite until someone either protects it or adds it to
the allowlist on purpose.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_V1 = Path(__file__).resolve().parent.parent / "app" / "api" / "v1"

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

#: (module, method, path) reachable without authentication. Keep this short.
PUBLIC_ROUTES = {
    ("health", "get", "/health"),
    ("health", "get", "/health/ready"),
    ("auth", "post", "/login"),
    ("auth", "post", "/refresh"),
}

#: (module, method, path) that must require the admin role.
ADMIN_ROUTES = {
    ("auth", "post", "/register"),
    ("members", "post", ""),
    ("members", "patch", "/{member_id}"),
    ("members", "post", "/{member_id}/deactivate"),
    ("members", "post", "/{member_id}/revoke"),
    ("incidents", "patch", "/{incident_id}"),
}

AUTH_ANNOTATIONS = {"CurrentUser", "AdminUser"}


def _routes() -> list[tuple[str, str, str, set[str]]]:
    """(module, method, path, annotation-names) for every decorated route."""
    found = []
    for path in sorted(API_V1.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for deco in node.decorator_list:
                if not (
                    isinstance(deco, ast.Call)
                    and isinstance(deco.func, ast.Attribute)
                    and isinstance(deco.func.value, ast.Name)
                    and deco.func.value.id == "router"
                    and deco.func.attr in HTTP_METHODS
                ):
                    continue
                first = deco.args[0] if deco.args else None
                route = first.value if isinstance(first, ast.Constant) else ""
                params = node.args.args + node.args.kwonlyargs
                annotations = {
                    p.annotation.id
                    for p in params
                    if isinstance(p.annotation, ast.Name)
                }
                found.append((path.stem, deco.func.attr, str(route), annotations))
    return found


ROUTES = _routes()


def test_routes_were_discovered() -> None:
    assert len(ROUTES) >= 10, f"route discovery looks broken: {ROUTES}"


@pytest.mark.parametrize(
    "module,method,route,annotations",
    ROUTES,
    ids=[f"{m}:{meth.upper()} {r or '/'}" for m, meth, r, _ in ROUTES],
)
def test_every_route_requires_auth_unless_allowlisted(
    module: str, method: str, route: str, annotations: set[str]
) -> None:
    if (module, method, route) in PUBLIC_ROUTES:
        return
    assert annotations & AUTH_ANNOTATIONS, (
        f"{module}:{method.upper()} {route!r} has no CurrentUser/AdminUser "
        "dependency and is not on the public allowlist"
    )


@pytest.mark.parametrize("key", sorted(ADMIN_ROUTES))
def test_admin_routes_require_admin(key: tuple[str, str, str]) -> None:
    matches = [r for r in ROUTES if r[:3] == key]
    assert matches, f"admin route {key} no longer exists; update ADMIN_ROUTES"
    assert "AdminUser" in matches[0][3], f"{key} must depend on AdminUser"


@pytest.mark.parametrize("key", sorted(PUBLIC_ROUTES))
def test_public_allowlist_has_no_stale_entries(key: tuple[str, str, str]) -> None:
    assert any(r[:3] == key for r in ROUTES), f"stale allowlist entry {key}"
