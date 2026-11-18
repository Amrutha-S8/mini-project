"""AI containment: static import-graph guards (SR-AI-03, checks V2/V3).

The project's defining security property is that the deterministic
AccessEngine is the sole access decision authority and that no AI component
can reach the door. These tests enforce it mechanically by parsing the import
graph with ``ast`` — no runtime import needed, so they work in any environment
and will keep working as Days 3-11 add modules.

Phase 1 (DD-08 decision 8): ``app/ai/`` now exists, so the AI-tier guards
run instead of skipping. The Day 2 "no AI package anywhere" check is replaced
by an AI-package boundary (allowed only in ``app/ai/`` adapters, never in
``app/ai/core/``) plus transitive isolation checks over the full import graph,
each with negative controls.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
APP_ROOT = BACKEND_ROOT / "app"

#: Packages that must never appear in the deterministic core.
FORBIDDEN_AI_PACKAGES = frozenset(
    {
        "google",
        "google_generativeai",
        "generativeai",
        "langchain",
        "langchain_core",
        "langchain_community",
        "langgraph",
        "chromadb",
        "openai",
        "anthropic",
        "transformers",
        "sentence_transformers",
        "langchain_google_genai",
        "langchain_chroma",
        "langchain_text_splitters",
        "langchain_huggingface",
        "huggingface_hub",
        "torch",
        "onnxruntime",
    }
)

#: Modules the AI/advisory tier must never import (no path to the door).
FORBIDDEN_CORE_TARGETS = frozenset(
    {
        "app.domain.access_engine",
        "app.domain.virtual_door",
        "app.services.access_engine",
        "app.services.door",
        "app.services.virtual_door",
    }
)

#: Files belonging to the AI tier, added on Days 8-11.
AI_TIER_GLOBS = ("ai/**/*.py", "services/rag*.py", "services/gemini*.py")


def _python_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _imported_roots(path: Path) -> set[str]:
    """Top-level package names imported by a module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _imported_modules(path: Path) -> set[str]:
    """Fully-qualified absolute module names imported by a module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module)
            for alias in node.names:
                modules.add(f"{node.module}.{alias.name}")
    return modules


# --- repository-wide guard (active from Day 2) -------------------------------


def test_app_tree_is_parseable() -> None:
    """Every backend module must be syntactically valid Python."""
    files = _python_files(APP_ROOT)
    assert files, "no python files found under app/"
    for path in files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def ai_package_offenders(app_root: Path) -> dict[str, set[str]]:
    """AI packages imported outside the adapter area (DD-08 decision 8).

    AI packages are allowed only under ``app/ai/`` and never in
    ``app/ai/core/``, which must stay standard-library only.
    """
    offenders: dict[str, set[str]] = {}
    for path in _python_files(app_root):
        rel = path.relative_to(app_root).parts
        in_adapters = rel[0] == "ai" and (len(rel) < 2 or rel[1] != "core")
        if in_adapters:
            continue
        bad = _imported_roots(path) & FORBIDDEN_AI_PACKAGES
        if bad:
            offenders[str(path)] = bad
    return offenders


def test_ai_packages_only_in_ai_adapters() -> None:
    """Replaces the Day 2 'no AI package anywhere' guard (DD-08 decision 8)."""
    assert ai_package_offenders(APP_ROOT) == {}


# --- AccessEngine guard (V2) -------------------------------------------------


def _access_engine_path() -> Path | None:
    candidate = APP_ROOT / "domain" / "access_engine.py"
    return candidate if candidate.is_file() else None


def test_domain_core_imports_only_stdlib_and_itself() -> None:
    """The deterministic core: no framework, database, network or AI imports."""
    stdlib = set(sys.stdlib_module_names)
    network = {"http", "urllib", "socket", "ssl", "asyncio", "smtplib", "ftplib"}
    offenders: dict[str, set[str]] = {}
    for path in _python_files(APP_ROOT / "domain"):
        bad: set[str] = set()
        for module in _imported_modules(path):
            root = module.split(".")[0]
            if root == "__future__":
                continue
            outside_core = module.startswith("app.") and not module.startswith(
                "app.domain"
            )
            third_party_or_network = root != "app" and (
                root not in stdlib or root in network
            )
            if outside_core or third_party_or_network:
                bad.add(module)
        if bad:
            offenders[str(path.relative_to(BACKEND_ROOT))] = bad
    assert not offenders, f"domain core has forbidden imports: {offenders}"


def test_access_engine_imports_no_ai_package() -> None:
    """V2: the sole access decision authority must be AI-free."""
    path = _access_engine_path()
    if path is None:
        pytest.skip("app/domain/access_engine.py missing")
    bad = _imported_roots(path) & FORBIDDEN_AI_PACKAGES
    assert not bad, f"AccessEngine imports AI packages: {sorted(bad)}"


def test_access_engine_performs_no_network_io() -> None:
    """The engine must not import any network client (SR-AI-04)."""
    path = _access_engine_path()
    if path is None:
        pytest.skip("app/domain/access_engine.py missing")
    network = {"httpx", "requests", "urllib", "urllib3", "http", "socket", "aiohttp"}
    bad = _imported_roots(path) & network
    assert not bad, f"AccessEngine performs network I/O via: {sorted(bad)}"


# --- AI tier guard (V3) ------------------------------------------------------


def _ai_tier_files() -> list[Path]:
    found: list[Path] = []
    for pattern in AI_TIER_GLOBS:
        found.extend(p for p in APP_ROOT.glob(pattern) if "__pycache__" not in p.parts)
    return sorted(set(found))


def test_ai_tier_cannot_import_access_engine_or_door() -> None:
    """V3: no import path from the advisory tier to the door."""
    files = _ai_tier_files()
    if not files:
        pytest.skip("AI tier not implemented yet (scheduled Days 8-11)")
    offenders: dict[str, set[str]] = {}
    for path in files:
        bad = {
            module
            for module in _imported_modules(path)
            if any(module.startswith(target) for target in FORBIDDEN_CORE_TARGETS)
        }
        if bad:
            offenders[str(path.relative_to(BACKEND_ROOT))] = bad
    assert not offenders, f"AI tier imports access-control modules: {offenders}"


# --- session-layer guard -----------------------------------------------------


def test_readonly_session_factory_exists() -> None:
    """The AI tier's only database handle must be defined and read-only."""
    source = (APP_ROOT / "database" / "session.py").read_text(encoding="utf-8")
    assert "get_readonly_session" in source
    assert "mode=ro" in source, "read-only engine must use the SQLite ro URI"


def test_no_unlock_capability_in_day2_api() -> None:
    """Day 2 exposes no door control of any kind."""
    api_sources = " ".join(
        p.read_text(encoding="utf-8") for p in _python_files(APP_ROOT / "api")
    )
    for forbidden in ("unlock", "open_door", "door_open"):
        assert forbidden not in api_sources, (
            f"Day 2 API must not reference {forbidden!r}; "
            "door control arrives on Day 4 behind the AccessEngine"
        )


# --- AI tier transitive isolation (DD-08 decisions 8 and 10) -------------------
#
# The checks below parse the whole app/ import graph with ast and follow it
# transitively, including the package __init__ files Python runs on import.
# Each check takes the app root as a parameter, so the negative controls can
# run the same code against a deliberately broken tree.

#: Modules the AI tier must never reach, directly or through anything else.
AI_FORBIDDEN_MODULES = frozenset(
    {
        "app.domain.access_engine",
        "app.domain.virtual_door",
        "app.database.session",  # holds the writer engine and get_session
        "app.core.security",  # token signing
        "app.main",
        "app.cli",
    }
)
AI_FORBIDDEN_PREFIXES = ("app.services", "app.api")

#: Names AI code must not even mention as identifiers or attributes.
AI_FORBIDDEN_SYMBOLS = frozenset(
    {
        "AccessEngine",
        "AccessRequest",
        "DecisionSigner",
        "PendingHold",
        "VirtualDoor",
        "get_session",
        "get_writer_engine",
        "create_writer_engine",
        "init_engines",
        "unlock",
        "enter_lockdown",
        "release_lockdown",
        "set_unlock_seconds",
    }
)

#: The only project modules app/ai/core may import besides itself.
AI_CORE_ALLOWED_APP_MODULES = frozenset(
    {"app.domain.events", "app.domain.evidence", "app.domain.attack_chain"}
)

#: Modules outside app/ai that may import app.ai. Empty until the API layer
#: is approved (Phase 7).
AI_IMPORTERS_ALLOWLIST: frozenset[str] = frozenset()


def _module_of(path: Path, app_root: Path) -> str:
    rel = path.relative_to(app_root.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _internal_imports(path: Path, app_root: Path, known: set[str]) -> set[str]:
    """Project modules imported by ``path``, with relative imports resolved."""
    package = _module_of(path, app_root)
    if path.name != "__init__.py":
        package = package.rsplit(".", 1)[0]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    root = app_root.name
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            names = [module]
            names += [f"{module}.{a.name}" for a in node.names]
        else:
            continue
        for name in names:
            if name == root or name.startswith(root + "."):
                # Keep the longest known module prefix of the name.
                parts = name.split(".")
                while parts and ".".join(parts) not in known:
                    parts.pop()
                if parts:
                    found.add(".".join(parts))
    return found


def import_graph(app_root: Path) -> dict[str, set[str]]:
    files = {_module_of(p, app_root): p for p in _python_files(app_root)}
    known = set(files)
    graph: dict[str, set[str]] = {}
    for module, path in files.items():
        edges = _internal_imports(path, app_root, known)
        # Importing a.b.c runs a/__init__ and a/b/__init__ first.
        for target in list(edges) + [module]:
            parts = target.split(".")
            edges.update(".".join(parts[:i]) for i in range(1, len(parts)))
        edges.discard(module)
        graph[module] = {e for e in edges if e in known}
    return graph


def reachable(graph: dict[str, set[str]], start: str) -> set[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        for nxt in graph.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _forbidden_for_ai(module: str) -> bool:
    return module in AI_FORBIDDEN_MODULES or module.startswith(AI_FORBIDDEN_PREFIXES)


def transitive_ai_offenders(app_root: Path) -> dict[str, set[str]]:
    graph = import_graph(app_root)
    ai_prefix = f"{app_root.name}.ai"
    offenders: dict[str, set[str]] = {}
    for module in graph:
        if module == ai_prefix or module.startswith(ai_prefix + "."):
            bad = {m for m in reachable(graph, module) if _forbidden_for_ai(m)}
            if bad:
                offenders[module] = bad
    return offenders


def ai_symbol_offenders(app_root: Path) -> dict[str, set[str]]:
    offenders: dict[str, set[str]] = {}
    for path in _python_files(app_root / "ai"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        used: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, ast.alias):
                used.add(node.name.split(".")[-1])
                if node.asname:
                    used.add(node.asname)
            elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                used.add(node.name)
        bad = used & AI_FORBIDDEN_SYMBOLS
        if bad:
            offenders[str(path)] = bad
    return offenders


def ai_core_import_offenders(app_root: Path) -> dict[str, set[str]]:
    stdlib = set(sys.stdlib_module_names)
    network = {"http", "urllib", "socket", "ssl", "asyncio", "smtplib", "ftplib"}
    root = app_root.name
    offenders: dict[str, set[str]] = {}
    for path in _python_files(app_root / "ai" / "core"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        bad: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    bad.add("relative import")
                    continue
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                top = module.split(".")[0]
                if top == "__future__":
                    continue
                if top == root:
                    if not (
                        module.startswith(f"{root}.ai.core")
                        or module in AI_CORE_ALLOWED_APP_MODULES
                    ):
                        bad.add(module)
                elif top not in stdlib or top in network:
                    bad.add(module)
        if bad:
            offenders[str(path)] = bad
    return offenders


def ai_importer_offenders(app_root: Path) -> dict[str, set[str]]:
    graph = import_graph(app_root)
    ai_prefix = f"{app_root.name}.ai"
    offenders: dict[str, set[str]] = {}
    for module, edges in graph.items():
        if module == ai_prefix or module.startswith(ai_prefix + "."):
            continue
        bad = {e for e in edges if e == ai_prefix or e.startswith(ai_prefix + ".")}
        if bad and module not in AI_IMPORTERS_ALLOWLIST:
            offenders[module] = bad
    return offenders


def test_ai_tier_exists_and_is_scanned() -> None:
    graph = import_graph(APP_ROOT)
    ai_modules = {m for m in graph if m.startswith("app.ai")}
    assert "app.ai.core.privacy" in ai_modules and len(ai_modules) >= 10


def test_ai_tier_cannot_reach_engine_door_or_writer_transitively() -> None:
    assert transitive_ai_offenders(APP_ROOT) == {}


def test_ai_code_names_no_engine_door_or_writer_symbol() -> None:
    assert ai_symbol_offenders(APP_ROOT) == {}


def test_ai_core_is_standard_library_only() -> None:
    assert ai_core_import_offenders(APP_ROOT) == {}


def test_nothing_outside_the_ai_tier_imports_it() -> None:
    """One-way flow: the core, services and API do not depend on AI code."""
    assert ai_importer_offenders(APP_ROOT) == {}


def test_what_the_ai_tier_actually_reaches() -> None:
    """Pin the exact project modules the AI tier depends on today."""
    graph = import_graph(APP_ROOT)
    reached: set[str] = set()
    for module in graph:
        if module.startswith("app.ai"):
            reached |= reachable(graph, module)
    outside = {m for m in reached if not m.startswith("app.ai")}
    assert outside == {
        "app",
        "app.domain",
        "app.domain.attack_chain",
        "app.domain.events",
        "app.domain.evidence",
    }


# --- negative controls: the checkers must catch planted violations -----------


def _write(root: Path, rel: str, source: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


@pytest.fixture
def fake_app(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    for package in ("", "ai/", "ai/core/", "domain/", "database/", "helpers/"):
        _write(root, f"{package}__init__.py", "")
    _write(root, "domain/virtual_door.py", "from app.domain import access_engine\n")
    _write(root, "domain/access_engine.py", "")
    _write(root, "domain/events.py", "")
    _write(root, "database/session.py", "")
    _write(root, "ai/core/ok.py", "import json\nfrom app.domain import events\n")
    return root


def test_negative_control_transitive_path_via_helper(fake_app: Path) -> None:
    _write(fake_app, "helpers/door_proxy.py", "from app.domain.virtual_door import X\n")
    _write(fake_app, "ai/agent.py", "from app.helpers import door_proxy\n")
    offenders = transitive_ai_offenders(fake_app)
    assert offenders["app.ai.agent"] >= {
        "app.domain.virtual_door",
        "app.domain.access_engine",
    }


def test_negative_control_relative_import(fake_app: Path) -> None:
    _write(fake_app, "ai/core/sneaky.py", "from ...database import session\n")
    assert (
        "app.database.session"
        in transitive_ai_offenders(fake_app)["app.ai.core.sneaky"]
    )
    assert (
        "relative import"
        in ai_core_import_offenders(fake_app)[str(fake_app / "ai/core/sneaky.py")]
    )


def test_negative_control_package_init_side_effect(fake_app: Path) -> None:
    """Importing app.helpers.x also runs app/helpers/__init__.py."""
    _write(fake_app, "helpers/__init__.py", "from app.database import session\n")
    _write(fake_app, "helpers/maths.py", "")
    _write(fake_app, "ai/calc.py", "from app.helpers.maths import add\n")
    assert "app.database.session" in transitive_ai_offenders(fake_app)["app.ai.calc"]


def test_negative_control_symbols(fake_app: Path) -> None:
    _write(fake_app, "ai/tool.py", "def run(door):\n    door.unlock()\n")
    _write(fake_app, "ai/tool2.py", "x = get_session\n")
    offenders = ai_symbol_offenders(fake_app)
    assert offenders[str(fake_app / "ai/tool.py")] == {"unlock"}
    assert offenders[str(fake_app / "ai/tool2.py")] == {"get_session"}


def test_negative_control_ai_core_imports(fake_app: Path) -> None:
    _write(fake_app, "ai/core/net.py", "import socket\nimport langchain\n")
    _write(fake_app, "ai/core/models.py", "from app.models import User\n")
    offenders = ai_core_import_offenders(fake_app)
    assert offenders[str(fake_app / "ai/core/net.py")] == {"socket", "langchain"}
    assert offenders[str(fake_app / "ai/core/models.py")] == {"app.models"}


def test_negative_control_ai_packages_outside_adapters(fake_app: Path) -> None:
    _write(fake_app, "domain/smart.py", "import chromadb\n")
    _write(fake_app, "ai/core/llm.py", "from google import genai\n")
    _write(fake_app, "ai/gemini_adapter.py", "from langchain_google_genai import X\n")
    offenders = ai_package_offenders(fake_app)
    assert set(offenders) == {
        str(fake_app / "domain/smart.py"),
        str(fake_app / "ai/core/llm.py"),
    }


def test_negative_control_reverse_dependency(fake_app: Path) -> None:
    _write(fake_app, "domain/uses_ai.py", "from app.ai.core import ok\n")
    assert "app.domain.uses_ai" in ai_importer_offenders(fake_app)
