"""Deterministic security core (stdlib only, no I/O, no AI).

Everything in this package is pure Python: face matching over precomputed
embeddings, the AccessEngine, the virtual door state machine, event
normalisation, the event pipeline and attack-chain reconstruction. It imports
no web framework, database driver, network client or AI library, which a CI
test enforces (tests/test_import_boundary.py). Time is always passed in, so
every decision is reproducible.

The FastAPI routes, SQLAlchemy persistence, OpenCV capture and InsightFace
embedding extraction wrap this core; they do not replace it.
"""
