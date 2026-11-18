"""AI / advisory tier (modules M16-M18). Read-only and advisory by construction.

Only ``app.ai.core`` exists today: standard-library safety and policy logic
that the future Gemini, LangChain, ChromaDB and LangGraph adapters must call.
The adapters are not written yet (DD-08 decision 9).

Rules enforced by ``tests/test_import_boundary.py``:

* Nothing in this package imports, transitively, the AccessEngine, the
  virtual door, the database session module (which holds the writer
  engine), services, API routes or token signing.
* AI packages (Gemini, LangChain, ChromaDB, LangGraph) may be imported only
  under ``app/ai/``, never in ``app/ai/core/`` or anywhere else.
* The tier is disabled unless ``AI_ENABLED=true`` *and* the gate record
  shows every required check passed (``app.ai.core.config``).
"""
