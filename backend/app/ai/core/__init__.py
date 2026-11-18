"""Standard-library AI core: the policy and safety layer of the AI tier.

Every module here is pure Python (stdlib plus ``app.ai.core`` and three
read-only domain modules: ``events``, ``evidence`` and ``attack_chain``),
so it is fully testable without any AI package. It decides what the AI tier
may see, send, say and recommend. It never decides access and has no way to
act on the door, permissions, visitors or lockdown.

Modules:

* ``config``             kill switch and gate record (AI_ENABLED=false default)
* ``types``              user context, roles, record kinds, retrieved chunks
* ``access_policy``      role-based retrieval filters, checked three times
* ``sensitive``          detection and sanitisation of secrets and personal data
* ``privacy``            what may ever be sent to Gemini (default: nothing local)
* ``prompt_safety``      versioned templates, untrusted-data delimiting,
                         injection screening, context selection
* ``output_validation``  strict parsing of model output; decision-language guard
* ``citations``          citation and evidence-reference validation
* ``routing``            supervisor routing, role allowlists, action refusals
* ``reports``            deterministic incident and period reports
* ``escalation``         deterministic escalation recommendations
* ``evaluation``         retrieval, citation, routing and fallback metrics
"""
