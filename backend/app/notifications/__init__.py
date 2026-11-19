"""Homeowner notifications (module M20 core, stdlib only).

WhatsApp Cloud API first, SMS (Twilio) as fallback. The provider clients use
``urllib`` behind an injectable transport, so the whole send, fallback and
webhook-verification logic is testable without network access.

Delivery is never assumed. A provider accepting a request is recorded as
``accepted``; ``delivered`` and ``read`` are set only from the provider's own
status report (a signed webhook, or Twilio's message-status API).
"""
