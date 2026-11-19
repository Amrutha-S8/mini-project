"""Response and request models for event history, incidents and the dashboard.

Identity fields (``family_member_id``, ``member_name``, ``user_id``) are
optional because the API fills them only for roles allowed to see them
(owner decisions R-1 and D-3). A viewer always receives ``None`` there.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Decision = Literal["allow", "deny", "hold"]
Severity = Literal["info", "low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "resolved", "false_positive"]


class AccessEventPublic(BaseModel):
    id: int
    decision_id: str
    occurred_at: datetime
    door_id: str
    camera_id: str | None = None
    source: Literal["camera", "admin_review", "manual_override"]
    decision: Decision
    rule_name: str
    reason_code: str
    match_confidence: float | None = None
    #: Whether the engine matched a registered person. Shown to every role.
    identity: Literal["registered", "unknown"]
    family_member_id: int | None = None
    member_name: str | None = None


class SecurityEventPublic(BaseModel):
    id: int
    event_uid: str
    event_type: str
    modality: str
    severity: Severity
    outcome: Literal["succeeded", "blocked", "failed", "observed"]
    suspicious: bool
    occurred_at: datetime
    source_module: str
    detector_rule: str | None = None
    confidence: float | None = None
    door_id: str | None = None
    camera_id: str | None = None
    incident_id: int | None = None
    family_member_id: int | None = None
    user_id: int | None = None
    ip_address: str | None = None
    #: Already-redacted details. Admin only.
    details: dict[str, Any] | None = None


class IncidentSummary(BaseModel):
    id: int
    incident_uid: str
    title: str
    category: str
    severity: Severity
    status: IncidentStatus
    opened_at: datetime
    closed_at: datetime | None = None
    event_count: int
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    notify_recommended: bool
    assigned_to_user_id: int | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by_user_id: int | None = None
    #: The most recent finding's reason, if the incident came from detection.
    latest_reason: str | None = None


class AiAdvisory(BaseModel):
    """Advisory AI content, always labelled with its model and time (SR-AI-14)."""

    # ``model_version`` is a column name, not a Pydantic method.
    model_config = ConfigDict(protected_namespaces=())

    label: Literal["AI-generated advisory content"] = "AI-generated advisory content"
    summary: str
    recommendations: Any | None = None
    model_version: str
    generated_at: datetime


class DetectionPublic(BaseModel):
    """One suspicious-activity finding. Reasons never contain member names."""

    id: int
    detector_rule: str
    severity: Severity
    reason: str
    detected_at: datetime
    #: The stored security event that triggered the finding.
    security_event_id: int
    event_uids: list[str]


class IncidentDetail(IncidentSummary):
    resolution_notes: str | None = None
    resolved_by_user_id: int | None = None
    #: Rule findings, oldest first, each with its reason and related event.
    detections: list[DetectionPublic] = Field(default_factory=list)
    #: Deterministic attack-chain reconstruction. Admin only.
    attack_chain: Any | None = None
    attack_chain_generated_at: datetime | None = None
    #: Admin only, and only when the incident was AI-enriched.
    ai_advisory: AiAdvisory | None = None


class IncidentResolve(BaseModel):
    resolution: Literal["resolved", "false_positive"]
    resolution_notes: str = Field(min_length=1, max_length=2000)


class NotificationPublic(BaseModel):
    """One notification attempt as the provider reported it.

    ``delivered`` and ``read`` appear only after the provider confirmed them.
    ``accepted`` and ``sent`` mean the provider took the message; delivery is
    not confirmed.
    """

    id: int
    incident_id: int
    channel: Literal["whatsapp", "sms"]
    provider: str
    recipient_masked: str | None = None
    trigger_reason: str
    status: str
    delivery_confirmed: bool
    provider_message_id: str | None = None
    provider_status: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime
    sent_at: datetime | None = None
    delivered_at: datetime | None = None
    failed_at: datetime | None = None
    status_checked_at: datetime | None = None


class NotifyResponse(BaseModel):
    queued: bool
    message: str


class ChannelStatus(BaseModel):
    channel: Literal["whatsapp", "sms"]
    provider: str
    configured: bool
    recipient_masked: str | None = None
    #: Which settings are missing or invalid. Names only, never values.
    problems: list[str]
    delivery_confirmation: str


class FindingPublic(BaseModel):
    incident_id: int
    incident_uid: str
    rule: str
    severity: Severity
    reason: str
    created: bool
    notification_queued: bool


class IngestResponse(BaseModel):
    """Result of submitting one activity record for monitoring."""

    status: Literal["stored", "duplicate", "rejected"]
    event_uid: str | None = None
    error: str | None = None
    warnings: list[str]
    findings: list[FindingPublic]


class IncidentUpdate(BaseModel):
    """Admin change to an incident. Send only the fields to change.

    ``assigned_to_user_id: null`` unassigns; leaving the field out keeps the
    current assignee.
    """

    status: IncidentStatus | None = None
    resolution_notes: str | None = Field(default=None, min_length=1, max_length=2000)
    assigned_to_user_id: int | None = None


class DecisionCounts(BaseModel):
    allow: int = 0
    deny: int = 0
    hold: int = 0
    total: int = 0


class DashboardSummary(BaseModel):
    generated_at: datetime
    #: ``household`` for admin and viewer; ``own`` for a member, whose counts
    #: cover only their own access events.
    scope: Literal["household", "own"]
    access_last_24h: DecisionCounts
    access_last_7d: DecisionCounts
    access_all_time: DecisionCounts
    last_access_event_at: datetime | None = None
    #: Open and investigating incidents per severity. ``None`` for members.
    active_incidents_by_severity: dict[str, int] | None = None
    #: Active incidents no admin has acknowledged yet. ``None`` for members.
    unacknowledged_active_incidents: int | None = None
    #: ``None`` for members.
    suspicious_events_last_24h: int | None = None
