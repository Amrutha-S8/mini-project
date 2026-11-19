"""Suspicious activity monitoring: detection findings become stored incidents.

Flow for every newly stored security event:

    stored event -> recent history -> suspicious_activity.evaluate()
        -> one IncidentDetection per finding
        -> a new incident, or the open incident with the same dedupe key
           within the merge window
        -> which incidents need a homeowner notification

The facts used to check record claims (does this decision exist, what did
the AccessEngine decide, does this member exist) come from the server's own
tables. This service writes only ``incidents``, ``incident_detections``,
``security_events.incident_id`` (set once) and the audit log. It has no
access to the virtual door, the AccessEngine or permissions.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.core.config import Settings
from app.core.logging import get_logger
from app.domain.events import SecurityEvent, Severity
from app.domain.suspicious_activity import (
    DetectionConfig,
    Finding,
    evaluate,
    parse_quiet_hours,
    should_notify,
)
from app.models.access_event import AccessEvent
from app.models.audit_log import ACTION_INCIDENT_CREATE
from app.models.family_member import FamilyMember
from app.models.incident import IncidentRecord
from app.models.incident_detection import IncidentDetection
from app.models.security_event import SecurityEventRecord
from app.services import audit_service, security_event_service

logger = get_logger(__name__)

ACTIVE_STATUSES = ("open", "investigating")
TRIGGER_CREATED = "created"
TRIGGER_ESCALATED = "escalated"


class DbFacts:
    """``TrustedFacts`` over the server's own tables."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def decision_of(self, decision_id: str) -> str | None:
        return self._db.execute(
            select(AccessEvent.decision).where(AccessEvent.decision_id == decision_id)
        ).scalar_one_or_none()

    def member_status(self, member_id: int) -> str | None:
        member = self._db.get(FamilyMember, member_id)
        return None if member is None else member.status


def detection_config(settings: Settings) -> DetectionConfig:
    start, end = parse_quiet_hours(settings.monitoring_quiet_hours)
    return DetectionConfig(
        quiet_start=start, quiet_end=end, timezone=settings.household_timezone
    )


@dataclass(frozen=True)
class IncidentOutcome:
    incident_id: int
    incident_uid: str
    rule: str
    severity: str
    reason: str
    created: bool
    #: ``created``/``escalated`` when the homeowner should be told, else None.
    notify_trigger: str | None


def _severity_name(severity: Severity) -> str:
    return severity.name.lower()


def _open_incident_for(
    db: Session, dedupe_key: str, *, since: datetime
) -> IncidentRecord | None:
    return db.execute(
        select(IncidentRecord)
        .join(IncidentDetection, IncidentDetection.incident_id == IncidentRecord.id)
        .where(IncidentDetection.dedupe_key == dedupe_key)
        .where(IncidentDetection.detected_at >= since)
        .where(IncidentRecord.status.in_(ACTIVE_STATUSES))
        .order_by(IncidentDetection.detected_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _event_times(
    finding: Finding, event: SecurityEvent, history: list[SecurityEvent]
) -> tuple[datetime, datetime]:
    by_id = {e.event_id: e.occurred_at for e in history}
    by_id[event.event_id] = event.occurred_at
    times = [by_id[i] for i in finding.event_ids if i in by_id] or [event.occurred_at]
    return min(times), max(times)


def _all_event_uids(db: Session, incident_id: int) -> set[str]:
    uids: set[str] = set()
    for raw in db.execute(
        select(IncidentDetection.event_uids).where(
            IncidentDetection.incident_id == incident_id
        )
    ).scalars():
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, list):
            uids.update(str(v) for v in value)
    return uids


def _link_events(db: Session, incident_id: int, event_uids: tuple[str, ...]) -> None:
    """Point each unlinked event at the incident (``incident_id`` is set-once)."""
    if not event_uids:
        return
    rows = db.execute(
        select(SecurityEventRecord)
        .where(SecurityEventRecord.event_uid.in_(event_uids))
        .where(SecurityEventRecord.incident_id.is_(None))
    ).scalars()
    for row in rows:
        row.incident_id = incident_id


def _apply_finding(
    db: Session,
    finding: Finding,
    *,
    event: SecurityEvent,
    record: SecurityEventRecord,
    history: list[SecurityEvent],
    settings: Settings,
    now: datetime,
) -> IncidentOutcome:
    minimum = Severity.parse(settings.notify_min_severity)
    first, last = _event_times(finding, event, history)
    since = now - timedelta(minutes=settings.incident_merge_window_minutes)
    incident = _open_incident_for(db, finding.dedupe_key, since=since)
    created = incident is None
    notify_trigger: str | None = None

    if incident is None:
        incident = IncidentRecord(
            incident_uid=f"inc-{uuid.uuid4().hex}",
            opened_at=now,
            title=finding.title[:200],
            category=finding.rule[:50],
            severity=_severity_name(finding.severity),
            status="open",
            event_count=len(set(finding.event_ids)),
            first_event_at=first,
            last_event_at=last,
            notify_recommended=int(should_notify(finding.severity, minimum)),
        )
        db.add(incident)
        db.flush()
        audit_service.record(
            db,
            action=ACTION_INCIDENT_CREATE,
            entity_type="incident",
            entity_id=incident.id,
            actor_label="system",
            after={
                "incident_uid": incident.incident_uid,
                "rule": finding.rule,
                "severity": incident.severity,
            },
        )
        if should_notify(finding.severity, minimum):
            notify_trigger = TRIGGER_CREATED
    else:
        previous = Severity.parse(incident.severity)
        if finding.severity > previous:
            incident.severity = _severity_name(finding.severity)
            incident.title = finding.title[:200]
            if (
                should_notify(finding.severity, minimum)
                and incident.acknowledged_at is None
            ):
                notify_trigger = TRIGGER_ESCALATED
            if should_notify(finding.severity, minimum):
                incident.notify_recommended = 1
        if incident.first_event_at is None or first < incident.first_event_at:
            incident.first_event_at = first
        if incident.last_event_at is None or last > incident.last_event_at:
            incident.last_event_at = last

    db.add(
        IncidentDetection(
            incident_id=incident.id,
            security_event_id=record.id,
            detector_rule=finding.rule,
            dedupe_key=finding.dedupe_key[:200],
            severity=_severity_name(finding.severity),
            reason=finding.reason[:1000],
            event_uids=json.dumps(list(finding.event_ids)),
            detected_at=now,
        )
    )
    db.flush()
    if not created:
        incident.event_count = len(_all_event_uids(db, incident.id))
    _link_events(db, incident.id, finding.event_ids)
    db.flush()
    return IncidentOutcome(
        incident_id=incident.id,
        incident_uid=incident.incident_uid,
        rule=finding.rule,
        severity=incident.severity,
        reason=finding.reason,
        created=created,
        notify_trigger=notify_trigger,
    )


def process_event(
    db: Session,
    *,
    event: SecurityEvent,
    record: SecurityEventRecord,
    settings: Settings,
    now: datetime | None = None,
) -> list[IncidentOutcome]:
    """Run detection for one stored event and persist the results."""
    now = now or utc_now()
    cfg = detection_config(settings)
    history = security_event_service.recent_events(
        db, around=event.occurred_at, window=cfg.longest_window, exclude_id=record.id
    )
    findings = evaluate(event, history, DbFacts(db), cfg)
    return [
        _apply_finding(
            db,
            finding,
            event=event,
            record=record,
            history=history,
            settings=settings,
            now=now,
        )
        for finding in findings
    ]


@dataclass(frozen=True)
class MonitorResult:
    status: str
    event_uid: str | None
    error: str | None
    warnings: tuple[str, ...]
    incidents: tuple[IncidentOutcome, ...]


def record_and_detect(
    db: Session,
    raw: Mapping[str, Any],
    *,
    trusted: bool,
    settings: Settings,
    submitter_ip: str | None = None,
    now: datetime | None = None,
) -> MonitorResult:
    """Store one event (or its rejection) and run detection on what was stored."""
    now = now or utc_now()
    result = security_event_service.record_event(
        db, raw, trusted=trusted, submitter_ip=submitter_ip, now=now
    )
    outcomes: list[IncidentOutcome] = []
    if (
        result.status != security_event_service.STATUS_DUPLICATE
        and result.record is not None
        and result.event is not None
    ):
        outcomes = process_event(
            db, event=result.event, record=result.record, settings=settings, now=now
        )
    stored_uid = None
    if result.status == security_event_service.STATUS_STORED and result.event:
        stored_uid = result.event.event_id
    elif result.status == security_event_service.STATUS_DUPLICATE and result.record:
        stored_uid = result.record.event_uid
    return MonitorResult(
        status=result.status,
        event_uid=stored_uid,
        error=result.error,
        warnings=tuple(result.warnings),
        incidents=tuple(outcomes),
    )


def record_internal(
    db: Session,
    raw: Mapping[str, Any],
    *,
    settings: Settings,
    now: datetime | None = None,
) -> MonitorResult | None:
    """For server modules (auth, door): record, detect and COMMIT.

    Call it only after the caller's own writes are committed: on failure the
    session is rolled back, which must lose nothing but the monitoring rows.
    (SAVEPOINTs are not used because pysqlite does not support them reliably.)
    Never raises: monitoring must not break the operation it observes.
    Failures are logged, not hidden.
    """
    try:
        result = record_and_detect(db, raw, trusted=True, settings=settings, now=now)
        db.commit()
        return result
    except Exception:  # noqa: BLE001 - logged; the observed operation continues
        db.rollback()
        logger.error(
            "monitoring failed to record an internal event",
            extra={"context": {"event_type": str(raw.get("event_type"))}},
            exc_info=True,
        )
        return None
