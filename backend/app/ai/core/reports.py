"""Deterministic security reports (Security Report and Incident Analysis agents).

Reports are built from stored facts by fixed rules. No model writes them,
and under the owner's privacy policy they never go to Gemini, because they
are household data. The same input always gives byte-identical output.

Audience rules follow the retrieval permissions (DD-08 decision 5):

* **admin**: full detail, including event ids, links and evidence references.
* **viewer**: security summaries and incident reports without event ids,
  link explanations, evidence references or member/user identifiers.
* **member**: no incident or period reports (``ReportAccessDenied``).

Period windows are whole calendar periods in the household timezone
(daily: yesterday; weekly: last Monday-to-Monday; monthly: last calendar
month), converted to UTC, so daylight-saving changes give 23 or 25 hour days
rather than shifted boundaries.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from enum import StrEnum
from zoneinfo import ZoneInfo

from app.ai.core.types import Role, UserContext
from app.domain.attack_chain import Incident
from app.domain.events import Modality, SecurityEvent, Severity


class Period(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ReportAccessDenied(PermissionError):
    pass


def _audience(ctx: UserContext) -> Role:
    role = ctx.parsed_role if ctx.is_active else None
    if role not in (Role.ADMIN, Role.VIEWER):
        raise ReportAccessDenied("reports are available to admins and viewers")
    return role


def report_window(
    period: Period, now: datetime, timezone: str
) -> tuple[datetime, datetime]:
    """[start, end) in UTC for the most recent *complete* period."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    tz = ZoneInfo(timezone)
    local = now.astimezone(tz)
    today = local.date()
    if period is Period.DAILY:
        start_d, end_d = today - timedelta(days=1), today
    elif period is Period.WEEKLY:
        this_monday = today - timedelta(days=today.weekday())
        start_d, end_d = this_monday - timedelta(days=7), this_monday
    elif period is Period.MONTHLY:
        first = today.replace(day=1)
        start_d = (first - timedelta(days=1)).replace(day=1)
        end_d = first
    else:  # pragma: no cover - exhaustive over Period
        raise ValueError(f"unknown period {period!r}")

    def midnight(d: date) -> datetime:
        return datetime.combine(d, time.min, tzinfo=tz).astimezone(UTC)

    return midnight(start_d), midnight(end_d)


@dataclass(frozen=True)
class PeriodSummary:
    period: Period
    start: datetime
    end: datetime
    total_events: int
    suspicious_events: int
    blocked: int
    failed_logins: int
    throttled_logins: int
    unknown_visitor_sightings: int
    access_denied: int
    access_allowed: int
    by_severity: tuple[tuple[str, int], ...]
    by_modality: tuple[tuple[str, int], ...]
    top_event_types: tuple[tuple[str, int], ...]
    incidents: int
    incidents_by_severity: tuple[tuple[str, int], ...]


def summarise_period(
    period: Period,
    events: Sequence[SecurityEvent],
    incidents: Sequence[Incident],
    *,
    now: datetime,
    timezone: str,
) -> PeriodSummary:
    start, end = report_window(period, now, timezone)
    window = [e for e in events if start <= e.occurred_at < end]
    in_window = [i for i in incidents if start <= i.started_at < end]
    types = Counter(e.event_type for e in window)
    severity = Counter(e.severity.name.lower() for e in window)
    modality = Counter(e.modality.value for e in window)
    inc_sev = Counter(i.severity.name.lower() for i in in_window)
    sev_order = [s.name.lower() for s in sorted(Severity, reverse=True)]
    return PeriodSummary(
        period=period,
        start=start,
        end=end,
        total_events=len(window),
        suspicious_events=sum(1 for e in window if e.suspicious),
        blocked=sum(1 for e in window if e.outcome == "blocked"),
        failed_logins=types["auth.login_failed"],
        throttled_logins=types["auth.login_throttled"],
        unknown_visitor_sightings=types["face.unknown_visitor"],
        access_denied=types["access.denied"],
        access_allowed=types["access.allowed"],
        by_severity=tuple((s, severity[s]) for s in sev_order if severity[s]),
        by_modality=tuple(
            (m.value, modality[m.value]) for m in Modality if modality[m.value]
        ),
        top_event_types=tuple(
            sorted(types.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        ),
        incidents=len(in_window),
        incidents_by_severity=tuple((s, inc_sev[s]) for s in sev_order if inc_sev[s]),
    )


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def render_period_report(summary: PeriodSummary, ctx: UserContext) -> str:
    _audience(ctx)  # admins and viewers see the same aggregate counts
    lines = [
        f"{summary.period.value.capitalize()} security report",
        f"Period: {_iso(summary.start)} to {_iso(summary.end)} (UTC)",
        "",
        f"Events: {summary.total_events} ({summary.suspicious_events} suspicious, "
        f"{summary.blocked} blocked)",
        f"Access: {summary.access_allowed} allowed, {summary.access_denied} denied",
        f"Failed logins: {summary.failed_logins} "
        f"(throttled: {summary.throttled_logins})",
        f"Unknown visitor sightings: {summary.unknown_visitor_sightings}",
        f"Incidents: {summary.incidents}",
    ]
    if summary.incidents_by_severity:
        lines.append(
            "Incidents by severity: "
            + ", ".join(f"{s} {n}" for s, n in summary.incidents_by_severity)
        )
    if summary.by_severity:
        lines.append(
            "Events by severity: "
            + ", ".join(f"{s} {n}" for s, n in summary.by_severity)
        )
    if summary.top_event_types:
        lines.append("Most frequent event types:")
        lines.extend(f"  - {t}: {n}" for t, n in summary.top_event_types)
    lines += [
        "",
        "Generated by fixed rules from stored records. Not AI-generated.",
    ]
    return "\n".join(lines)


def incident_category(incident: Incident) -> str:
    mods = incident.modalities
    if Modality.AI_AGENT in mods:
        return "ai_misuse"
    if mods & {Modality.BIOMETRIC, Modality.ACCESS, Modality.DOOR}:
        return "intrusion_attempt"
    if Modality.AUTH in mods:
        return "credential_attack"
    if mods & {Modality.ADMIN, Modality.API}:
        return "privilege_misuse"
    return "anomaly"


@dataclass(frozen=True)
class IncidentReport:
    incident_id: str
    title: str
    category: str
    severity: str
    text: str
    evidence_refs: tuple[str, ...]
    deterministic: bool = True
    is_ai_generated: bool = False


def render_incident_report(incident: Incident, ctx: UserContext) -> IncidentReport:
    role = _audience(ctx)
    full = role is Role.ADMIN
    category = incident_category(incident)
    severity = incident.severity.name.lower()
    title = f"{category.replace('_', ' ').capitalize()} ({severity})"
    lines = [
        title,
        f"Incident: {incident.incident_id}",
        f"Window: {_iso(incident.started_at)} to {_iso(incident.ended_at)}",
        "Layers: " + ", ".join(sorted(m.value for m in incident.modalities)),
        "",
        "Summary:",
        incident.summary,
        "",
        "Timeline:",
    ]
    for step in incident.timeline:
        line = (
            f"  {_iso(step.at)}  {step.event_type}  stage={step.stage.value}  "
            f"outcome={step.outcome}  severity={step.severity.name.lower()}"
        )
        if full:
            line += f"  event={step.event_id}"
            if step.evidence_ref:
                line += f"  evidence={step.evidence_ref}"
        lines.append(line)
    if incident.gaps:
        lines.append("")
        lines.append("Gaps in the record (nothing is inferred for these):")
        lines.extend(f"  {_iso(g.start)} to {_iso(g.end)}" for g in incident.gaps)
    if full and incident.links:
        lines.append("")
        lines.append("Why these events are linked:")
        lines.extend(
            f"  {link.a} -> {link.b}: {link.explanation}" for link in incident.links
        )
    if incident.recommendations:
        lines.append("")
        lines.append("Recommendations (for human review; nothing was executed):")
        lines.extend(f"  - {r}" for r in incident.recommendations)
    lines += ["", "Generated by fixed rules from stored records. Not AI-generated."]
    return IncidentReport(
        incident_id=incident.incident_id,
        title=title,
        category=category,
        severity=severity,
        text="\n".join(lines),
        evidence_refs=incident.evidence_refs if full else (),
    )
