"""ORM models.

Tables are created with the module that needs them, so no placeholder or
unused table is introduced:

    users, sessions, family_members, audit_log      -> migration 0001 (Day 2)
    access_events, visitor_events, security_events,
      incidents, incident_evidence,
      workflow_executions                           -> migration 0002 (DD-09)
    retention_extensions                            -> migration 0003 (DD-11)

Still to come, each with its owning module:

    face_embeddings                         -> Day 3  (M05)
    permissions                             -> Day 4  (M07)
    pipeline_logs                           -> Day 6  (M11)
    automation_tasks                        -> Day 12 (M19)
    notifications                           -> Day 13 (M20)

Columns that will point at those tables (``access_events.permission_id``,
``access_events.matched_embedding_id``, ``workflow_executions.automation_task_id``)
are plain integers until the target table exists.
"""

from app.models.access_event import AccessEvent
from app.models.audit_log import AuditLog
from app.models.family_member import FamilyMember
from app.models.incident import IncidentEvidence, IncidentRecord
from app.models.retention_extension import RetentionExtensionRecord
from app.models.security_event import SecurityEventRecord
from app.models.session import SessionRecord
from app.models.user import User
from app.models.visitor_event import VisitorEvent
from app.models.workflow_execution import WorkflowExecution

__all__ = [
    "AccessEvent",
    "AuditLog",
    "FamilyMember",
    "IncidentEvidence",
    "IncidentRecord",
    "RetentionExtensionRecord",
    "SecurityEventRecord",
    "SessionRecord",
    "User",
    "VisitorEvent",
    "WorkflowExecution",
]
