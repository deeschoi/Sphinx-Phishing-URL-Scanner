"""When a scan job started running.

Revision ID: 0005
Revises: 0004

Maintenance treats a ``running`` row as stuck from ``started_at``, so a job
can sit in the durable queue without being marked timed out.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_jobs", "started_at")
