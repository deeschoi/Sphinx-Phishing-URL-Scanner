"""Create scan_jobs table for async and batch scans.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("batch_id", sa.String(length=36), nullable=True),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("client_key", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("timeout", sa.Integer(), nullable=False, server_default="8"),
    )
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_batch_id", "scan_jobs", ["batch_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_batch_id", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_created_at", table_name="scan_jobs")
    op.drop_table("scan_jobs")
