"""Add result_json column to scans table.

Stores the full /api/scan response so the analyst can bind to server-truth
rather than the browser-echoed copy.  Nullable so older rows stay valid.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("result_json", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "result_json")
