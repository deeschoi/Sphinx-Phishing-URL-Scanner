"""Public scan ids, per-client history, and redacted stored payloads.

Revision ID: 0004
Revises: 0003

Existing ``result_json`` blobs kept the URL the caller submitted, including
query strings and token-shaped path segments. This rewrites them and adds an
unguessable ``public_id`` so ``/api/scans/{id}`` is not enumerable. Job rows
store that public id instead of the integer primary key.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from phishing.db import redact_stored_result

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _load_json(value: object) -> object:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return value


def upgrade() -> None:
    op.add_column("scans", sa.Column("public_id", sa.String(length=36), nullable=True))
    op.add_column(
        "scans",
        sa.Column("client_key", sa.String(length=64), nullable=False, server_default=""),
    )

    bind = op.get_bind()
    scans = sa.table(
        "scans",
        sa.column("id", sa.Integer),
        sa.column("public_id", sa.String),
        sa.column("result_json", sa.JSON),
        sa.column("signals", sa.JSON),
    )
    rows = bind.execute(sa.select(scans.c.id, scans.c.result_json, scans.c.signals)).all()
    for row in rows:
        raw = _load_json(row.result_json)
        redacted = redact_stored_result(raw) if isinstance(raw, dict) else None
        signals = _load_json(row.signals)
        redacted_signals = (
            redact_stored_result({"signals": signals}).get("signals")
            if isinstance(signals, list)
            else signals
        )
        bind.execute(
            sa.update(scans)
            .where(scans.c.id == row.id)
            .values(
                public_id=str(uuid.uuid4()),
                result_json=redacted,
                signals=redacted_signals,
            )
        )

    # SQLite cannot ALTER a column to NOT NULL. New databases get the constraint
    # from create_all; Postgres can take it here. Every row was just backfilled.
    if bind.dialect.name != "sqlite":
        op.alter_column(
            "scans", "public_id", existing_type=sa.String(length=36), nullable=False
        )
    op.create_index("ix_scans_public_id", "scans", ["public_id"], unique=True)
    op.create_index("ix_scans_client_key", "scans", ["client_key"])

    op.add_column("scan_jobs", sa.Column("scan_public_id", sa.String(length=36), nullable=True))
    bind.execute(
        sa.text(
            "UPDATE scan_jobs SET scan_public_id = ("
            "SELECT public_id FROM scans WHERE scans.id = scan_jobs.scan_id)"
        )
    )
    op.drop_column("scan_jobs", "scan_id")
    op.alter_column(
        "scan_jobs",
        "scan_public_id",
        new_column_name="scan_id",
        existing_type=sa.String(length=36),
    )


def downgrade() -> None:
    op.alter_column(
        "scan_jobs",
        "scan_id",
        new_column_name="scan_public_id",
        existing_type=sa.String(length=36),
    )
    op.add_column("scan_jobs", sa.Column("scan_id", sa.Integer(), nullable=True))
    op.drop_column("scan_jobs", "scan_public_id")
    op.drop_index("ix_scans_client_key", table_name="scans")
    op.drop_index("ix_scans_public_id", table_name="scans")
    op.drop_column("scans", "client_key")
    op.drop_column("scans", "public_id")
