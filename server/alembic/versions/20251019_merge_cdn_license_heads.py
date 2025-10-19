"""Merge CDN proxy and license batch heads

Revision ID: 20251019_merge_cdn_license_heads
Revises: 20251019_add_license_batches, 20251019_add_proxy_protocol_flag
Create Date: 2025-10-19
"""

from __future__ import annotations

from typing import Sequence, Union


revision: str = "20251019_merge_cdn_license_heads"
down_revision: Union[str, Sequence[str], None] = (
    "20251019_add_license_batches",
    "20251019_add_proxy_protocol_flag",
)
branch_labels = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """No-op merge revision."""
    pass


def downgrade() -> None:
    """No-op merge revision."""
    pass
