"""JSON export for audit data."""

from __future__ import annotations

import json
from pathlib import Path


def export_audit_json(
    entries: list[dict[str, object]],
    output_path: str,
) -> None:
    """Export audit entries to a JSON file."""
    Path(output_path).write_text(
        json.dumps(entries, indent=2, default=str),
        encoding="utf-8",
    )
