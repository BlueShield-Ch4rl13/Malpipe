"""Informe en formato JSON (para ingesta en SIEM/The Hive u otras herramientas)."""
from __future__ import annotations

import json

from ..models import Report


def to_json(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
