"""Escaneo YARA opcional. Si yara-python no está instalado, se omite sin fallar."""
from __future__ import annotations

import os

from ..models import YaraMatch

try:
    import yara  # type: ignore
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False


def _compile(rules_dir: str):
    filepaths = {}
    for root, _, files in os.walk(rules_dir):
        for f in files:
            if f.endswith((".yar", ".yara")):
                filepaths[f] = os.path.join(root, f)
    if not filepaths:
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except yara.SyntaxError:
        return None


def scan_yara(data: bytes, rules_dir: str) -> list[YaraMatch]:
    if not _HAS_YARA or not os.path.isdir(rules_dir):
        return []
    rules = _compile(rules_dir)
    if rules is None:
        return []
    matches = []
    for m in rules.match(data=data):
        matches.append(
            YaraMatch(rule=m.rule, tags=list(m.tags), meta=dict(m.meta))
        )
    return matches
