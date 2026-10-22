"""Escaneo YARA opcional. Si yara-python no está instalado, se omite sin fallar.

Cada fichero de reglas se compila por separado: antes se compilaban todos
juntos y un error de sintaxis en uno desactivaba TODAS las reglas sin decir
nada. Ahora el fichero roto se salta, se avisa por el log y se informa en
YARA_ERRORES para quien quiera mostrarlo.
"""
from __future__ import annotations

import logging
import os

from ..models import YaraMatch

try:
    import yara  # type: ignore
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False


log = logging.getLogger("malpipe.yara")

# Ficheros de reglas que no compilan: {ruta: error}
YARA_ERRORES: dict[str, str] = {}
_CACHE: dict[str, list] = {}


def _compile(rules_dir: str) -> list:
    """Una regla compilada por fichero; los que fallan se saltan y se avisan."""
    if rules_dir in _CACHE:
        return _CACHE[rules_dir]
    compiladas = []
    for root, _, files in os.walk(rules_dir):
        for f in sorted(files):
            if not f.endswith((".yar", ".yara")):
                continue
            ruta = os.path.join(root, f)
            try:
                compiladas.append(yara.compile(filepath=ruta))
            except yara.Error as e:   # SyntaxError y errores de include
                YARA_ERRORES[ruta] = str(e)
                log.warning("reglas YARA de %s no compilan y se saltan: %s", ruta, e)
    _CACHE[rules_dir] = compiladas
    return compiladas


def scan_yara(data: bytes, rules_dir: str) -> list[YaraMatch]:
    if not _HAS_YARA or not os.path.isdir(rules_dir):
        return []
    matches = []
    for rules in _compile(rules_dir):
        for m in rules.match(data=data):
            matches.append(YaraMatch(rule=m.rule, tags=list(m.tags), meta=dict(m.meta)))
    return matches
