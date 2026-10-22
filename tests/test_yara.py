"""Una regla YARA con un error no puede apagar todas las demás en silencio."""
from __future__ import annotations

import pytest

yara = pytest.importorskip("yara")

from malpipe.static import yara_scan  # noqa: E402


def test_un_fichero_roto_no_desactiva_los_demas(tmp_path):
    (tmp_path / "buena.yar").write_text('rule Buena { strings: $a = "MALPIPE-TEST" condition: $a }')
    (tmp_path / "rota.yar").write_text("rule Rota { strings: $a = condition: }")
    yara_scan._CACHE.clear()
    yara_scan.YARA_ERRORES.clear()
    hits = yara_scan.scan_yara(b"xx MALPIPE-TEST xx", str(tmp_path))
    assert [m.rule for m in hits] == ["Buena"]
    assert any(r.endswith("rota.yar") for r in yara_scan.YARA_ERRORES)


def test_las_reglas_del_repositorio_compilan():
    yara_scan._CACHE.clear()
    yara_scan.YARA_ERRORES.clear()
    yara_scan.scan_yara(b"", "rules")
    assert yara_scan.YARA_ERRORES == {}, yara_scan.YARA_ERRORES
