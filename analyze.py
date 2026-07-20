#!/usr/bin/env python3
"""malpipe — pipeline automatizado de análisis de malware.

Uso exclusivamente defensivo. Analiza una muestra sin ejecutarla (estático) y,
opcionalmente, coordina su detonación en un sandbox AISLADO (dinámico).

  python analyze.py muestra.bin
  python analyze.py muestra.bin --output ./caso --rules ./rules
  python analyze.py muestra.bin --dynamic        # requiere sandbox configurado

ADVERTENCIA: trata toda muestra como peligrosa. El análisis estático es seguro
(no ejecuta el fichero). El dinámico SOLO debe correr en una VM aislada, sin red
o con red simulada, y con snapshots — nunca en tu equipo de trabajo.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from malpipe import capabilities, indicators, report, score, static


def analyze_file(path: Path, rules_dir: Path, do_dynamic: bool = False) -> dict:
    data = path.read_bytes()
    identity = static.identify(path, data)

    pe, elf = {}, {}
    if identity["format"] == "PE":
        pe = static.analyze_pe(data)
    elif identity["format"] == "ELF":
        elf = static.analyze_elf(path)

    strings = indicators.extract_strings(data)
    iocs = indicators.extract_iocs(strings)
    yara_hits = indicators.yara_scan(data, rules_dir)
    imports = (pe or elf).get("imports", {})
    caps = capabilities.detect(imports, strings)
    verdict = score.score(identity, pe or elf, caps, yara_hits, iocs)

    result = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "identity": identity, "pe": pe or elf, "score": verdict,
        "capabilities": caps, "yara": yara_hits, "iocs": iocs,
        "strings": strings,
    }
    if do_dynamic:
        from malpipe import sandbox
        result["dynamic"] = sandbox.detonate(path)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analyze.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sample", type=Path, help="Ruta de la muestra a analizar")
    ap.add_argument("--output", type=Path, help="Carpeta de salida (por defecto malpipe_<sha>)")
    ap.add_argument("--rules", type=Path, default=Path(__file__).parent / "rules",
                    help="Directorio con reglas YARA")
    ap.add_argument("--dynamic", action="store_true", help="Ejecutar análisis dinámico (sandbox aislado)")
    args = ap.parse_args(argv)

    if not args.sample.is_file():
        print(f"error: no existe la muestra {args.sample}", file=sys.stderr)
        return 2

    print(f"[malpipe] analizando {args.sample.name} …")
    result = analyze_file(args.sample, args.rules, args.dynamic)

    out = args.output or Path(f"malpipe_{result['identity']['sha256'][:12]}")
    out.mkdir(parents=True, exist_ok=True)
    jp = report.write_json(out, result)
    hp = report.write_html(out, result)

    sc = result["score"]
    print(f"  Veredicto : {sc['verdict']} · riesgo {sc['risk_score']}/100 · confianza {sc['confidence']}")
    caps = ", ".join(c["attack"] for c in result["capabilities"][:8])
    if caps:
        print(f"  ATT&CK    : {caps}")
    if result["yara"]:
        print(f"  YARA      : {', '.join(m['rule'] for m in result['yara'])}")
    print(f"  Informe   : {hp}")
    print(f"  JSON      : {jp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
