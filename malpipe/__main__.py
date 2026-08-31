"""CLI de malpipe.

Uso:
    python -m malpipe muestra.exe
    python -m malpipe muestra.exe -o resultados/ --no-dynamic
    python -m malpipe carpeta_muestras/ -o resultados/
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .config import config
from .pipeline import analyze
from .report import to_html, to_json


def _analyze_one(path: str, outdir: str, do_dynamic: bool) -> None:
    print(f"[*] Analizando: {path}")
    report = analyze(path, do_dynamic=do_dynamic)

    sha = report.static.hashes.sha256[:12] or "sample"
    base = os.path.join(outdir, sha)
    to_json(report, base + ".json")
    to_html(report, base + ".html")

    print(f"    veredicto : {report.verdict.upper()} ({report.score}/100)")
    if report.dynamic.engine and report.dynamic.engine != "ninguno":
        estado = "ok" if report.dynamic.analyzed else f"omitido ({report.dynamic.error})"
        print(f"    dinámico  : {report.dynamic.engine} — {estado}")
    if report.attack:
        print(f"    ATT&CK    : {', '.join(t.id for t in report.attack)}")
    print(f"    informe   : {base}.html\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="malpipe",
        description="Pipeline de análisis de malware (estático + dinámico).",
    )
    parser.add_argument("target", help="fichero o directorio de muestras a analizar")
    parser.add_argument(
        "-o", "--output", default="reports", help="directorio de salida (por defecto: reports/)"
    )
    parser.add_argument(
        "--no-dynamic", action="store_true", help="solo análisis estático"
    )
    parser.add_argument("--version", action="version", version=f"malpipe {__version__}")
    args = parser.parse_args(argv)

    do_dynamic = not args.no_dynamic
    if do_dynamic and not config.dynamic_available:
        print("[!] Sin sandbox configurado (TRIAGE_API_KEY/VT_API_KEY). "
              "Se ejecuta solo estático.", file=sys.stderr)

    os.makedirs(args.output, exist_ok=True)

    if os.path.isdir(args.target):
        files = [
            os.path.join(args.target, f)
            for f in sorted(os.listdir(args.target))
            if os.path.isfile(os.path.join(args.target, f))
        ]
        if not files:
            print("[!] No hay ficheros en el directorio.", file=sys.stderr)
            return 1
        for fp in files:
            _analyze_one(fp, args.output, do_dynamic)
    elif os.path.isfile(args.target):
        _analyze_one(args.target, args.output, do_dynamic)
    else:
        print(f"[!] No existe: {args.target}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
