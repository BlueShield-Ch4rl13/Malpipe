"""CLI de malpipe.

Uso:
    python -m malpipe muestra.exe
    python -m malpipe muestra.exe -o resultados/ --no-dynamic
    python -m malpipe carpeta_muestras/ -o resultados/ --cti --stix --misp
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .config import config
from .enrich.cti import cargar_feed
from .export import a_misp, a_stix
from .pipeline import analyze
from .report import to_html, to_json


def _escribir_json(datos: dict, ruta: str) -> None:
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)


def _analyze_one(path: str, outdir: str, do_dynamic: bool, feed: dict | None, stix: bool, misp: bool) -> None:
    print(f"[*] Analizando: {path}")
    report = analyze(path, do_dynamic=do_dynamic, cti_feed=feed)

    sha = report.static.hashes.sha256[:12] or "sample"
    base = os.path.join(outdir, sha)
    to_json(report, base + ".json")
    to_html(report, base + ".html")
    if stix:
        _escribir_json(a_stix(report), base + ".stix.json")
    if misp:
        _escribir_json(a_misp(report), base + ".misp.json")

    print(f"    veredicto : {report.verdict.upper()} ({report.score}/100)")
    if report.dynamic.engine and report.dynamic.engine != "ninguno":
        estado = "ok" if report.dynamic.analyzed else f"omitido ({report.dynamic.error})"
        print(f"    dinámico  : {report.dynamic.engine} — {estado}")
    for c in report.configs:
        print(f"    familia   : {c.family} ({c.extractor}, confianza {c.confidence}) C2: {', '.join(c.c2) or '-'}")
    if report.cti.checked:
        print(f"    News CTI  : {len(report.cti.matches)} coincidencia(s)"
              + (f": {', '.join(m.matched for m in report.cti.matches)}" if report.cti.matches else ""))
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
    parser.add_argument("--cti", action="store_true",
                        help="cruza los indicadores con el feed de News CTI (MALPIPE_CTI_URL o el público)")
    parser.add_argument("--cti-fichero", metavar="RUTA", help="feed de News CTI local (iocs_latest.json)")
    parser.add_argument("--stix", action="store_true", help="escribe también <sha>.stix.json (STIX 2.1)")
    parser.add_argument("--misp", action="store_true", help="escribe también <sha>.misp.json (evento MISP)")
    parser.add_argument("--version", action="version", version=f"malpipe {__version__}")
    args = parser.parse_args(argv)

    do_dynamic = not args.no_dynamic
    if do_dynamic and not config.dynamic_available:
        print("[!] Sin sandbox configurado (CAPE_URL o TRIAGE_API_KEY). "
              "Se ejecuta solo estático.", file=sys.stderr)

    feed = None
    if args.cti or args.cti_fichero:
        try:
            feed = cargar_feed(args.cti_fichero or config.cti_url)
            print(f"[*] News CTI: {len(feed.get('iocs') or [])} indicadores ({feed.get('generated_utc', '?')})")
        except Exception as exc:  # noqa: BLE001 - sin feed se analiza igual
            print(f"[!] No se pudo cargar News CTI: {exc}. Se sigue sin cruzar.", file=sys.stderr)

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
            _analyze_one(fp, args.output, do_dynamic, feed, args.stix, args.misp)
    elif os.path.isfile(args.target):
        _analyze_one(args.target, args.output, do_dynamic, feed, args.stix, args.misp)
    else:
        print(f"[!] No existe: {args.target}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
