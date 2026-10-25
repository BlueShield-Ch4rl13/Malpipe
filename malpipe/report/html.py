"""Informe HTML autónomo (sin dependencias externas ni JS)."""
from __future__ import annotations

import html

from ..models import Report

_VERDICT_COLOR = {
    "malicioso": "#ef4444",
    "sospechoso": "#f59e0b",
    "limpio": "#22c55e",
    "desconocido": "#64748b",
}


def _esc(x: object) -> str:
    return html.escape(str(x))


def _rows(pairs: list[tuple[str, object]]) -> str:
    return "".join(
        f"<tr><td class='k'>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
        for k, v in pairs if v not in ("", None, [], {})
    )


def _chips(items: list[str]) -> str:
    if not items:
        return "<span class='muted'>—</span>"
    return "".join(f"<span class='chip'>{_esc(i)}</span>" for i in items)


def _list(items: list[str]) -> str:
    if not items:
        return "<p class='muted'>Ninguno.</p>"
    return "<ul>" + "".join(f"<li><code>{_esc(i)}</code></li>" for i in items) + "</ul>"


def _configs(report: Report) -> str:
    if not report.configs:
        return "<p class='muted'>Ninguna familia reconocida en la muestra.</p>"
    bloques = []
    for c in report.configs:
        filas = _rows([(k, v) for k, v in c.values.items()])
        bloques.append(
            f"<p><strong>{_esc(c.family)}</strong> <span class='muted'>· extractor {_esc(c.extractor)} · "
            f"confianza {_esc(c.confidence)} · {_esc(c.source)}</span></p>"
            f"<p><strong>C2:</strong></p>{_list(c.c2)}<table>{filas}</table>")
    return "".join(bloques)


def _cti(report: Report) -> str:
    cti = report.cti
    if not cti.checked:
        return f"<p class='muted'>No se ha cruzado. {_esc(cti.error)}</p>"
    cab = (f"<p class='muted'>{cti.indicators} indicadores del feed de {_esc(cti.generated)} · "
           f"<code>{_esc(cti.source)}</code></p>")
    if not cti.matches:
        return cab + "<p>Ningún indicador de la muestra está en News CTI.</p>"
    filas = "".join(
        f"<tr><td><code>{_esc(m.matched)}</code></td><td>{_esc(m.type)}</td><td>{_esc(m.threat)}</td>"
        f"<td>{_esc(m.level)}</td><td>{_esc(', '.join(m.sources))}</td></tr>" for m in cti.matches)
    return cab + ("<table><tr><th>Indicador</th><th>Tipo</th><th>Amenaza</th><th>Nivel</th><th>Fuentes</th></tr>"
                  f"{filas}</table>")


def render_html(report: Report) -> str:
    """El informe HTML como texto (el portal del navegador lo descarga sin escribir a disco)."""
    st, dy = report.static, report.dynamic
    color = _VERDICT_COLOR.get(report.verdict, "#64748b")

    sections_rows = "".join(
        f"<tr><td><code>{_esc(s.name)}</code></td><td>{s.virtual_size}</td>"
        f"<td>{s.raw_size}</td><td>{s.entropy}</td></tr>"
        for s in st.pe.sections
    )

    attack_rows = "".join(
        f"<tr><td><code>{_esc(t.id)}</code></td><td>{_esc(t.name)}</td>"
        f"<td>{_esc(t.tactic)}</td><td>{_esc(t.source)}</td></tr>"
        for t in report.attack
    ) or "<tr><td colspan='4' class='muted'>Sin técnicas mapeadas.</td></tr>"

    doc = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>malpipe · informe · {_esc(st.filename)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0;
         max-width: 60rem; margin: 0 auto; padding: 2rem 1.5rem; line-height:1.6; }}
  h1 {{ font-size:1.5rem; margin:0 0 .25rem; }}
  h2 {{ font-size:1.15rem; margin:2rem 0 .75rem; border-left:4px solid #3b82f6;
        padding-left:.6rem; }}
  .sub {{ color:#94a3b8; font-size:.85rem; margin-bottom:1.5rem; }}
  .verdict {{ display:inline-block; padding:.5rem 1.25rem; border-radius:.5rem;
             font-weight:700; color:#0f172a; background:{color}; }}
  .score {{ font-size:.9rem; color:#94a3b8; margin-left:.75rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; margin:.5rem 0; }}
  td, th {{ text-align:left; padding:.4rem .6rem; border-bottom:1px solid #1e293b;
           vertical-align:top; }}
  th {{ color:#94a3b8; font-weight:600; }}
  .k {{ color:#94a3b8; width:30%; }}
  code {{ font-family: ui-monospace, monospace; background:#1e293b; color:#7dd3fc;
         padding:.05rem .35rem; border-radius:.25rem; font-size:.82em;
         word-break:break-all; }}
  .chip {{ display:inline-block; background:#1e293b; border:1px solid #334155;
          color:#cbd5e1; border-radius:.3rem; padding:.15rem .5rem; margin:.15rem;
          font-size:.75rem; font-family:ui-monospace,monospace; }}
  ul {{ margin:.25rem 0; padding-left:1.25rem; }}
  .muted {{ color:#64748b; }}
  footer {{ margin-top:3rem; color:#64748b; font-size:.75rem;
           border-top:1px solid #1e293b; padding-top:1rem; }}
</style></head><body>

<h1>Informe de análisis de malware</h1>
<div class="sub">malpipe {report.version} · {_esc(report.generated_at)}</div>

<div class="verdict">{_esc(report.verdict).upper()}</div>
<span class="score">Puntuación: {report.score}/100</span>
<p><strong>Por qué:</strong></p>{_list(report.reasons)}

<h2>Fichero</h2>
<table>{_rows([
    ("Nombre", st.filename),
    ("Tamaño (bytes)", st.size),
    ("Tipo", st.filetype),
    ("SHA-256", st.hashes.sha256),
    ("SHA-1", st.hashes.sha1),
    ("MD5", st.hashes.md5),
    ("Imphash", st.hashes.imphash),
    ("ssdeep", st.hashes.ssdeep),
])}</table>

<h2>Análisis dinámico (sandbox)</h2>
<table>{_rows([
    ("Motor", dy.engine),
    ("Analizado", "sí" if dy.analyzed else "no"),
    ("Puntuación sandbox", dy.score),
    ("Familia", dy.family),
    ("Enlace", dy.sandbox_url),
    ("Aviso", dy.error),
])}</table>
<p><strong>Firmas:</strong></p>{_chips(dy.signatures)}
<p><strong>Red durante la detonación:</strong></p>{_list(dy.hosts + dy.domains + dy.urls)}

<h2>Configuración de familia</h2>
{_configs(report)}

<h2>News CTI</h2>
{_cti(report)}

<h2>MITRE ATT&amp;CK</h2>
<table>
<tr><th>Técnica</th><th>Nombre</th><th>Táctica</th><th>Fuente</th></tr>
{attack_rows}
</table>

<h2>PE / Cabecera</h2>
<table>{_rows([
    ("Es PE", "sí" if st.pe.is_pe else "no"),
    ("Arquitectura", st.pe.machine),
    ("DLL", "sí" if st.pe.is_dll else "no"),
    ("Subsistema", st.pe.subsystem),
    ("Compilado", st.pe.compile_time),
])}</table>
<p><strong>Imports sospechosos:</strong></p>{_chips(st.pe.suspicious_imports)}
<p><strong>Secciones:</strong></p>
<table>
<tr><th>Nombre</th><th>V.Size</th><th>R.Size</th><th>Entropía</th></tr>
{sections_rows or "<tr><td colspan='4' class='muted'>—</td></tr>"}
</table>

<h2>Indicadores (IOCs)</h2>
<p><strong>IPs</strong></p>{_list(st.indicators.ips)}
<p><strong>Dominios</strong></p>{_list(st.indicators.domains)}
<p><strong>URLs</strong></p>{_list(st.indicators.urls)}

<h2>Strings de interés</h2>
{_list(st.interesting_strings)}

<footer>
  Generado por malpipe. Análisis estático local + dinámico en sandbox (CAPEv2 propio o tria.ge).
  Heurística orientativa: contrasta siempre con el criterio del analista.
</footer>
</body></html>"""
    return doc


def to_html(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(report))
