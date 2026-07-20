"""Informe del análisis estático: JSON estructurado + HTML autocontenido."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path


def _esc(v):
    return html.escape(str(v)) if v is not None else ""


def write_json(out_dir: Path, result: dict) -> Path:
    p = out_dir / "report.json"
    p.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def _rows(headers, rows):
    th = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="scroll"><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def write_html(out_dir: Path, result: dict) -> Path:
    idn = result["identity"]
    sc = result["score"]
    caps = result.get("capabilities", [])
    yara = result.get("yara", [])
    iocs = result.get("iocs", [])
    pe = result.get("pe", {})
    col = sc["verdict_color"]

    reasons = "".join(
        f'<div class="reason"><span class="pts">+{r["points"]}</span>'
        f'<span>{_esc(r["label"])}</span></div>' for r in sc["reasons"]) or \
        '<div class="muted">Sin señales de riesgo.</div>'

    cap_rows = [[f'<span class="mono att">{_esc(c["attack"])}</span>', _esc(c["capability"]),
                 _esc(c["tactic"]), f'<span class="muted mono">{_esc(", ".join(c["evidence"]))}</span>']
                for c in caps]
    caps_html = _rows(["ATT&CK", "Capacidad", "Táctica", "Evidencia"], cap_rows) if caps \
        else '<div class="muted">Ninguna capacidad detectada por imports/cadenas.</div>'

    yara_rows = [[f'<span class="mono">{_esc(m["rule"])}</span>',
                  _esc((m.get("meta", {}) or {}).get("severity", "")),
                  _esc((m.get("meta", {}) or {}).get("description", ""))] for m in yara]
    yara_html = _rows(["Regla", "Severidad", "Descripción"], yara_rows) if yara \
        else '<div class="muted">Sin coincidencias YARA.</div>'

    ioc_rows = [[_esc(i["type"]), f'<span class="mono wrap">{_esc(i.get("defanged", i["value"]))}</span>']
                for i in iocs]
    iocs_html = _rows(["Tipo", "Indicador"], ioc_rows) if iocs \
        else '<div class="muted">Sin IOCs incrustados.</div>'

    sec_html = ""
    if pe.get("sections"):
        sec_rows = [[f'<span class="mono">{_esc(s["name"])}</span>', _esc(s["vsize"]), _esc(s["rsize"]),
                     f'<span class="{"hot" if s["entropy"]>=7.2 else ""}">{_esc(s["entropy"])}</span>',
                     ("RWX" if s["exec"] and s["write"] else ("X" if s["exec"] else ""))]
                    for s in pe["sections"]]
        sec_html = f'<h3>Secciones del PE</h3>{_rows(["Sección","V.Size","R.Size","Entropía","Perm."], sec_rows)}'

    imports_html = ""
    if pe.get("imports"):
        flat = sorted({f for v in pe["imports"].values() for f in v})[:60]
        imports_html = (f'<h3>Imports destacados ({pe.get("import_count",0)} en total)</h3>'
                        f'<div class="chips">' + "".join(f'<span class="chip mono">{_esc(f)}</span>' for f in flat) + '</div>')

    anoms = pe.get("anomalies", [])
    anoms_html = ("<h3>Anomalías estructurales</h3><ul class='an'>" +
                  "".join(f"<li>{_esc(a)}</li>" for a in anoms) + "</ul>") if anoms else ""

    dyn = result.get("dynamic")
    dyn_html = ""
    if dyn:
        dyn_html = f'<h3>Análisis dinámico</h3><div class="muted">{_esc(json.dumps(dyn, ensure_ascii=False)[:400])}</div>'

    strings_preview = ""
    if result.get("strings"):
        interesting = [s for s in result["strings"] if len(s) >= 6][:80]
        strings_preview = ('<h3>Cadenas relevantes (muestra)</h3><div class="scroll" style="max-height:300px">'
                           '<pre class="mono">' + _esc("\n".join(interesting)) + '</pre></div>')

    doc = TEMPLATE
    for k, v in {
        "TITLE": _esc(idn["filename"]), "COLOR": col,
        "VERDICT": _esc(sc["verdict"].upper()), "SCORE": _esc(sc["risk_score"]),
        "CONF": _esc(sc["confidence"]),
        "FMT": _esc(idn.get("format", "")), "TYPE": _esc(idn.get("type", "")),
        "SIZE": _esc(idn["size"]), "ENT": _esc(idn["entropy"]),
        "MD5": _esc(idn["md5"]), "SHA256": _esc(idn["sha256"]),
        "IMPHASH": _esc(pe.get("imphash", "") or "&mdash;"), "SSDEEP": _esc(idn.get("ssdeep", "")),
        "COMPILED": _esc(pe.get("compile_timestamp", "") or "&mdash;"),
        "REASONS": reasons, "CAPS": caps_html, "YARA": yara_html, "IOCS": iocs_html,
        "SECTIONS": sec_html, "IMPORTS": imports_html, "ANOMS": anoms_html,
        "DYNAMIC": dyn_html, "STRINGS": strings_preview,
        "GENERATED": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }.items():
        doc = doc.replace("{{" + k + "}}", str(v))

    p = out_dir / "report.html"
    p.write_text(doc, encoding="utf-8")
    return p


TEMPLATE = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{TITLE}} · malpipe</title>
<style>
:root{--bg:#0A0E13;--panel:#12171F;--panel2:#171E28;--line:#232C38;--ink:#E6EDF3;--muted:#8B97A5;
--teal:#4FD6C4;--amber:#E0A34A;--red:#F0616D;--mono:ui-monospace,"SF Mono",Consolas,monospace;
--sans:system-ui,"Segoe UI",Roboto,Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.5}
.mono{font-family:var(--mono);font-size:12.5px}.muted{color:var(--muted)}.wrap{word-break:break-all}
header{padding:16px 26px;border-bottom:1px solid var(--line);display:flex;align-items:baseline;gap:12px}
header .logo{color:var(--teal);font-family:var(--mono);font-weight:700;font-size:18px}
main{max-width:1200px;margin:0 auto;padding:22px 26px}
.hero{display:grid;grid-template-columns:170px 1fr;gap:22px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:18px}
.gauge{display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge .v{font-family:var(--mono);font-size:13px;text-align:center;margin-top:6px;font-weight:600}
.facts{display:grid;grid-template-columns:repeat(2,1fr);gap:8px 26px;font-size:12.5px}
.facts .k{color:var(--muted)}.facts .val{font-family:var(--mono);word-break:break-all}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:820px){.grid{grid-template-columns:1fr}.hero{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:16px}
.card h3,.card h2{margin:0 0 12px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
h3{margin:18px 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.reason{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line)}
.reason:last-child{border:none}.reason .pts{font-family:var(--mono);color:var(--amber);min-width:38px}
.scroll{overflow:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:12.5px}
thead th{position:sticky;top:0;background:#0F151D;text-align:left;padding:8px 12px;color:var(--muted);border-bottom:1px solid var(--line);white-space:nowrap}
tbody td{padding:7px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.att{color:var(--teal)}.hot{color:var(--red);font-weight:600}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{background:var(--panel2);border:1px solid var(--line);border-radius:4px;padding:2px 7px;font-size:11.5px}
ul.an{margin:0;padding-left:18px;color:var(--amber);font-size:13px}
pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-all;font-size:11.5px;color:var(--muted)}
footer{color:var(--muted);font-size:12px;padding:18px 26px;border-top:1px solid var(--line);text-align:center}
</style></head><body>
<header><span class="logo">&#9679; malpipe</span><span class="muted">análisis estático de malware</span></header>
<main>
  <div class="hero">
    <div class="gauge">
      <svg width="150" height="150" viewBox="0 0 150 150">
        <circle cx="75" cy="75" r="64" fill="none" stroke="#171E28" stroke-width="13"/>
        <circle cx="75" cy="75" r="64" fill="none" stroke="{{COLOR}}" stroke-width="13" stroke-linecap="round"
          stroke-dasharray="402" stroke-dashoffset="calc(402 - 402 * {{SCORE}} / 100)" transform="rotate(-90 75 75)"/>
        <text x="75" y="70" text-anchor="middle" fill="{{COLOR}}" font-family="monospace" font-size="34" font-weight="700">{{SCORE}}</text>
        <text x="75" y="92" text-anchor="middle" fill="#8B97A5" font-family="monospace" font-size="11">/ 100</text>
      </svg>
      <div class="v" style="color:{{COLOR}}">{{VERDICT}}</div>
    </div>
    <div>
      <div class="facts">
        <div><div class="k">Fichero</div><div class="val">{{TITLE}}</div></div>
        <div><div class="k">Formato · tipo</div><div class="val">{{FMT}} · {{TYPE}}</div></div>
        <div><div class="k">Tamaño</div><div class="val">{{SIZE}} bytes</div></div>
        <div><div class="k">Entropía</div><div class="val">{{ENT}}</div></div>
        <div><div class="k">Compilado</div><div class="val">{{COMPILED}}</div></div>
        <div><div class="k">Confianza</div><div class="val">{{CONF}}</div></div>
        <div style="grid-column:1/3"><div class="k">SHA-256</div><div class="val">{{SHA256}}</div></div>
        <div><div class="k">MD5</div><div class="val">{{MD5}}</div></div>
        <div><div class="k">imphash</div><div class="val">{{IMPHASH}}</div></div>
        <div style="grid-column:1/3"><div class="k">ssdeep</div><div class="val">{{SSDEEP}}</div></div>
      </div>
    </div>
  </div>
  <div class="grid">
    <div class="card"><h3>¿Por qué? — evidencias</h3>{{REASONS}}</div>
    <div class="card"><h3>Coincidencias YARA</h3>{{YARA}}</div>
  </div>
  <div class="card"><h2>Capacidades &amp; MITRE ATT&amp;CK</h2>{{CAPS}}</div>
  <div class="card"><h2>Indicadores de compromiso</h2>{{IOCS}}</div>
  <div class="card">{{SECTIONS}}{{ANOMS}}{{IMPORTS}}{{DYNAMIC}}</div>
  <div class="card">{{STRINGS}}</div>
</main>
<footer>malpipe · generado {{GENERATED}} · análisis estático · uso exclusivamente defensivo. La parte dinámica se ejecuta en un lab aislado.</footer>
</body></html>"""
