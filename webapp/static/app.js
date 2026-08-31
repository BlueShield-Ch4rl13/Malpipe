"use strict";

// Estado local
let selectedFile = null;
let turnstileToken = "";
let pollTimer = null;

const $ = (id) => document.getElementById(id);

// ---------- Arranque ----------
document.addEventListener("DOMContentLoaded", async () => {
  bindUpload();
  $("reset-btn").addEventListener("click", reset);
  $("analyze-btn").addEventListener("click", submit);

  try {
    const cfg = await (await fetch("/api/config")).json();
    if (cfg.max_mb) $("max-mb").textContent = cfg.max_mb;
    if (cfg.turnstile_sitekey) renderTurnstile(cfg.turnstile_sitekey);
  } catch (_) { /* el portal funciona igual sin config */ }
});

// ---------- Turnstile (opcional) ----------
function renderTurnstile(sitekey) {
  const mount = () => {
    if (!window.turnstile) return setTimeout(mount, 300);
    window.turnstile.render("#turnstile", {
      sitekey,
      theme: "dark",
      callback: (t) => { turnstileToken = t; },
      "expired-callback": () => { turnstileToken = ""; },
    });
  };
  mount();
}

// ---------- Selección de fichero ----------
function bindUpload() {
  const drop = $("drop");
  const input = $("file-input");

  drop.addEventListener("click", () => input.click());
  drop.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
  });
  input.addEventListener("change", () => setFile(input.files[0]));

  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("drag"); })
  );
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("drag"); })
  );
  drop.addEventListener("drop", (e) => {
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });
}

function setFile(f) {
  if (!f) return;
  selectedFile = f;
  $("drop-file").textContent = `${f.name} · ${fmtSize(f.size)}`;
  $("analyze-btn").disabled = false;
  hideError();
}

// ---------- Envío ----------
async function submit() {
  if (!selectedFile) return;
  hideError();
  $("analyze-btn").disabled = true;

  const form = new FormData();
  form.append("file", selectedFile);
  form.append("cf_turnstile_response", turnstileToken);

  let res;
  try {
    res = await fetch("/api/analyze", { method: "POST", body: form });
  } catch (_) {
    return showError("No se pudo conectar con el servidor.");
  }
  if (!res.ok) {
    const msg = (await res.json().catch(() => ({}))).detail || "Error en el análisis.";
    $("analyze-btn").disabled = false;
    return showError(msg);
  }

  const { job_id, phase } = await res.json();
  show("processing");
  $("phase").textContent = phase || "…";
  poll(job_id);
}

// ---------- Sondeo del estado ----------
function poll(jobId) {
  const tick = async () => {
    let job;
    try {
      const r = await fetch(`/api/result/${jobId}`);
      if (!r.ok) throw new Error();
      job = await r.json();
    } catch (_) {
      return showError("Se perdió la conexión con el análisis.");
    }

    $("phase").textContent = job.phase || "…";

    if (job.status === "completado" || (job.report && job.status !== "procesando")) {
      renderResult(job);
    } else if (job.status === "error") {
      // aun con error del sandbox, mostramos el estático si existe
      if (job.report) renderResult(job);
      else showError(job.error || "El análisis falló.");
    } else {
      pollTimer = setTimeout(tick, 4000);
    }
  };
  tick();
}

// ---------- Render del resultado ----------
const VERDICT_MSG = {
  malicioso: "Este fichero parece malicioso. No lo abras ni lo ejecutes.",
  sospechoso: "Este fichero muestra señales sospechosas. Trátalo con cautela.",
  limpio: "No se han encontrado señales de peligro. Aun así, mantén la prudencia.",
  desconocido: "No hay datos suficientes para un veredicto firme (falta el análisis dinámico).",
};

function renderResult(job) {
  const rep = job.report;
  const v = rep.verdict || "desconocido";

  $("verdict").className = "verdict v-" + v;
  $("verdict-badge").textContent = v.toUpperCase();
  $("verdict-line").textContent = VERDICT_MSG[v] || "";
  $("verdict-file").textContent = rep.static.filename;
  $("verdict-score").textContent = rep.score;

  const cards = $("result-cards");
  cards.innerHTML = "";
  cards.appendChild(fileCard(rep.static));
  cards.appendChild(dynamicCard(rep.dynamic, job));
  if (rep.attack.length) cards.appendChild(attackCard(rep.attack));
  if (hasIocs(rep.static.indicators)) cards.appendChild(iocCard(rep.static.indicators));
  if (rep.static.pe.is_pe) cards.appendChild(peCard(rep.static.pe));

  show("result");
}

function fileCard(st) {
  const h = st.hashes;
  return card("📄", "Resumen del fichero", table([
    ["Nombre", st.filename],
    ["Tipo", st.filetype],
    ["Tamaño", fmtSize(st.size)],
    ["SHA-256", codeEl(h.sha256)],
    ["MD5", codeEl(h.md5)],
    ["Imphash", h.imphash ? codeEl(h.imphash) : ""],
  ]));
}

function dynamicCard(dy, job) {
  const rows = [
    ["Motor", dy.engine],
    ["Analizado", dy.analyzed ? "sí" : "no"],
    ["Puntuación sandbox", dy.score != null ? dy.score : ""],
    ["Familia", dy.family],
  ];
  const el = card("🧪", "Análisis dinámico (sandbox)", table(rows));

  if (dy.signatures && dy.signatures.length) {
    el.appendChild(pEl("Comportamientos detectados:"));
    el.appendChild(chips(dy.signatures));
  } else if (dy.analyzed) {
    el.appendChild(pEl("Sin comportamientos destacados.", "muted"));
  }
  if (dy.sandbox_url) {
    const a = document.createElement("a");
    a.href = dy.sandbox_url; a.target = "_blank"; a.rel = "noopener";
    a.textContent = "Ver informe completo en el sandbox →";
    const p = document.createElement("p"); p.appendChild(a); el.appendChild(p);
  }
  if (!dy.analyzed && (dy.error || (job && job.status === "procesando"))) {
    el.appendChild(pEl(dy.error || "En curso…", "muted"));
  }
  return el;
}

function attackCard(techniques) {
  const el = card("🎯", "Técnicas MITRE ATT&CK", null);
  const t = document.createElement("table");
  t.innerHTML = "<tr><th>Técnica</th><th>Nombre</th><th>Táctica</th></tr>";
  techniques.forEach((x) => {
    const tr = document.createElement("tr");
    tr.appendChild(tdCode(x.id));
    tr.appendChild(td(x.name));
    tr.appendChild(td(x.tactic));
    t.appendChild(tr);
  });
  el.appendChild(t);
  return el;
}

function iocCard(ind) {
  const el = card("🌐", "Indicadores (IOCs)", null);
  addIoc(el, "IPs", ind.ips);
  addIoc(el, "Dominios", ind.domains);
  addIoc(el, "URLs", ind.urls);
  return el;
}

function peCard(pe) {
  const el = card("⚙️", "Cabecera PE", table([
    ["Arquitectura", pe.machine],
    ["Tipo", pe.is_dll ? "DLL" : "Ejecutable"],
    ["Subsistema", pe.subsystem],
    ["Compilado", pe.compile_time],
  ]));
  if (pe.suspicious_imports.length) {
    el.appendChild(pEl("Funciones sospechosas importadas:"));
    el.appendChild(chips(pe.suspicious_imports));
  }
  return el;
}

// ---------- Utilidades de DOM ----------
function card(icon, title, body) {
  const el = document.createElement("div");
  el.className = "card";
  const h = document.createElement("h2");
  h.innerHTML = `<span class="i">${icon}</span>`;
  h.appendChild(document.createTextNode(" " + title));
  el.appendChild(h);
  if (body) el.appendChild(body);
  return el;
}

function table(rows) {
  const t = document.createElement("table");
  rows.forEach(([k, v]) => {
    if (v === "" || v == null) return;
    const tr = document.createElement("tr");
    const tdk = document.createElement("td"); tdk.className = "k"; tdk.textContent = k;
    const tdv = document.createElement("td");
    if (v instanceof Node) tdv.appendChild(v); else tdv.textContent = v;
    tr.append(tdk, tdv); t.appendChild(tr);
  });
  return t;
}

function chips(items) {
  const box = document.createElement("div");
  items.forEach((i) => {
    const s = document.createElement("span"); s.className = "chip"; s.textContent = i;
    box.appendChild(s);
  });
  return box;
}

function addIoc(parent, label, items) {
  parent.appendChild(pEl(label));
  if (!items || !items.length) { parent.appendChild(pEl("Ninguno.", "muted")); return; }
  const ul = document.createElement("ul"); ul.className = "ioc";
  items.forEach((i) => {
    const li = document.createElement("li"); li.appendChild(codeEl(i)); ul.appendChild(li);
  });
  parent.appendChild(ul);
}

function td(txt) { const e = document.createElement("td"); e.textContent = txt || ""; return e; }
function tdCode(txt) { const e = document.createElement("td"); e.appendChild(codeEl(txt)); return e; }
function codeEl(txt) { const e = document.createElement("code"); e.textContent = txt; return e; }
function pEl(txt, cls) {
  const p = document.createElement("p"); p.textContent = txt;
  if (cls) p.className = cls; return p;
}

function hasIocs(ind) {
  return (ind.ips && ind.ips.length) || (ind.domains && ind.domains.length) ||
         (ind.urls && ind.urls.length);
}

// ---------- Navegación entre vistas ----------
function show(view) {
  ["upload", "processing", "result"].forEach((v) =>
    $("view-" + v).classList.toggle("hidden", v !== view)
  );
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function reset() {
  if (pollTimer) clearTimeout(pollTimer);
  selectedFile = null; turnstileToken = "";
  $("file-input").value = ""; $("drop-file").textContent = "";
  $("analyze-btn").disabled = true;
  if (window.turnstile) try { window.turnstile.reset(); } catch (_) {}
  show("upload");
}

// ---------- Helpers ----------
function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}
function showError(msg) {
  const e = $("upload-error");
  e.textContent = msg; e.classList.remove("hidden");
  show("upload");
  $("analyze-btn").disabled = !selectedFile;
}
function hideError() { $("upload-error").classList.add("hidden"); }
