// Interfaz del portal. Todo lo que sale de la muestra se pinta con textContent:
// una muestra puede llevar HTML o JavaScript en sus cadenas y aqui no se ejecuta.

const FEED_CTI = "https://raw.githubusercontent.com/BlueShield-Ch4rl13/ScriptNewsCTI/main/data/iocs_latest.json";
const MAX_MB = 50;

const $ = (id) => document.getElementById(id);
const motor = new Worker(new URL("./motor.js", import.meta.url), { type: "module" });
let ocupado = false;
let ultimo = null;

// ── utilidades de DOM ───────────────────────────────────────────────────────
function el(etiqueta, atributos = {}, ...hijos) {
  const n = document.createElement(etiqueta);
  for (const [k, v] of Object.entries(atributos)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "clase") n.className = v;
    else if (k === "texto") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  for (const h of hijos.flat()) if (h !== null && h !== undefined && h !== false) n.append(h instanceof Node ? h : String(h));
  return n;
}
const svg = (etiqueta, atributos = {}) => {
  const n = document.createElementNS("http://www.w3.org/2000/svg", etiqueta);
  for (const [k, v] of Object.entries(atributos)) n.setAttribute(k, String(v));
  return n;
};
const tamano = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`);
// Indicadores desactivados: que nadie haga clic por error en un C2
const desactivar = (v) => String(v).replace(/^http/i, "hxxp").replace(/\./g, "[.]");

function descargar(nombre, contenido, tipo = "application/json") {
  const url = URL.createObjectURL(new Blob([contenido], { type: tipo }));
  const a = el("a", { href: url, download: nombre });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ── estado de la carga ──────────────────────────────────────────────────────
function progreso(texto, pct) {
  $("estado").hidden = false;
  $("estado-texto").textContent = texto;
  if (pct !== undefined) $("barra").style.width = `${pct}%`;
}
function error(texto) {
  ocupado = false;
  $("estado").hidden = true;
  $("error").hidden = false;
  $("error").textContent = texto;
  for (const b of document.querySelectorAll("#inicio button")) b.disabled = false;
}

motor.addEventListener("message", (e) => {
  const m = e.data;
  if (m.tipo === "progreso") progreso(m.texto, m.pct);
  else if (m.tipo === "error") error(`No se pudo analizar: ${m.texto}`);
  else if (m.tipo === "listo") {
    $("n-reglas").textContent = m.construccion.reglas_yara;
  } else if (m.tipo === "resultado") {
    ocupado = false;
    ultimo = m;
    progreso("Hecho", 100);
    pintar(m.salida, m.erroresYara, m.construccion);
  }
});
motor.addEventListener("error", (e) => error(`El motor no ha podido arrancar: ${e.message || "error desconocido"}`));

async function feedCti() {
  if (!$("usar-cti").checked) return "";
  try {
    const r = await fetch(FEED_CTI, { cache: "no-cache" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.text();
  } catch (e) {
    console.warn("News CTI no disponible:", e);
    return "";
  }
}

async function analizar(nombre, datos) {
  if (ocupado) return;
  if (datos.byteLength > MAX_MB * 1048576) {
    error(`El fichero pesa ${tamano(datos.byteLength)}; el máximo en el navegador es ${MAX_MB} MB.`);
    return;
  }
  ocupado = true;
  $("error").hidden = true;
  for (const b of document.querySelectorAll("#inicio button")) b.disabled = true;
  progreso("Preparando el motor (la primera vez descarga unos 20 MB)…", 3);
  const feed = await feedCti();
  motor.postMessage({ tipo: "analizar", nombre, datos, feed }, [datos]);
}

// ── entrada: fichero, arrastrar y ejemplos ─────────────────────────────────
$("fichero").addEventListener("change", async (e) => {
  const f = e.target.files && e.target.files[0];
  if (f) analizar(f.name, await f.arrayBuffer());
  e.target.value = "";
});
const zona = $("drop");
for (const ev of ["dragenter", "dragover"]) zona.addEventListener(ev, (e) => { e.preventDefault(); zona.classList.add("encima"); });
for (const ev of ["dragleave", "drop"]) zona.addEventListener(ev, () => zona.classList.remove("encima"));
zona.addEventListener("drop", async (e) => {
  e.preventDefault();
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) analizar(f.name, await f.arrayBuffer());
});
// Calentar el motor en cuanto alguien muestra intencion de usarlo
for (const ev of ["pointerenter", "focusin", "dragenter"]) {
  zona.addEventListener(ev, () => motor.postMessage({ tipo: "preparar" }), { once: true });
}

// EICAR: la cadena estandar de prueba de los antivirus. Se compone al vuelo
// (al reves en el codigo) para que este .js no salte en el antivirus de nadie.
$("ej-eicar").addEventListener("click", () => {
  const cadena = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".split("").reverse().join("");
  analizar("eicar.com", new TextEncoder().encode(cadena).buffer);
});

// Tabla de configuracion de un beacon de Cobalt Strike con datos inventados
// (dominio .test reservado), cifrada con el XOR 0x2e de la version 4: es lo
// que el extractor reconoce. No es un beacon: no hay codigo, solo la tabla.
$("ej-beacon").addEventListener("click", () => {
  const partes = [];
  const u16 = (v) => [(v >> 8) & 255, v & 255];
  const u32 = (v) => [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
  const corto = (i, v) => partes.push(...u16(i), ...u16(1), ...u16(2), ...u16(v));
  const entero = (i, v) => partes.push(...u16(i), ...u16(2), ...u16(4), ...u32(v));
  const datos = (i, texto, largo) => {
    const b = new TextEncoder().encode(texto);
    partes.push(...u16(i), ...u16(3), ...u16(largo), ...b, ...new Array(largo - b.length).fill(0));
  };
  corto(1, 8); corto(2, 443); entero(3, 60000); corto(5, 20);
  datos(8, "cdn.ejemplo-malo.test,/jquery-3.3.1.min.js", 256);
  datos(9, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 128);
  datos(10, "/submit.php", 64); entero(37, 305419896); partes.push(0, 0, 0, 0, 0, 0);
  const relleno = (n) => Array.from({ length: n }, (_, i) => (i * 37 + 11) & 255);
  const bytes = new Uint8Array([...relleno(2048), ...partes.map((b) => b ^ 0x2e), ...relleno(1024)]);
  analizar("beacon-sintetico.bin", bytes.buffer);
});

// ── resultado ───────────────────────────────────────────────────────────────
const TEXTO = {
  malicioso: ["MALICIOSO", "#F0616D", "Hay pruebas claras de que es malware. No lo abras ni lo reenvíes."],
  sospechoso: ["SOSPECHOSO", "#E0A34A", "Tiene rasgos habituales en el malware. Trátalo como peligroso hasta que alguien lo revise."],
  limpio: ["SIN SEÑALES", "#4FD6C4", "No se han encontrado señales de malware."],
  desconocido: ["SIN SEÑALES", "#4FD6C4", "El análisis estático no encuentra señales de malware. No es una garantía: un fichero empaquetado o cifrado puede esconderlas."],
};

function indicador(puntos, color) {
  const s = svg("svg", { viewBox: "0 0 120 120", role: "img", "aria-label": `Puntuación ${puntos} de 100` });
  const r = 50;
  const largo = 2 * Math.PI * r;
  s.append(svg("circle", { cx: 60, cy: 60, r, fill: "none", stroke: "#171E28", "stroke-width": 10 }));
  s.append(svg("circle", { cx: 60, cy: 60, r, fill: "none", stroke: color, "stroke-width": 10, "stroke-linecap": "round", "stroke-dasharray": `${(largo * puntos) / 100} ${largo}`, transform: "rotate(-90 60 60)" }));
  const t = svg("text", { x: 60, y: 67, "text-anchor": "middle", fill: "#E6EDF3", "font-size": 28, "font-family": "ui-monospace, monospace", "font-weight": 700 });
  t.textContent = String(puntos);
  s.append(t);
  return s;
}

function tarjeta(titulo, contenido, clase = "") {
  return el("div", { clase: `tarjeta ${clase}` }, el("h3", { texto: titulo }), contenido);
}
const vacio = (texto) => el("p", { clase: "vacio", texto });
const lista = (valores, transformar = (v) => v) =>
  valores.length ? el("ul", { clase: "lista" }, valores.map((v) => el("li", { texto: transformar(v) }))) : vacio("Ninguno.");

function pintar(salida, erroresYara, construccion) {
  const inf = salida.informe;
  const st = inf.static;
  const [etiqueta, color, explicacion] = TEXTO[inf.verdict] || TEXTO.desconocido;
  const nodo = $("resultado");
  nodo.replaceChildren();
  $("inicio").hidden = true;
  nodo.hidden = false;
  window.scrollTo({ top: 0 });

  const base = (st.hashes.sha256 || "muestra").slice(0, 12);
  const veredicto = el("div", { clase: "veredicto", texto: etiqueta });
  veredicto.style.color = color;
  nodo.append(el("div", { clase: "heroe" },
    el("div", { clase: "indicador" }, indicador(inf.score, color), veredicto),
    el("div", {},
      el("h2", { texto: st.filename }),
      el("p", { clase: "explicacion", texto: explicacion }),
      el("div", { clase: "datos" },
        [["Tipo", st.filetype], ["Tamaño", tamano(st.size)], ["SHA-256", st.hashes.sha256], ["MD5", st.hashes.md5],
         ["Analizado", `en tu navegador · malpipe ${inf.version}`]]
          .map(([k, v]) => el("div", {}, el("span", { clase: "k", texto: k }), el("span", { clase: "v", texto: v })))),
      el("div", { clase: "descargas" },
        el("button", { clase: "btn primario", type: "button", texto: "Informe HTML", onclick: () => descargar(`${base}.html`, salida.html, "text/html") }),
        el("button", { clase: "btn", type: "button", texto: "JSON", onclick: () => descargar(`${base}.json`, JSON.stringify(inf, null, 2)) }),
        el("button", { clase: "btn", type: "button", texto: "STIX 2.1", onclick: () => descargar(`${base}.stix.json`, JSON.stringify(salida.stix, null, 2)) }),
        el("button", { clase: "btn", type: "button", texto: "Evento MISP", onclick: () => descargar(`${base}.misp.json`, JSON.stringify(salida.misp, null, 2)) })))));

  const rejilla = el("div", { clase: "rejilla" });
  nodo.append(rejilla);

  // Por que
  rejilla.append(tarjeta("Por qué esta puntuación", inf.reasons.length
    ? el("div", {}, inf.reasons.map((r) => {
        const m = /^([+≥]\d+) (.*)$/.exec(r);
        return el("div", { clase: "razon" }, el("span", { clase: "pts", texto: m ? m[1] : "=" }), el("span", { texto: m ? m[2] : r }));
      }))
    : vacio("Nada suma: ninguna de las señales que mira malpipe aparece en este fichero.")));

  // Familia
  if (inf.configs.length) {
    const familias = inf.configs.map((c) => el("div", {},
      el("p", {}, el("strong", { texto: c.family }),
        el("span", { clase: "muted", texto: ` · confianza ${c.confidence} · ${c.extractor}` })),
      el("p", { clase: "subt", texto: "Servidores de mando y control (C2)" }),
      lista(c.c2, desactivar),
      el("div", { clase: "tabla" }, el("table", { clase: "kv" }, Object.entries(c.values).map(([k, v]) =>
        el("tr", {}, el("th", { texto: k }),
          el("td", { clase: "mono", texto: Array.isArray(v) ? v.join(", ") : String(v) })))))));
    rejilla.append(tarjeta("Familia y configuración", el("div", {}, familias), "alerta"));
  }

  // News CTI
  const cti = inf.cti;
  rejilla.append(tarjeta("News CTI", !cti.checked
    ? vacio("No se ha cruzado (desmarcado o feed no disponible).")
    : el("div", {},
        el("p", { clase: "muted", texto: `${cti.indicators.toLocaleString("es")} ${cti.indicators === 1 ? "indicador" : "indicadores"} en el feed de ${cti.generated || "?"}` }),
        cti.matches.length
          ? el("div", { clase: "tabla" }, el("table", { clase: "ancha" },
              el("tr", {}, ["Indicador", "Tipo", "Amenaza", "Nivel", "Fuentes"].map((t) => el("th", { texto: t }))),
              cti.matches.map((m) => el("tr", {}, el("td", { clase: "mono", texto: desactivar(m.matched) }), el("td", { texto: m.type }),
                el("td", { texto: m.threat }), el("td", { texto: m.level }), el("td", { texto: m.sources.join(", ") })))))
          : vacio("Ninguno de sus indicadores está en News CTI."))));

  // ATT&CK
  const porTactica = {};
  for (const t of inf.attack) (porTactica[t.tactic || "Sin táctica"] ??= []).push(t);
  rejilla.append(tarjeta("MITRE ATT&CK", inf.attack.length
    ? el("div", {}, Object.entries(porTactica).map(([tac, ts]) => el("div", { clase: "tactica" },
        el("div", { clase: "nombre", texto: tac }),
        ts.map((t) => el("a", { clase: "chip", href: `https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`,
          target: "_blank", rel: "noopener noreferrer", texto: `${t.id} ${t.name}` })))))
    : vacio("Ninguna técnica encaja con lo que se ve sin ejecutarlo.")));

  // YARA
  rejilla.append(tarjeta("Reglas YARA", el("div", {},
    st.yara.length
      ? el("div", { clase: "tabla" }, el("table", {}, st.yara.map((y) => el("tr", {},
          el("td", { clase: "mono" }, el("span", { clase: "chip peligro", texto: y.rule })),
          el("td", { texto: y.meta.description || y.meta.descripcion || "" }),
          el("td", { clase: "muted", texto: y.meta.fichero || "" })))))
      : vacio(`Ninguna de las ${construccion.reglas_yara} reglas coincide.`),
    erroresYara.length ? el("p", { clase: "subt", texto: `Ficheros de reglas que no compilan y se han saltado: ${erroresYara.join("; ")}` }) : null)));

  // Ejecutable
  if (st.pe.is_pe) {
    rejilla.append(tarjeta("Ejecutable de Windows (PE)", el("div", {},
      el("div", { clase: "datos" }, [["Arquitectura", st.pe.machine], ["Subsistema", st.pe.subsystem], ["DLL", st.pe.is_dll ? "sí" : "no"],
        ["Compilado", st.pe.compile_time || "—"], ["Imphash", st.pe.imphash || "—"]]
        .map(([k, v]) => el("div", {}, el("span", { clase: "k", texto: k }), el("span", { clase: "v", texto: v })))),
      el("p", { clase: "subt", texto: "Secciones (una entropía por encima de 7,2 suele ser código empaquetado o cifrado)" }),
      el("div", { clase: "tabla" }, el("table", { clase: "ancha" },
        el("tr", {}, ["Sección", "Tamaño virtual", "En disco", "Entropía"].map((t) => el("th", { texto: t }))),
        st.pe.sections.map((s) => {
          const barra = el("span");
          barra.style.width = `${Math.min(100, (s.entropy / 8) * 100)}%`;
          return el("tr", {}, el("td", { clase: "mono", texto: s.name }), el("td", { texto: s.virtual_size }), el("td", { texto: s.raw_size }),
            el("td", {}, el("div", { clase: `entropia ${s.entropy >= 7.2 ? "alta" : ""}` }, el("span", { clase: "b" }, barra), el("span", { clase: "mono", texto: s.entropy }))));
        }))),
      el("p", { clase: "subt", texto: "Imports que suele usar el malware" }),
      st.pe.suspicious_imports.length ? el("div", {}, st.pe.suspicious_imports.map((i) => el("span", { clase: "chip", texto: i }))) : vacio("Ninguno."))));
  }

  // Indicadores y cadenas
  const ind = st.indicators;
  const grupos = [["IP", ind.ips], ["Dominios", ind.domains], ["URL", ind.urls], ["Correos", ind.emails]];
  rejilla.append(tarjeta("Indicadores en sus cadenas", grupos.some(([, v]) => v.length)
    ? el("div", {}, grupos.filter(([, v]) => v.length).map(([t, v]) =>
        el("div", {}, el("p", { clase: "subt", texto: `${t} (${v.length})` }), lista(v, desactivar))))
    : vacio("Ninguno: no hay IP, dominios, URL ni correos en sus cadenas.")));
  rejilla.append(tarjeta("Cadenas de interés", lista(st.interesting_strings)));

  nodo.append(el("div", { clase: "acciones" },
    el("button", { clase: "btn primario", type: "button", texto: "Analizar otro fichero", onclick: volver })));
  $("version").textContent = `${inf.version} · Pyodide ${construccion.pyodide} · YARA-X ${construccion.yarax}`;
}

function volver() {
  $("resultado").hidden = true;
  $("resultado").replaceChildren();
  $("inicio").hidden = false;
  $("estado").hidden = true;
  for (const b of document.querySelectorAll("#inicio button")) b.disabled = false;
  window.scrollTo({ top: 0 });
}

// Para las pruebas de extremo a extremo
window.__malpipe = { ultimo: () => ultimo };
