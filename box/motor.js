// Motor del portal, en un Web Worker para no congelar la pagina.
//
// Carga Pyodide (Python en WebAssembly), escribe el paquete malpipe en su
// sistema de ficheros, instala pefile desde la rueda servida por el propio
// portal y compila las reglas de rules/ con YARA-X. Despues, cada mensaje con
// un fichero se escanea con YARA y se analiza con malpipe.navegador.analizar.
// Nada de esto sale del navegador.

let preparado = null;

function progreso(texto, pct) {
  self.postMessage({ tipo: "progreso", texto, pct });
}

async function preparar() {
  const c = await (await fetch("./construccion.json")).json();
  progreso(`Cargando Python (Pyodide ${c.pyodide})…`, 8);
  const base = (ruta) => new URL(ruta, self.location.href).href;
  const { loadPyodide } = await import(base(c.rutas.pyodide + "pyodide.mjs"));
  const py = await loadPyodide({ indexURL: base(c.rutas.pyodide) });

  progreso("Cargando malpipe…", 50);
  const [codigo, rueda, fuentesYara] = await Promise.all([
    fetch("./py/malpipe.json").then((r) => r.json()),
    fetch("./py/" + c.pefile).then((r) => r.arrayBuffer()),
    fetch("./py/reglas.json").then((r) => r.json()),
  ]);
  const sitio = py.runPython("import site; site.getsitepackages()[0]");
  py.unpackArchive(rueda, "wheel", { extractDir: sitio });
  for (const [ruta, texto] of Object.entries(codigo)) {
    const destino = `${sitio}/${ruta}`;
    py.FS.mkdirTree(destino.slice(0, destino.lastIndexOf("/")));
    py.FS.writeFile(destino, texto);
  }
  py.runPython("import importlib; importlib.invalidate_caches(); import malpipe.navegador");
  const analizar = py.pyimport("malpipe.navegador").analizar;

  progreso(`Cargando YARA-X ${c.yarax}…`, 75);
  const yara = await import(base(c.rutas.yarax + "yara_x_js.js"));
  await yara.default({ module_or_path: base(c.rutas.yarax + "yara_x_js_bg.wasm") });
  // Un conjunto de reglas por fichero: uno roto no apaga los demas.
  const reglas = [];
  const errores = [];
  let total = 0;
  for (const [fichero, texto] of Object.entries(fuentesYara)) {
    const comp = new yara.Compiler();
    try {
      comp.addSource(texto);
      reglas.push({ fichero, r: comp.build() });
      total += (texto.match(/^\s*(?:(?:private|global)\s+)*rule\s+\w+/gm) || []).length;
    } catch (e) {
      errores.push(`${fichero}: ${String(e && e.message ? e.message : e).split("\n")[0]}`);
    }
  }
  return { analizar, reglas, errores, construccion: { ...c, reglas_yara: total } };
}

function escanear(motor, datos) {
  const salida = [];
  for (const { fichero, r } of motor.reglas) {
    for (const m of r.scan(datos).matches) {
      const meta = { fichero };
      for (const x of m.metadata || []) meta[x.identifier] = x.value;
      salida.push({ rule: m.identifier, tags: m.tags || [], meta });
    }
  }
  return salida;
}

self.onmessage = async (e) => {
  try {
    preparado ??= preparar();
    const motor = await preparado;
    if (e.data.tipo === "preparar") {
      self.postMessage({ tipo: "listo", construccion: motor.construccion, erroresYara: motor.errores });
      return;
    }
    const { nombre, datos, feed } = e.data;
    const bytes = new Uint8Array(datos);
    progreso("Escaneando con YARA…", 88);
    const yara = escanear(motor, bytes);
    progreso("Analizando…", 94);
    const salida = JSON.parse(motor.analizar(nombre, bytes, JSON.stringify(yara), feed || ""));
    self.postMessage({ tipo: "resultado", salida, erroresYara: motor.errores, construccion: motor.construccion });
  } catch (err) {
    preparado = err && String(err).includes("fetch") ? null : preparado;
    self.postMessage({ tipo: "error", texto: String(err && err.message ? err.message : err) });
  }
};
