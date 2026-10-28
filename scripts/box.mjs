// Regenera motor/, la parte generada del portal estatico de box.carlosvillalbalagos.com.
//
//   npm ci && npm run box
//
// Cloudflare publica la raiz del repositorio tal cual, sin compilar (como
// dfir.): index.html, estilo.css, app.js y motor.js se editan a mano. Este
// script solo rehace motor/ con lo que sale de otros sitios: Pyodide y YARA-X de node_modules (versiones fijadas en
// package.json), el codigo de malpipe/ y las reglas de rules/ empaquetados en
// dos JSON, y la rueda de pefile de PyPI comprobando su SHA-256. Ejecutalo
// cada vez que cambies malpipe/ o rules/: el CI falla si motor/ no esta al dia.
// Las carpetas de Pyodide y YARA-X llevan la version en el nombre: se pueden
// cachear para siempre (ver _headers).
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const RAIZ = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(RAIZ, "motor");
const paquete = (n) => JSON.parse(fs.readFileSync(path.join(RAIZ, "node_modules", n, "package.json"), "utf8"));

const PYODIDE = paquete("pyodide").version;
const YARAX = paquete("@virustotal/yara-x").version;
const PEFILE = {
  nombre: "pefile-2024.8.26-py3-none-any.whl",
  url: "https://files.pythonhosted.org/packages/54/16/12b82f791c7f50ddec566873d5bdd245baa1491bac11d15ffb98aecc8f8b/pefile-2024.8.26-py3-none-any.whl",
  sha256: "76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f",
};

function copiar(origen, destino) {
  fs.mkdirSync(path.dirname(destino), { recursive: true });
  fs.copyFileSync(origen, destino);
}

function ficheros(dir, filtro) {
  const salida = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const ruta = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== "__pycache__") salida.push(...ficheros(ruta, filtro));
    } else if (filtro(e.name)) {
      salida.push(ruta);
    }
  }
  return salida.sort();
}

async function pefile(destino) {
  const cache = path.join(RAIZ, "node_modules", ".cache", PEFILE.nombre);
  let datos = fs.existsSync(cache) ? fs.readFileSync(cache) : null;
  if (!datos) {
    const r = await fetch(PEFILE.url);
    if (!r.ok) throw new Error(`no se pudo descargar ${PEFILE.url}: HTTP ${r.status}`);
    datos = Buffer.from(await r.arrayBuffer());
  }
  const h = createHash("sha256").update(datos).digest("hex");
  if (h !== PEFILE.sha256) throw new Error(`${PEFILE.nombre}: SHA-256 ${h}, se esperaba ${PEFILE.sha256}`);
  fs.mkdirSync(path.dirname(cache), { recursive: true });
  fs.writeFileSync(cache, datos);
  fs.writeFileSync(destino, datos);
}

// 1. motor/ es entero generado: se rehace desde cero
fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(DIST, { recursive: true });

// 2. Pyodide (solo el nucleo: no se cargan paquetes de su repositorio).
// Desde la 314 el cargador del wasm es pyodide.asm.mjs; hasta la 0.29, pyodide.asm.js.
const dirPy = `pyodide-${PYODIDE}`;
const asm = ["pyodide.asm.mjs", "pyodide.asm.js"].find((f) => fs.existsSync(path.join(RAIZ, "node_modules", "pyodide", f)));
if (!asm) throw new Error(`pyodide ${PYODIDE}: no trae pyodide.asm.mjs ni pyodide.asm.js`);
for (const f of ["pyodide.mjs", asm, "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]) {
  copiar(path.join(RAIZ, "node_modules", "pyodide", f), path.join(DIST, dirPy, f));
}

// 3. YARA-X
const dirYara = `yara-x-${YARAX}`;
for (const f of ["yara_x_js.js", "yara_x_js_bg.wasm"]) {
  copiar(path.join(RAIZ, "node_modules", "@virustotal", "yara-x", "pkg", f), path.join(DIST, dirYara, f));
}

// 4. malpipe y sus reglas
const codigo = {};
for (const f of ficheros(path.join(RAIZ, "malpipe"), (n) => n.endsWith(".py"))) {
  codigo[path.relative(RAIZ, f).split(path.sep).join("/")] = fs.readFileSync(f, "utf8");
}
const reglas = {};
for (const f of ficheros(path.join(RAIZ, "rules"), (n) => /\.ya?ra?$/.test(n))) {
  reglas[path.basename(f)] = fs.readFileSync(f, "utf8");
}
fs.writeFileSync(path.join(DIST, "malpipe.json"), JSON.stringify(codigo));
fs.writeFileSync(path.join(DIST, "reglas.json"), JSON.stringify(reglas));
await pefile(path.join(DIST, PEFILE.nombre));

// 5. Lo que el motor necesita saber de esta construccion
const version = /version = "([^"]+)"/.exec(fs.readFileSync(path.join(RAIZ, "pyproject.toml"), "utf8"))[1];
const huella = createHash("sha256").update(JSON.stringify(codigo) + JSON.stringify(reglas)).digest("hex").slice(0, 12);
fs.writeFileSync(path.join(DIST, "construccion.json"), JSON.stringify({
  malpipe: version, pyodide: PYODIDE, yarax: YARAX, pefile: PEFILE.nombre,
  rutas: { pyodide: `./motor/${dirPy}/`, yarax: `./motor/${dirYara}/` },
  codigo: huella, ficheros_python: Object.keys(codigo).length, ficheros_yara: Object.keys(reglas).length,
}, null, 2));

const peso = ficheros(DIST, () => true).reduce((t, f) => t + fs.statSync(f).size, 0);
console.log(`motor/: malpipe ${version}, Pyodide ${PYODIDE}, YARA-X ${YARAX}, ` +
  `${Object.keys(codigo).length} modulos, ${Object.keys(reglas).length} ficheros YARA, ${(peso / 1048576).toFixed(1)} MB`);
