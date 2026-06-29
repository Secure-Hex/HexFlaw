# HexFlaw

> Analizador de vulnerabilidades de código fuente potenciado por IA — por [SecureHex](https://securehex.cl)

---

## 1. Qué es HexFlaw

**HexFlaw** es una herramienta de línea de comandos que realiza **análisis estático
de seguridad (SAST)** sobre código fuente, combinando análisis de programas clásico
(parsing AST, grafos de llamadas, taint tracing) con modelos de lenguaje (LLM) para
detectar, **confirmar** y documentar vulnerabilidades.

A diferencia de un linter o un grep de patrones, HexFlaw no se queda en "acá hay un
`system()`". Construye un modelo del programa, razona sobre si datos controlables por
un atacante **realmente alcanzan** ese sink sin sanitización, y solo entonces reporta.
Por cada vulnerabilidad confirmada produce:

- **Causa raíz** con archivos y líneas exactas.
- **Reporte ejecutivo y técnico** con CVSS v3.1 y remediación sugerida.
- **Prueba de concepto (PoC)** ejecutable, adaptada al tipo de objetivo.

### Objetivo de diseño

- **Local-first**: el código del cliente nunca sale de la máquina salvo decisión
  explícita. El backend de embeddings por defecto corre en CPU local.
- **Bajo costo en tokens**: el LLM es caro; HexFlaw aplica varias capas de filtrado
  barato *antes* de gastar una sola llamada (ver §4.7).
- **Recall sobre precisión en el filtrado**: en seguridad, un falso negativo (vuln
  no encontrada) es peor que un falso positivo. Los filtros previos al LLM están
  calibrados para **no descartar sinks reales**.
- **Agnóstico a interfaz**: toda la lógica vive en un Core Engine; la CLI es solo una
  capa de presentación. Una futura Web API reusa el mismo motor sin cambios.

### Tipos de aplicación soportados

Web, binarios C/C++, firmware de routers, apps móviles y smart contracts. Lenguajes
con definición builtin: Python, C, C++, JavaScript, TypeScript, Go, Java, Rust, PHP,
Ruby y **Solidity** (smart contracts). Extensible a otros vía el sistema de plugins de
lenguaje (`languages add/install/edit`).

---

## 2. Instalación

Requiere **Python 3.11+**.

```bash
git clone <repo-url> hexflaw && cd hexflaw

# Runtime base (suficiente para el pipeline completo, con fallbacks locales)
pip install -e .

# Con backends pesados opcionales (recomendado para calidad real):
#   embeddings  -> sentence-transformers (embeddings neuronales locales)
#   treesitter  -> parsing AST preciso multi-lenguaje
#   pdf         -> exportar reportes a PDF (weasyprint)
#   secrets     -> keyring del SO para almacenar API keys fuera de disco
#   openai      -> backend LLM alternativo (OpenAI)
#   tui         -> interfaz TUI (Textual)
#   dev         -> tests + linters
pip install -e ".[embeddings,treesitter,pdf,secrets,dev]"
```

### API key del LLM

El análisis con LLM requiere una API key. Hay tres formas de proveerla, en orden de
preferencia de seguridad:

```bash
# 1) Keyring del SO (recomendado; requiere el extra [secrets]):
hexflaw config --api-key sk-ant-...     # se guarda en el keyring, nunca en disco plano

# 2) Variable de entorno (tiene prioridad sobre lo persistido):
export ANTHROPIC_API_KEY=...
cp .env.example .env                    # alternativa: archivo .env

# 3) Sin keyring disponible, 'config --api-key' cae a ~/.hexflaw/config.json (600)
#    con una advertencia explícita.
```

La precedencia al resolver la key es: entorno > config.json > keyring. Sin key, el
pipeline corre igual hasta M3 (ingestión + code graph) y degrada de forma limpia en los
pasos que necesitan LLM.

### Perfilado del sistema (una sola vez)

```bash
hexflaw setup
```

`setup` detecta CPU, RAM, GPU, Ollama y conectividad, hace un benchmark rápido de
embeddings y **recomienda el backend óptimo** para tu hardware (lógica en §4.2). La
configuración global se guarda en `~/.hexflaw/config.json`.

---

## 3. Cómo funciona — alto nivel

### 3.1 El flujo de trabajo (análogo a git)

HexFlaw opera sobre un **proyecto**, detectado por la presencia de un directorio
`.hexflaw/` en el CWD o un directorio padre — igual que git encuentra `.git/`. No hace
falta pasar IDs: te parás en la carpeta del target y corrés los comandos.

```bash
cd ~/pentest/mi-target/
hexflaw init --name "Mi Target"     # crea .hexflaw/ en esta carpeta
hexflaw ingest ./codigo/            # M1: detecta lenguajes, chunkea, hashea
hexflaw analyze --target "..."      # M2 → M3 → M4 → M5 (hasta confirmar)
hexflaw report                      # M6a → M6b: reportes + CVSS
hexflaw poc                         # M6a → M6c: PoCs
```

O todo de una sola vez:

```bash
hexflaw run ./codigo/ --target "..." --format pdf
```

> **Cuidado con proyectos anidados:** `init` crea el `.hexflaw/` en el directorio
> actual. Si tu código está en una subcarpeta de otro proyecto HexFlaw, la detección
> estilo-git encontrará el `.hexflaw/` del padre. Inicializá el proyecto en la raíz
> correcta.

### 3.2 El pipeline de módulos

```
[M0 System Profiling]   ← setup: recomienda backend de embeddings
        ↓
[M1 Ingestion]          ← chunking por AST, hashing, guards de seguridad
        ↓
[M2 Target Definition]  ← qué analizar: directed (--target) o discovery
        ↓
[M3 Code Graph]         ← call graph, entry points, sinks
        ↓
[M4 Static Analysis]    ← filtrado barato → LLM → hallazgos preliminares
        ↓
[M5 Taint + Confirm]    ← ¿el input alcanza el sink? → confirmed/conditional/...
        ↓
[M6a Root Cause]
        ↓
[M6b Report]  ∥  [M6c PoC]   ← en paralelo
        ↓
findings/ + reports/ + poc/
```

### 3.3 Comandos y opciones

| Comando | Qué hace | Opciones clave |
|---|---|---|
| `setup` | Perfila el sistema (M0), recomienda backend y materializa los builtins de lenguaje (444) | `--reprofile`, `--yes` |
| `init` | Inicializa el proyecto en el CWD | `--name` |
| `ingest <fuente>` | Ingesta el código (M1). La fuente puede ser **directorio, `.zip`, URL git o URL http(s)** | `--incremental` |
| `analyze` | Pipeline M2→M5 | `--target`, `--path`, `--mode`, `--budget` |
| `report` | Reportes de confirmados (M6a→M6b) | `--format markdown\|pdf\|json\|sarif` |
| `poc` | PoCs de confirmados (M6a→M6c) | — |
| `run <fuente>` | Pipeline completo de una vez (acepta directorio/zip/git/url) | `--target`, `--format markdown\|pdf\|json\|sarif` |
| `status` | Estado del proyecto y artefactos | — |
| `config` | Ver/editar configuración (las API keys van al keyring) | `--show`, `--embedding-backend`, `--api-key`, `--token-budget` |
| `findings list` | Lista hallazgos | `--status`, `--run` |
| `findings show <ID>` | Detalle de un hallazgo (snippet, razonamiento, taint path) | `--run` |
| `findings recheck <ID>` | Re-evalúa **un solo** hallazgo con M5 | — |
| `findings runs` | Historial de análisis (cada run con su ID) | — |
| `languages list/show/add/edit/validate/remove/install/learn` | Plugin system de lenguajes | — |
| `tui` | Interfaz TUI (Textual): estado, findings y análisis en vivo | — |
| `agent` | Cola del backend LLM "agent" (status/pending/show/answer) | — |

#### Opciones transversales de `analyze`

- **`--target "..."`** — modo *directed*: describís la funcionalidad a auditar. El
  análisis se acota semánticamente a esa funcionalidad (§4.4). Sin `--target`, entra el
  modo *discovery*: el LLM propone la superficie de ataque más riesgosa.
- **`--path "dir1 dir2"`** — prioriza chunks bajo esas rutas. Es un **plus, no un filtro
  duro**: esos chunks suben al tope del ranking *y además saltan el pre-filtrado por
  keyword*, pero el sistema sigue aportando sus picks semánticos para el resto de la
  capacidad. Sirve para apuntar a un subsistema concreto sin perder lo que el sistema
  detecta por su cuenta.
- **`--mode thorough|balanced|economy`** — balance costo/profundidad. Controla el
  tamaño de batch, el tope de chunks y qué modelo se usa por tarea.
- **`--budget N`** — tope duro de tokens para ese análisis. Al alcanzarlo, M4 se detiene
  sin sorpresas de costo.

### 3.4 Estados de un hallazgo

| Estado | Significado |
|---|---|
| `preliminary` | Detectado por M4, todavía no pasó por M5. |
| `confirmed` | M5 trazó un camino de input controlable → sink sin sanitización. |
| `conditional` | Existe el camino, pero con una condición/mitigación que el atacante podría sortear (ej. una denylist débil). |
| `false_positive` | El LLM determinó que no es explotable. |
| `needs_review` | M5 lo evaluó pero **no concluyó** (veredicto ambiguo, o se cortó por error/presupuesto). Tiene `review_reason`; se re-evalúa con `findings recheck`. |

### 3.5 Dónde quedan los resultados

Todo dentro de `.hexflaw/` en la carpeta del proyecto:

```
.hexflaw/
├── chunks.json              # ingestión (M1)
├── code_graph.json          # call graph (M3) + sidecar de integridad
├── findings.json            # hallazgos del último run (copia "latest")
├── runs/<run-id>/           # historial: cada analyze archivado, no se sobrescribe
├── cache/
│   ├── analysis_cache.json  # findings por hash de chunk
│   └── embedding_cache.json # vectores por hash de chunk
├── findings/F00X_*.json     # root cause por hallazgo (M6a)
├── reports/                 # ejecutivo + técnico + consolidado (md/pdf)
└── poc/F00X_*/              # poc.py, README, requirements, expected_output
```

---

## 4. Cómo funciona — en profundidad

Esta sección explica el *qué*, el *cómo* y, sobre todo, el *por qué* de cada decisión.

### 4.1 Embeddings — convertir código en geometría

Un **embedding** es un vector (una lista de números) que representa el "significado" de
un fragmento de código. La idea: código semánticamente parecido produce vectores
cercanos en el espacio. La cercanía se mide con **similitud coseno** (el coseno del
ángulo entre dos vectores: 1 = idénticos en dirección, 0 = no relacionados).

**Para qué los usamos.** Permiten buscar código por *significado* en vez de por texto
exacto. Si querés "funciones que ejecutan comandos del sistema sin sanitizar", no podés
hacer un grep — esa frase no aparece en el código. Pero sí podés embeber esa frase y
buscar los chunks cuyo vector esté cerca. Esto es la base de:

1. El **scoping al target** en M4 (§4.4): rankear todos los chunks por cercanía a la
   funcionalidad que pediste auditar.
2. El **filtrado semántico** que reduce cuánto código llega al LLM (caro).

**Qué modelo usamos y por qué.** El backend por defecto es `local-cpu` con un modelo
de *code search* nativo de sentence-transformers, entrenado sobre el dataset
CodeSearchNet. Lo elegimos por tres razones concretas:

- **Entrenado para código, no para texto natural** → entiende sintaxis y semántica de
  programación, no solo lenguaje humano.
- **Corre en CPU local** → respeta el principio local-first: el código no sale de la
  máquina para vectorizarse.
- **No requiere `trust_remote_code`** → importante en una herramienta de seguridad: no
  ejecutamos código remoto arbitrario de un repositorio de modelos para analizar código
  potencialmente malicioso.

El modelo es **configurable** (`config local_embedding_model`); no está hardcodeado,
porque distintos hardwares y casos justifican distintos backends.

**Backends intercambiables.** Detrás de una interfaz común (`embed`, `embed_batch`):

| Backend | Modo | Privacidad |
|---|---|---|
| `local-cpu` | offline, CPU | el código nunca sale de la máquina (default) |
| `ollama` | offline, GPU local | el código nunca sale de la máquina |
| `voyage` / `openai` | API externa | ⚠️ envía el código al proveedor para vectorizarlo |

Si no hay `sentence-transformers` instalado, `local-cpu` cae a un **embedding
determinístico por hashing de tokens** (sin dependencias pesadas): de menor calidad,
pero permite que la herramienta corra offline y reproducible. La calidad neuronal se
activa instalando el extra `[embeddings]`.

**Caché de embeddings.** Vectorizar miles de chunks en CPU es caro (decenas de segundos
a minutos). Como el mismo chunk produce siempre el mismo vector, cacheamos por **hash
del contenido** en `embedding_cache.json`. La primera corrida paga el costo; las
siguientes leen de disco (medido: ~115 s en frío → ~0.01 s en caliente sobre un
codebase grande). El caché se invalida solo si cambia el código o el modelo.

### 4.2 M0 — System Profiling: por qué recomendamos un backend

Distinto hardware justifica distinto backend de embeddings. `setup` decide así:

```
GPU disponible + Ollama  → ollama (rápido, local)
RAM ≥ 16GB, sin GPU      → local-cpu (CPU alcanza, sin dependencia externa)
RAM < 8GB                → voyage/openai (no hay recursos para inferencia local)
Sin internet             → backend local forzado
```

La lógica prioriza **local-first**: solo recomienda un backend por API cuando el hardware
no da para inferencia local. El perfil se guarda con un hash de integridad para detectar
manipulación externa.

### 4.3 M1 — Ingestion: chunking por AST y seguridad

**Chunking semántico.** No mandamos archivos enteros al análisis: los partimos en
**chunks**, donde una función o clase = un chunk. ¿Por qué? Porque la unidad natural de
razonamiento sobre una vulnerabilidad es la función, y porque chunks pequeños:

- reducen la superficie de prompt injection desde el código analizado,
- permiten cachear y filtrar a granularidad fina,
- dan ubicaciones precisas (archivo + rango de líneas) a cada hallazgo.

El chunking usa **tree-sitter** (parser AST universal) cuando la grammar está disponible:
recorre el árbol y extrae nodos de definición (funciones, métodos, clases). Si tree-sitter
no está instalado o la grammar falla, cae a un **fallback por regex** por lenguaje
(Python, C/C++, Go, JS/TS). Último recurso: el archivo entero como un solo chunk (modo
`llm-only`, usado p.ej. en Solidity cuando la grammar del pack no es compatible).

**Detección de lenguaje.** Primero por extensión; si no resuelve, por **shebang**
(`#!/usr/bin/env python3`, `node`, `php`, `ruby`), leyendo solo la primera línea. Esto
cubre scripts sin extensión (CGIs, hooks) habituales en firmware.

**Fuentes de ingestión.** `ingest`/`run` aceptan cuatro tipos, normalizados a un
directorio local seguro antes de caminarlo:

- **directorio** — se camina tal cual.
- **`.zip`** — se extrae a un sandbox temporal (`700`) con guards anti zip-slip y
  rechazo de symlinks embebidos.
- **URL git** (`git@…`, `…​.git`, GitHub/GitLab/Bitbucket/Codeberg) — `git clone`
  **shallow** con hooks deshabilitados (`core.hooksPath=/dev/null`, `GIT_CONFIG_NOSYSTEM`,
  sin prompts) para que un repo malicioso no ejecute código al clonarse.
- **URL http(s)** — descarga con timeout y tope de tamaño; si es un zip, se extrae con
  los mismos guards.

El sandbox temporal se elimina al terminar.

**M1 es el módulo de mayor riesgo** — el código que te pasan para analizar *es* el vector
de ataque. Guards aplicados:

- **Symlinks prohibidos** (`os.lstat`): un symlink a `/etc/passwd` o a tus claves SSH
  no se sigue ni se lee (también dentro de zips).
- **Anti zip-slip / path traversal**: cada path resuelto debe quedar dentro de la raíz.
- **Git hooks deshabilitados** al clonar: ningún `post-checkout` malicioso corre.
- **Límites de tamaño** por archivo y por proyecto, y tope de descarga por URL (anti-DoS).
- **Binarios disfrazados** (un `.c` que en realidad es un ELF): se ignoran, nunca se
  ejecutan. *HexFlaw jamás ejecuta el código analizado* — inamovible por diseño.
- **Sanitización de nombres**: rechazo de null bytes y caracteres de control.

**Re-ingest incremental** (`--incremental`): compara hashes contra la ingestión previa y
**reutiliza los chunks de archivos sin cambios**, re-procesando solo lo modificado.

### 4.4 M2 — Target Definition: dirigir el análisis

El "target" define **qué** analizar. Dos modos:

- **Directed** (`--target "git grep con keywords del usuario"`): vos describís la
  funcionalidad. HexFlaw **acota el análisis a esa funcionalidad** rankeando todos los
  chunks candidatos por similitud semántica a tu descripción (embeddings, §4.1) y se
  queda con los más cercanos. Esto es lo que hace que `--target` realmente *enfoque* el
  análisis en vez de barrer todo el codebase.
- **Discovery** (sin `--target`): el LLM analiza el inventario de funciones y **propone**
  la superficie de ataque más riesgosa.

**¿Por qué ranking y no umbral?** Un umbral absoluto de similitud ("quedate con todo lo
que supere 0.4") es frágil: el valor correcto depende del modelo de embeddings y de cómo
esté redactado el target. Un **ranking top-N** (quedate con los N más cercanos) es robusto
entre modelos y nunca deja el análisis vacío.

### 4.5 M3 — Code Graph: el artefacto más crítico

El **code graph** es un modelo del programa como grafo dirigido:

- **Nodos** = funciones / métodos / clases.
- **Aristas `calls`** = quién llama a quién.
- **Entry points** = nodos que reciben input controlable (matchean patrones tipo
  `main`, handlers HTTP, lectura de `argv`/`recv`).
- **Sinks** = nodos que contienen operaciones peligrosas (`system`, `exec`, `strcpy`,
  queries SQL, escritura de archivos…), cada uno con su tipo (`command_execution`,
  `memory_write`, …).

**Por qué lo construimos.** Detectar un sink no alcanza. La pregunta de seguridad es:
*¿puede un atacante hacer que sus datos lleguen a ese sink?* Eso es un problema de
**alcanzabilidad en un grafo**: ¿existe un camino desde un entry point hasta el sink? El
code graph es lo que permite responder esa pregunta (en M5), en vez de adivinar.

**Cómo se construye.** A partir de los chunks de M1, una pasada heurística: un nodo por
chunk; una arista A→B si el nombre de B aparece invocado (`B(`) dentro del cuerpo de A.
La detección de aristas extrae los call-sites de cada chunk **una sola vez** y los cruza
contra el conjunto de funciones conocidas — **O(call-sites)**, no O(chunks × funciones).
Esto importa: el enfoque ingenuo es cuadrático y se cuelga en codebases grandes (decenas
de miles de funciones). Medido: ~0.7 s para construir el grafo de ~15.000 nodos / ~61.000
aristas.

**Caché con integridad.** El grafo se persiste con un hash SHA-256. Si el código no
cambió, M3 no se re-ejecuta: se carga de disco. Si el artefacto fue manipulado
externamente (el hash no coincide), se regenera. Es el artefacto más crítico del pipeline,
así que su integridad se verifica explícitamente.

### 4.6 M4 — Static Analysis: gastar tokens con cuidado

M4 es el **mayor consumidor de tokens** del pipeline: acá es donde el LLM mira el código.
Por eso, antes de gastar una sola llamada, aplicamos filtros baratos en cascada:

1. **Pre-filtrado por keyword (costo cero).** Si el perfil de vulns incluye
   `command_injection`, solo pasan chunks que contengan algún sink relevante
   (`system`, `exec`, `subprocess`, `shell`, …). Código inerte se descarta sin LLM. Es de
   alto *recall*: un chunk con el keyword pasa; mejor de más que de menos.

2. **Ranking semántico por embeddings.** De los supervivientes, se rankean por cercanía
   al target (§4.4) y se conservan los top-N (`scope_max_chunks`, default 200). Con
   `--path`, los chunks apuntados reciben un bonus y *saltan* el filtro de keyword (la
   intención explícita del usuario manda sobre la heurística — un wrapper propio del
   proyecto, ej. `gitcmd.NewCommand`, no es un sink estándar y el keyword no lo conoce).

> **Decisión de diseño — sin umbral en el filtro semántico.** Una versión previa aplicaba
> *además* un filtro por umbral de similitud sobre cada vuln. En la práctica descartaba
> sinks reales que el keyword ya había identificado (medido: cortaba de 200 a 4 chunks,
> ocultando 10 de 12 sinks `shell=True` legítimos). En SAST eso es lo peor: **falsos
> negativos**. Lo eliminamos. El ranking top-N ya hace el trabajo de acotar sin perder
> recall. La regla: los filtros previos al LLM **nunca** deben descartar un sink que el
> keyword identificó.

3. **Deduplicación.** Antes de gastar tokens se eliminan chunks repetidos: exacta por
   hash (gratis) y **near-duplicados por similitud coseno > 0.95** (cuando hay
   embeddings). Nunca se analiza el mismo código dos veces. Los chunks apuntados con
   `--path` nunca se descartan, y lo eliminado se loguea (sin truncación silenciosa).

4. **Batching.** En vez de una llamada por función, se agrupan varias funciones
   relacionadas por llamada hasta llenar el contexto. ~1000 funciones / 10 por batch = 100
   llamadas en vez de 1000.

5. **Caché por hash de chunk.** Si un chunk ya fue analizado (mismo hash + mismo modelo +
   mismo perfil de vulns), se reutiliza el resultado sin llamar al LLM. Clave en
   re-análisis del mismo codebase con distinto target.

El LLM recibe el código entre delimitadores `<CODE></CODE>` con instrucción explícita de
tratarlo como **datos, nunca instrucciones** (defensa contra prompt injection desde el
código, §4.10). Además, **antes de salir a la API** el código pasa por *secret scanning*
que redacta credenciales hardcodeadas (§4.10) — todas las rutas que mandan código al LLM
(M2/M4/M5/M6a/M6c) comparten ese único punto de salida. Devuelve hallazgos preliminares
en JSON.

### 4.7 Estrategias de optimización de tokens (resumen)

| Estrategia | Idea | Ahorro |
|---|---|---|
| Pre-filtrado keyword | descartar código sin sinks, costo cero | ~60% de chunks |
| Ranking semántico | mandar solo los N más relevantes al target | acota a top-N |
| Deduplicación | no analizar código repetido/near-dup (coseno > 0.95) | quita duplicados |
| Batching | varias funciones por llamada | ~85% de llamadas |
| Caché por chunk | no re-analizar código sin cambios | 50–90% en re-análisis |
| Caché de embeddings | no re-vectorizar chunks sin cambios | ~115 s → 0.01 s |
| Prompt caching | system prompt idéntico → tarifa reducida del proveedor | ~90% del system prompt |
| Modelo por tarea | el modelo más barato que alcanza para cada paso | 40–60% del costo |
| Budget tracker | tope duro de tokens por análisis | sin sorpresas |
| Rate limiting | espaciar llamadas para no exceder el límite por minuto | evita errores 429 |

**Selección de modelo por tarea.** No todas las tareas necesitan el modelo más caro. Se
usa una política por *tier*:

- **Económico** para decisiones binarias/repetitivas (screening, patrones simples,
  reporte ejecutivo tipo template).
- **Intermedio** para síntesis estructurada con contexto suficiente (target directed,
  reporte técnico, root cause de severidad media).
- **Avanzado** para lo cognitivamente demandante: **taint tracing** (razonamiento
  multi-paso sobre el grafo), discovery (inferencia arquitectural), root cause de
  Critical/High, PoC de explotación compleja. Acá un error del modelo significa un falso
  negativo, así que el razonamiento profundo se justifica.

El modo (`thorough`/`balanced`/`economy`) ajusta esta tabla: `economy` desactiva el tier
avanzado; `thorough` lo habilita donde aporta.

**Rate limiting y budget.** Las llamadas se espacian con una ventana deslizante por modelo
para no exceder el límite de tokens-por-minuto del tier de la cuenta (evita errores 429 y,
peor, batches descartados silenciosamente). Un budget configurable corta el análisis al
alcanzar el tope de tokens.

**Backends de LLM intercambiables** (`config llm_backend` / `analyze --llm-backend`), todos
detrás de la misma interfaz, con budget/rate-limiting/auditoría comunes:

- **`api`** (default) — Anthropic API.
- **`openai`** — API de OpenAI (mapea los tiers haiku/sonnet/opus a modelos OpenAI).
- **`agent`** — cola de archivos: HexFlaw parkea el prompt en disco y un **agente externo**
  (Claude Code, Codex, Cursor o un script propio) lo responde, sin gastar créditos de
  ninguna API (ver §4.7.1).

#### 4.7.1 Modo `agent` — un agente externo en el loop

El backend `agent` corre el pipeline **sin consumir créditos de ninguna API**: HexFlaw hace
la parte determinista (ingest, embeddings **locales**, code graph) a costo cero, y delega
cada llamada LLM (M2/M4/M5/M6) a un agente externo mediante una **cola de archivos JSON** en
disco (default `~/.hexflaw/agent_queue/`, configurable con `agent_queue_dir`). No hay red ni
servidor: todo es leer/escribir archivos.

**Cómo funciona.** Cuando el pipeline necesita el LLM, escribe un request y **se bloquea**
sondeando hasta que aparece la respuesta (timeout `agent_poll_timeout`, default 1800 s):

```
HexFlaw (analyze --llm-backend agent)          Agente externo (Claude Code / Codex / vos)
   necesita una llamada LLM                              │
   └─ escribe  req-<id>.json  ───▶  ~/.hexflaw/agent_queue/  ───▶  hexflaw agent pending
        (BLOQUEA, sondea cada 1s)                                  hexflaw agent show <id>
                                                                   …razona el prompt…
   lee text, sigue el pipeline   ◀── res-<id>.json  ◀──────────    hexflaw agent answer <id>
   archiva req+res en  done/
```

- **request** (`req-<id>.json`): `{id, label, model, max_tokens, system, prompt, created_at}`.
- **respuesta** (`res-<id>.json`): `{text, input_tokens?, output_tokens?}`.

> **Clave:** el `text` de la respuesta debe ser **exactamente el JSON que el módulo espera
> parsear** — el mismo que devolvería la API real (ej. M4 espera `{"findings":[…]}`, M5
> espera `{"status":…,"severity":…,"notes":[…]}`). El `system`+`prompt` del request ya traen
> esas instrucciones; el agente solo las sigue y devuelve ese JSON.

**Conducir la cola** (`hexflaw agent`): `status` (estado de la cola), `pending [--json]`
(requests en espera), `show <id> [--json]` (system+prompt verbatim) y
`answer <id> --text|--file|STDIN` (deja la respuesta).

**Uso interactivo** (cualquier agente de chat, o a mano):

```bash
# Terminal 1 — arranca y se bloquea esperando al agente:
hexflaw analyze --llm-backend agent --target "ping functionality" --mode economy

# Terminal 2 — el agente conduce la cola:
hexflaw agent pending --json                       # IDs y tareas pendientes
hexflaw agent show <id>                             # system + prompt verbatim
hexflaw agent answer <id> --text '{"findings":[…]}' # el JSON que el módulo espera
```

**Uso scripted** — el repo incluye **`scripts/agent-bridge.sh`**, un puente que automatiza
el loop (sondea la cola, pasa cada request a tu agente y deja la respuesta):

```bash
scripts/agent-bridge.sh --agent claude              # Claude Code (claude -p)
scripts/agent-bridge.sh --agent codex               # Codex CLI
scripts/agent-bridge.sh --agent custom --cmd 'mi-cli --flag'   # comando propio
scripts/agent-bridge.sh --agent claude --once       # procesa lo pendiente y sale
```

El agente recibe el `system` (como system prompt) y el `prompt` (por STDIN), y debe imprimir
por STDOUT el JSON que el módulo espera. En modo `custom`, tu comando recibe el `system` en
`$HEXFLAW_SYSTEM` y el `prompt` por STDIN. Requiere `jq`.

**Integración con Claude Code** (`hexflaw claude-install`) — el modo más cómodo si trabajás
dentro de Claude Code: instala un slash command y el propio Claude Code conduce la cola con su
razonamiento, así el costo corre por tu suscripción y no por la API.

```bash
# En la terminal, dentro del repo a auditar:
hexflaw claude-install        # crea .claude/commands/hexflaw.md  (--global para ~/.claude)
hexflaw ingest ./codigo       # dejá el repo ingestado

# En Claude Code, en ese mismo repo:
/hexflaw file upload handling   # corre analyze en modo agent y Claude Code responde la cola
```

**A tener en cuenta:** 1 llamada LLM = 1 request = 1 round-trip; M5 dispara ~1 por hallazgo,
así que conviene acotar con `--target` + `--mode economy`. Los **embeddings deben ser
`local-cpu`** para que sea de verdad cero tokens. Si el `text` no respeta el formato
esperado, el módulo lo trata como parseo fallido.

### 4.8 M5 — Taint Tracing: de "sink" a "vulnerabilidad"

Acá está el corazón de por qué HexFlaw no es un matcher de patrones. Por cada hallazgo
preliminar de M4:

1. **Localiza el sink** en el code graph.
2. **Busca un camino** desde un entry point hasta ese sink, con **BFS multi-source** sobre
   el grafo: O(V+E), encuentra el camino más corto (el más directo). Se usa BFS y no
   enumeración de todos los caminos porque enumerar *explota exponencialmente* en grafos
   reales (medido en la versión ingenua: >15 s por sink, hasta colgarse; con BFS: ~0.9 ms
   por sink). La detección de ciclos es implícita en el `visited` del BFS.
3. **Confirma con el LLM**: le da el camino (o, si el grafo heurístico no encontró uno, el
   código de la propia función) y le pide clasificar.

> **Decisión de diseño — no auto-descartar por grafo incompleto.** El call graph es
> heurístico (no resuelve dispatch dinámico ni llamadas cross-file complejas). Una versión
> previa marcaba `false_positive` cuando no encontraba camino — pero "sin camino en
> *nuestro* grafo" no es lo mismo que "no explotable", y descartaba vulns reales. Ahora,
> si no hay camino, **igual se consulta al LLM** con el código de la función (forward
> taint local). El veredicto lo decide el análisis del código, no una limitación del grafo.

El veredicto del LLM se mapea a `confirmed` / `conditional` / `false_positive`. Si el LLM
responde algo **inconcluso** (o la llamada falla por error/presupuesto), el hallazgo queda
en **`needs_review`** con un `review_reason` explícito — distinto de `preliminary`, que
significa "todavía no evaluado". Cualquier `needs_review` se re-evalúa puntualmente con
`findings recheck <ID>` (re-corre M5 solo sobre ese hallazgo).

El estado `conditional` es importante: captura el caso real de "hay una mitigación pero es
débil/evadible" (ej. una denylist de comandos que no cubre todos los casos). Ni confirmado
ni descartado: condicionalmente explotable.

### 4.9 M6 — Documentación: root cause, reportes y PoC

- **M6a Root Cause**: por cada confirmado, el LLM genera causa raíz (no el síntoma, el
  *por qué* existe), archivos/líneas afectadas, blast radius, **CVSS v3.1** (vector +
  score) y remediación con código corregido. Si el LLM falla, hay un fallback
  determinístico con la info ya disponible.
- **M6b Reportes**: ejecutivo (lenguaje de negocio, sin código) + técnico (causa raíz,
  snippet, taint path, CVSS, remediación) + consolidado. Formatos: **Markdown**,
  **PDF** (render offline, sin recursos externos), **JSON** (un export consolidado para
  Jira/Defect Dojo/CI) y **SARIF 2.1.0** (GitHub Code Scanning / SonarQube: una rule por
  tipo de vuln, `security-severity` = score CVSS). Todo contenido del código analizado se
  **escapa** antes de insertarse, y los snippets pasan por **secret scanning** (redacta
  API keys, tokens, claves privadas) antes de quedar en cualquier reporte/export.
- **M6c PoC**: por cada confirmado, un PoC ejecutable **adaptado al tipo de objetivo** —
  generado por el LLM (binario CLI → `subprocess` al binario; servicio de red → socket/
  HTTP; web → request). Barreras inviolables: **payloads de demostración no destructivos**
  (`id`, `whoami`, `sleep`), **placeholders** en vez de IPs/credenciales reales, y un
  scanner que rechaza output destructivo (`rm -rf`, fork bombs, reverse shells, IPs
  hardcodeadas) cayendo al template seguro. **HexFlaw nunca ejecuta el PoC** — se genera
  como archivo estático para que vos lo revises.

M6b y M6c corren **en paralelo** una vez que M6a termina.

### 4.10 Seguridad por diseño (transversal)

HexFlaw analiza código potencialmente malicioso con tus permisos. El threat model trata
ese código como hostil:

- **Prompt injection desde el código**: todo lo que va al LLM se delimita en
  `<CODE></CODE>` con instrucción de tratarlo como datos. Comentarios tipo
  "IGNORA INSTRUCCIONES PREVIAS" dentro del código no afectan el análisis.
- **Nunca ejecutar el código analizado** (M1/M3/M4) ni el PoC generado (M6c). Al clonar
  repos git, los **hooks se deshabilitan** para que el repo no ejecute código.
- **Permisos estrictos** (`600`/`700`) en todos los artefactos; las **API keys se guardan
  en el keyring del SO** (con el extra `[secrets]`), nunca en disco plano — el fallback a
  `config.json` (`600`) solo ocurre sin keyring y con advertencia explícita.
- **Builtins de lenguaje inmutables**: `setup` los copia a `~/.hexflaw/languages/builtin/`
  como solo-lectura (`444`), inspeccionables sin poder corromperlos.
- **Validación de schema** en todo JSON leído de disco (definiciones de lenguaje, code
  graph, config), con `additionalProperties: false` y límites de longitud.
- **Secret scanning antes de enviar código a la API** del LLM **y** antes de escribir
  cualquier snippet a un reporte/export — la red de seguridad cubre todo el pipeline en un
  único punto de salida.
- **Sanitización de logs**: nada de caracteres de control / inyección de líneas desde el
  código analizado.
- **Output del LLM tratado con escepticismo**: todo reporte incluye el disclaimer de que
  fue generado por IA y requiere validación manual; el PoC nunca se presenta como garantía
  de explotabilidad.

---

## 5. Arquitectura (resumen)

```
CLI (presentación)  →  Core Engine (orquestador)  →  Services  →  Infrastructure
   delgada, rich        agnóstico a interfaz         LLM, embeddings,  SQLite + JSON,
   sin lógica           y a backends                 graph, report,    caché de
                                                      language          embeddings, tree-sitter, FS
```

La dependencia va en una sola dirección: la CLI llama al Core; el Core nunca importa la
CLI. Los módulos del pipeline son *stateless* (input → output) y los backends se inyectan
desde el orquestador, nunca se instancian dentro de un módulo. Por eso agregar una Web API
no requiere tocar el motor.

---

## 6. Desarrollo

```bash
pip install -e ".[dev]"
pytest                  # suite de tests
ruff check hexflaw      # linting
```

---

_HexFlaw — SecureHex. El análisis asistido por IA requiere validación manual antes de
reportar a un cliente._
