# CHANGELOG

Las versiones y las entradas de abajo las genera
[python-semantic-release](https://python-semantic-release.readthedocs.io) a partir
de los mensajes de commit, siguiendo [Conventional Commits](https://www.conventionalcommits.org/):

| Prefijo del commit | Efecto |
|---|---|
| `fix:` | sube el patch (1.0.0 → 1.0.1) |
| `feat:` | sube el minor (1.0.0 → 1.1.0) |
| `BREAKING CHANGE:` en el cuerpo | sube el major (1.0.0 → 2.0.0) |
| `chore:`, `docs:`, `test:`, `style:`, `refactor:` | no publica nada |

Desde 1.0.0 rige semver pleno: los contratos públicos —los modelos de
`core/models.py`, el formato de `code_graph.json` y la superficie de la CLI— son
un compromiso. Romperlos exige un `BREAKING CHANGE:` explícito en el commit, que
lleva la versión a 2.0.0.

**No edites este archivo a mano debajo del marcador**: la próxima release lo
sobrescribe.

<!-- version list -->

## v1.4.1 (2026-07-30)

### Bug Fixes

- **m4**: Cover Java XSS/trust-boundary idioms and scale the rescue budget
  ([`557de66`](https://github.com/Secure-Hex/HexFlaw/commit/557de66fba4dde642306bc68c65a3ab205c7756a))

### Documentation

- Document the four prefilter layers in the README
  ([`53cc2a8`](https://github.com/Secure-Hex/HexFlaw/commit/53cc2a824feef4e450bb84198a4bdac607237ff2))

### Testing

- **benchmarks**: Add a free prefilter-recall harness and measure it
  ([`899dfed`](https://github.com/Secure-Hex/HexFlaw/commit/899dfed65090e467d75c6e2a54e3c4fa1cd23f5a))


## v1.4.0 (2026-07-30)

### Features

- **m4**: Rescue semantically similar chunks as the prefilter's last net
  ([`5c86661`](https://github.com/Secure-Hex/HexFlaw/commit/5c86661d900fa447a26a07ab40ae9d6e4a20285b))


## v1.3.0 (2026-07-30)

### Features

- **m4**: Learn sinks automatically for languages without coverage
  ([`1333534`](https://github.com/Secure-Hex/HexFlaw/commit/13335344e688116c0a28d2ab938b6baa243609d6))


## v1.2.0 (2026-07-30)

### Features

- **m3**: Infer local variable types to resolve call receivers
  ([`d3ebb89`](https://github.com/Secure-Hex/HexFlaw/commit/d3ebb89e592a1af355d302df12a7fef677885cd8))


## v1.1.0 (2026-07-30)

### Features

- **m3**: Qualify call receivers and import the CodeQL sink catalog
  ([`3ba6138`](https://github.com/Secure-Hex/HexFlaw/commit/3ba61380a1fd3a6092769578b1be74e07228413b))

- **sinks**: Let users import Semgrep rules locally without distributing them
  ([`b562887`](https://github.com/Secure-Hex/HexFlaw/commit/b5628878db9d3b9dac3dbe06de920f51e24d6411))


## v1.0.2 (2026-07-30)

### Bug Fixes

- **m4**: Rescue chunks that reach a sink through the call graph
  ([`9a43ce5`](https://github.com/Secure-Hex/HexFlaw/commit/9a43ce5327416d5a18e578cd6309ee7b026e1c06))

### Documentation

- Update README for the AST code graph and PyPI install
  ([`6f5b000`](https://github.com/Secure-Hex/HexFlaw/commit/6f5b000adb792acfe5073c2c3dbaa3f1b5b2c078))


## v1.0.1 (2026-07-30)

### Bug Fixes

- **chunking**: Type the tree-sitter parser as Any across both bindings
  ([`8935d6d`](https://github.com/Secure-Hex/HexFlaw/commit/8935d6d1b852cb44bc6a24303129184b8826026f))

### Continuous Integration

- Add a bootstrap path to publish the current version
  ([`630ad16`](https://github.com/Secure-Hex/HexFlaw/commit/630ad16819ab3e30986ac422617131896abab9e4))

- Pin the ruff rule set instead of inheriting version defaults
  ([`00e44e3`](https://github.com/Secure-Hex/HexFlaw/commit/00e44e3f524bf9e8bdde5b4aa572a97d250c5426))


## v1.0.0 (2026-07-30)

Primer release completo. Punto de adopción de versionado y changelog
automáticos: las entradas siguientes se generan solas.

### Features

- **m3**: el code graph se construye desde el AST y no desde un regex. Para
  Python con el `ast` de la stdlib (resuelve alias de import, `self.foo()`,
  `Clase.metodo()` y llamadas calificadas); para el resto de lenguajes con
  tree-sitter cuando la grammar está instalada; y el fallback regex sigue
  disponible cuando no hay AST posible.
- **m3**: aristas `data_flow` y `control_flow` en el artefacto. El data flow es
  intra-procedural con enlace inter-procedural por argumentos y valor de retorno,
  sensible a ramas, con seguimiento de campos de instancia entre métodos y
  reconocimiento de sanitizadores. El control flow anota qué condición guarda
  cada llamada. **No** es un CFG de bloques básicos ni un análisis sound: ver
  CLAUDE.md §6 M3 para el alcance exacto.
- **m5**: prefiere el camino de data flow, que prueba que el dato llega al sink y
  no solo que el sink es alcanzable, y anota cada salto con evidencia del grafo
  antes de que el LLM interprete.
- **cli**: comando `hexflaw graph` para inspeccionar y exportar el code graph en
  árbol, caminos entry point → sink, Graphviz DOT, Mermaid o JSON.
- **languages**: definiciones de Kotlin, Swift, C# y Bash, que la documentación
  prometía como Tier 2 pero no existían. Ahora los 15 lenguajes builtin son reales.
- **analyze**: modo `--exhaustive` (todo el codebase, sin prefiltro ni límite de
  scope, con Opus en todas las tareas) y M5b variant hunting, que caza vecinos de
  los hallazgos confirmados en el espacio de embeddings.

### Bug Fixes

- **m3**: los sinks se comparan por segmentos del nombre resuelto de la llamada y
  no por substring. `exec` ya no matchea `self.execute`, `open(` ya no matchea
  `sp.Popen` y un `import subprocess` a secas ya no vuelve sink al módulo.
- **m3**: el análisis de taint es sensible a ramas. Sanitizar dentro de un `if`
  ya no marca el flujo como sanitizado ignorando el camino del `else` — era un
  falso negativo, que en una herramienta de seguridad es peor que un falso
  positivo.
- **m3**: el adaptador de tree-sitter soporta las dos APIs que circulan bajo el
  mismo nombre de paquete. Sin él, el `TypeError` se lo comía un `except
  Exception` y **todos** los lenguajes caían al fallback regex en silencio.
- **m5**: `build_adjacency` filtra por tipo de arista. Mezclar `data_flow`
  inventaba caminos de llamada inexistentes, porque las de retorno van
  callee→caller.
- **graph**: `GRAPH_SCHEMA_VERSION` invalida los grafos cacheados por versiones
  anteriores. Sin eso, un proyecto ya analizado seguía usando el grafo viejo
  aunque el código no hubiera cambiado, y M5 razonaba peor sin que nada lo
  indicara.
- **m5b**: no corre en modo `--exhaustive`, donde M4 ya analizó el codebase
  entero y cazar variantes solo re-pagaba Opus sobre código ya analizado.

### Documentation

- CLAUDE.md deja de prometer data flow y control flow completos y describe el
  alcance real del análisis, con sus limitaciones explícitas.
- El docstring de M5 decía que sin path el hallazgo se marca `false_positive` sin
  gastar tokens; el código hace lo contrario desde hace tiempo, y por buenas
  razones.
