# CHANGELOG

Las versiones y las entradas de abajo las genera
[python-semantic-release](https://python-semantic-release.readthedocs.io) a partir
de los mensajes de commit, siguiendo [Conventional Commits](https://www.conventionalcommits.org/):

| Prefijo del commit | Efecto |
|---|---|
| `fix:` | sube el patch (0.2.0 → 0.2.1) |
| `feat:` | sube el minor (0.2.0 → 0.3.0) |
| `BREAKING CHANGE:` en el cuerpo | **mientras estemos en 0.x, sube el minor** (`major_on_zero = false`) |
| `chore:`, `docs:`, `test:`, `style:`, `refactor:` | no publica nada |

El salto a 1.0.0 es una decisión de producto: se hace subiendo `version` a mano
una vez y dejando que el automatismo siga desde ahí. A partir de 1.0.0, un
`BREAKING CHANGE` sí sube el major.

**No edites este archivo a mano debajo del marcador**: la próxima release lo
sobrescribe.

<!-- version list -->

## v0.2.0 (2026-07-30)

Primera versión publicada. Punto de adopción de versionado y changelog
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
