# HexFlaw — Benchmarks

Suite de evaluación de HexFlaw contra benchmarks SAST de referencia. Las métricas
son directamente comparables con Semgrep, CodeQL, Bandit, etc.

## OWASP Benchmark v1.2

2.740 testcases Java con etiqueta binaria (vulnerable / no vulnerable) en 11
categorías CWE. Estándar de facto para medir SAST. Fuente:
https://github.com/OWASP-Benchmark/BenchmarkJava

### Recall del prefiltro (gratis, sin LLM)

El techo de recall del pipeline se puede medir **sin gastar un token**: M3 y las 4
capas del prefiltro no usan LLM. Un testcase cuyo chunk vulnerable no sobrevive al
prefiltro es un falso negativo garantizado, por bueno que sea el modelo.

```bash
python benchmarks/owasp/prefilter_recall.py                    # corpus completo
python benchmarks/owasp/prefilter_recall.py --no-semantic      # aísla capas 0-2
python benchmarks/owasp/prefilter_recall.py --max-rescued 25   # el default real
```

**Resultado sobre los 2740 testcases (2026-07-30):**

| Configuración | Recall | Chunks al LLM |
|---|---|---|
| Antes de los arreglos, capas 0-2 | 89,3% | 4466 |
| Antes, + capa 3 con tope fijo de 25 | 89,6% | 4491 |
| Antes, + capa 3 sin tope (techo del método) | 100% | 8810 |
| **Después de los arreglos, capas 0-2** | **100%** | 6610 |

La medición encontró dos defectos, los dos ya corregidos:

1. **El `vuln_profile` de Java no incluía `xss` ni `trust_boundary`**, y la lista de
   keywords de `xss` era toda de idioms JS/PHP (`innerhtml`, `echo`, `|safe`). El XSS
   de servlet (`response.getWriter().format(param)`) no matcheaba nada:

   | Categoría | Recall antes | ¿Estaba en el perfil? |
   |---|---|---|
   | `xss` | 53,3% | **NO** |
   | `trustbound` | 55,4% | **NO** |
   | las otras 9 | 100% | — |

   Es el mismo error que ya se había cometido con Node y que un comentario del código
   documenta. Volvió a pasar con otro lenguaje: **una lista de keywords se degrada en
   silencio cada vez que se agrega un lenguaje sin revisarla.** Agregar los idioms de
   servlet llevó el recall de 89,3% a 100% sin tocar la capa 3. Costo: +48% de chunks
   al LLM (4466 → 6610), que es lo que vale cubrir 2 categorías más.

2. **El tope de la capa 3 era absoluto (25)** y aportaba +0,3 puntos sobre 13.691
   chunks: el rescate funcionaba —llegaba al 100% sin tope— pero el tope lo anulaba.
   Ahora es `max(piso, fracción × chunks ya aceptados)`, con piso 25 y fracción 0,10.
   El sobrecosto máximo pasa a ser predecible y proporcional en vez de una constante
   que queda mal en los dos extremos.

### Layout

```
benchmarks/
├── owasp/                  ← harness (versionado)
│   ├── scorer.py           ← ground truth + mapeo + confusion matrix + métricas (puro)
│   ├── report.py           ← escribe el Excel (openpyxl)
│   ├── run.py              ← CLI: prepare / score
│   └── test_scorer.py      ← tests del scorer (sin LLM)
├── vendor/benchmark/       ← clon del OWASP Benchmark (gitignored)
├── work/<category>/        ← muestras preparadas + proyecto HexFlaw (gitignored)
└── reports/                ← Excel generados (gitignored)
```

### Cómo correr una categoría

El análisis va en el medio porque con backend `agent` es interactivo (hay que
responder la cola de prompts).

```bash
cd benchmarks/owasp

# 1. Preparar la muestra (balanceada vuln/seguro, determinista)
python run.py prepare --category cmdi --n 20

# 2. Analizar con HexFlaw (modo más potente + variant hunting)
cd ../work/cmdi
hexflaw init && hexflaw ingest code
hexflaw analyze --mode thorough --hunt-variants --llm-backend agent
#   ↑ se bloquea en la cola; responder con `hexflaw agent pending|show|answer`

# 3. Puntuar y generar el Excel
cd ../../owasp
python run.py score --category cmdi
#   → benchmarks/reports/owasp_cmdi.xlsx
```

### Scoring

Cada testcase tiene una única categoría CWE y etiqueta binaria. HexFlaw "detecta"
un testcase si reporta una vuln **de esa categoría** en ese archivo:

|              | detectado | no detectado |
|--------------|-----------|--------------|
| real=true    | TP        | FN           |
| real=false   | FP        | TN           |

De ahí: **precisión**, **recall**, **F1**, **FPR** y **Youden's J** (= recall − FPR,
el score oficial del OWASP Benchmark), por categoría y total.

**Qué cuenta como detección:** por defecto, findings con status `confirmed` o
`conditional` (el veredicto positivo final de HexFlaw). `--include-preliminary`
suma también `preliminary`/`needs_review` (mide la recall bruta de M4 antes de que
M5 descarte).

### Categorías (CWE)

`cmdi`(78) `sqli`(89) `xss`(79) `ldapi`(90) `xpathi`(643) `pathtraver`(22)
`trustbound`(501) `securecookie`(614) `weakrand`(330) `hash`(328) `crypto`(327)

> Nota: el `vuln_profile` builtin de Java cubre 5 de las 11 (cmdi, sqli, pathtraver,
> deserialization, ssrf). Para las otras 6 hay que ampliar `java.json` o dejar que
> M2 discovery las proponga — pendiente para la corrida completa.
