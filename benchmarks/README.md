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
| Capas 0-2 | 89,3% | 4466 |
| + capa 3, tope 25 (default de producción) | 89,6% | 4491 |
| + capa 3 sin tope (techo del método) | **100%** | 8810 |

Dos conclusiones incómodas y accionables:

1. **El tope por defecto de la capa 3 (25) aporta +0,3 puntos** en un corpus de este
   tamaño. Es un valor absoluto sobre un corpus de 13.691 chunks: el rescate
   semántico funciona (llega al 100% sin tope) pero el tope lo anula. Debería
   escalar con el tamaño del corpus, no ser una constante.
2. **Los 147 fallos se concentran en dos categorías**, y la causa es de cobertura,
   no del método:

   | Categoría | Recall | ¿En el `vuln_profile` de Java? |
   |---|---|---|
   | `xss` | 53,3% | **NO** |
   | `trustbound` | 55,4% | **NO** |
   | las otras 9 | 100% | — |

   El XSS de servlet Java (`response.getWriter().format(param)`) no matchea ninguna
   keyword: la lista de `xss` es toda de idioms JS/PHP (`innerhtml`, `echo`,
   `|safe`). Y `xss` ni siquiera está en el `vuln_profile` de `java.json`.

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
