#!/usr/bin/env bash
#
# agent-bridge.sh — Puente para el backend LLM "agent" de HexFlaw.
#
# El backend `agent` corre el pipeline SIN gastar créditos de ninguna API: HexFlaw
# parkea cada llamada LLM como un request JSON en una cola en disco y se bloquea
# esperando la respuesta. Este script automatiza el otro lado de la cola: sondea
# los requests pendientes, se los pasa a un agente externo (Claude Code, Codex o un
# comando propio) y deja la respuesta para que el pipeline continúe.
#
# Uso típico (en dos terminales):
#
#   # Terminal 1 — arranca el análisis con el backend agent (se bloquea):
#   hexflaw analyze --llm-backend agent --target "ping functionality" --mode economy
#
#   # Terminal 2 — el puente conduce la cola:
#   scripts/agent-bridge.sh --agent claude        # usa Claude Code (claude -p)
#   scripts/agent-bridge.sh --agent codex         # usa Codex CLI
#   scripts/agent-bridge.sh --agent custom --cmd 'mi-cli --flag'
#   scripts/agent-bridge.sh --agent claude --once # procesa lo pendiente y sale
#
# CONTRATO con el agente: recibe el SYSTEM (como system prompt, según el preset) y
# el PROMPT por STDIN, y debe imprimir por STDOUT el texto que devolvería el modelo
# — es decir, EXACTAMENTE el JSON que el módulo espera parsear (ej. M4 espera
# {"findings":[...]}, M5 {"status":...,"severity":...,"notes":[...]}). Esas
# instrucciones ya vienen dentro del PROMPT del request; el agente solo las sigue.
#
# Requisitos: hexflaw en PATH, jq, y el CLI del agente elegido. Para que sea de
# verdad cero tokens de API, el backend de embeddings debe ser local (local-cpu).
#
set -euo pipefail

AGENT="claude"
CUSTOM_CMD=""
ONCE=0
INTERVAL="${HEXFLAW_BRIDGE_INTERVAL:-2}"

usage() {
  sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)    AGENT="${2:?--agent requiere un valor}"; shift 2 ;;
    --cmd)      CUSTOM_CMD="${2:?--cmd requiere un valor}"; shift 2 ;;
    --once)     ONCE=1; shift ;;
    --interval) INTERVAL="${2:?--interval requiere un valor}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; usage; exit 1 ;;
  esac
done

command -v hexflaw >/dev/null 2>&1 || { echo "[bridge] error: 'hexflaw' no está en PATH." >&2; exit 1; }
command -v jq      >/dev/null 2>&1 || { echo "[bridge] error: se requiere 'jq'." >&2; exit 1; }

# run_agent <system> <prompt>  → imprime por STDOUT la respuesta del modelo.
run_agent() {
  local system="$1" prompt="$2"
  case "$AGENT" in
    claude)
      command -v claude >/dev/null 2>&1 || { echo "[bridge] 'claude' no encontrado." >&2; return 1; }
      printf '%s' "$prompt" | claude -p --output-format text \
        --append-system-prompt "$system" --max-turns 1 --allowedTools ""
      ;;
    codex)
      command -v codex >/dev/null 2>&1 || { echo "[bridge] 'codex' no encontrado." >&2; return 1; }
      # Codex no separa system/prompt: los concatenamos. Ajustá la invocación a tu
      # versión de la CLI si hiciera falta (p.ej. 'codex exec -' o '--full-auto').
      printf '%s\n\n%s' "$system" "$prompt" | codex exec -
      ;;
    custom)
      [[ -n "$CUSTOM_CMD" ]] || { echo "[bridge] --agent custom requiere --cmd '<comando>'." >&2; return 1; }
      # El comando recibe el SYSTEM en \$HEXFLAW_SYSTEM y el PROMPT por STDIN.
      HEXFLAW_SYSTEM="$system" bash -c "$CUSTOM_CMD" <<<"$prompt"
      ;;
    *)
      echo "[bridge] agente desconocido: '$AGENT' (usá claude|codex|custom)." >&2
      return 1
      ;;
  esac
}

# process_one <request-id>
process_one() {
  local id="$1" req system prompt resp tmp
  req="$(hexflaw agent show "$id" --json)" || { echo "[bridge] no pude leer $id." >&2; return 0; }
  system="$(jq -r '.system // ""' <<<"$req")"
  prompt="$(jq -r '.prompt // ""' <<<"$req")"
  local label; label="$(jq -r '.label // ""' <<<"$req")"
  echo "[bridge] $id ($label) → $AGENT ..." >&2

  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN
  if resp="$(run_agent "$system" "$prompt")"; then
    printf '%s' "$resp" >"$tmp"
    hexflaw agent answer "$id" --file "$tmp" >&2
  else
    echo "[bridge] el agente falló en $id; queda pendiente para reintento." >&2
  fi
}

echo "[bridge] agente=$AGENT  intervalo=${INTERVAL}s  once=$ONCE" >&2
while true; do
  ids="$(hexflaw agent pending --json 2>/dev/null | jq -r '.[].id' || true)"
  if [[ -n "${ids//[$'\n\t ']/}" ]]; then
    while IFS= read -r id; do
      [[ -n "$id" ]] && process_one "$id"
    done <<<"$ids"
  fi
  [[ "$ONCE" -eq 1 ]] && break
  sleep "$INTERVAL"
done
