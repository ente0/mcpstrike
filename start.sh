#!/usr/bin/env bash
# mcpstrike stack launcher
# Starts hexstrike_server, mcpstrike-server, and mcpstrike-client in tandem.
# This file is git-ignored (contains personal IPs/model names).

HEXSTRIKE_PORT=8888
MCP_PORT=8889
OLLAMA_URL="http://localhost:11434"
MODEL="qwen3.5-uncensored-q8:latest"
MCP_URL="http://localhost:${MCP_PORT}/mcp"
HEXSTRIKE_URL="http://localhost:${HEXSTRIKE_PORT}"

echo "============================================================"
echo "  mcpstrike stack"
echo "============================================================"

# ── Layout ────────────────────────────────────────────────────────────────
#
#  ┌──────────────────────┬──────────────────────┐
#  │   hexstrike_server   │   mcpstrike-server   │  50% | 50%
#  ├──────────────────────┴──────────────────────┤
#  │              mcpstrike-client               │
#  └─────────────────────────────────────────────┘
#
# GUI detection:
#   Linux  → DISPLAY is set
#   macOS  → not SSH (SSH_CONNECTION / SSH_TTY unset) and not inside tmux already
_has_display() {
    [ -n "${DISPLAY:-}" ] ||
    { [ "$(uname)" = "Darwin" ] && [ -z "${SSH_CONNECTION:-}" ] && [ -z "${SSH_TTY:-}" ] && [ -z "${TMUX:-}" ]; }
}

# Priority: xterm (GUI) → tmux (fallback) → background
if _has_display && command -v xterm &>/dev/null; then
    xterm -title "hexstrike_server" \
        -e "hexstrike_server --port ${HEXSTRIKE_PORT}; read" &
    sleep 1

    xterm -title "mcpstrike-server" \
        -e "HEXSTRIKE_BACKEND_URL=${HEXSTRIKE_URL} mcpstrike-server; read" &
    sleep 2

    xterm -title "mcpstrike-client" \
        -e "mcpstrike-client --ollama-url ${OLLAMA_URL} --model ${MODEL} --mcp-url ${MCP_URL} --sessions-dir hexstrike_sessions; read"

elif command -v tmux &>/dev/null; then
    SESSION="mcpstrike"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    tmux new-session -d -s "$SESSION"

    # Split top/bottom: top=60%, bottom=40% (client)
    tmux split-window -v -t "${SESSION}:0.0" -p 40

    # Split top pane horizontally 50/50
    tmux split-window -h -t "${SESSION}:0.0" -p 50

    # Pane numbering (by position, left→right, top→bottom):
    #   0.0 = top-left    (hexstrike_server)
    #   0.1 = top-right   (mcpstrike-server)
    #   0.2 = bottom      (mcpstrike-client)

    tmux send-keys -t "${SESSION}:0.0" \
        "hexstrike_server --port ${HEXSTRIKE_PORT}" Enter
    sleep 1

    tmux send-keys -t "${SESSION}:0.1" \
        "HEXSTRIKE_BACKEND_URL=${HEXSTRIKE_URL} mcpstrike-server" Enter
    sleep 2

    tmux send-keys -t "${SESSION}:0.2" \
        "mcpstrike-client --ollama-url ${OLLAMA_URL} --model ${MODEL} --mcp-url ${MCP_URL} --sessions-dir hexstrike_sessions" Enter

    tmux select-pane -t "${SESSION}:0.2"
    tmux attach-session -t "$SESSION"

else
    # Last resort — first two in background with logs, client in foreground
    echo "xterm/tmux not found, running in background (logs in /tmp/mcpstrike_*.log)"

    hexstrike_server --port "$HEXSTRIKE_PORT" \
        > /tmp/mcpstrike_hexstrike.log 2>&1 &
    echo "hexstrike_server PID $! — tail -f /tmp/mcpstrike_hexstrike.log"
    sleep 1

    HEXSTRIKE_BACKEND_URL="${HEXSTRIKE_URL}" mcpstrike-server \
        > /tmp/mcpstrike_server.log 2>&1 &
    echo "mcpstrike-server PID $! — tail -f /tmp/mcpstrike_server.log"
    sleep 2

    mcpstrike-client \
        --ollama-url "$OLLAMA_URL" \
        --model "$MODEL" \
        --mcp-url "$MCP_URL" \
        --sessions-dir hexstrike_sessions
fi
