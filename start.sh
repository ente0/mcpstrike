#!/usr/bin/env bash
# mcpstrike stack launcher
# Starts hexstrike_server, mcpstrike-server, and mcpstrike-client in tandem.
# This file is git-ignored (contains personal IPs/model names).

HEXSTRIKE_PORT=8888
MCP_PORT=8889
OLLAMA_URL="http://localhost:11434"
MODEL="qwen3.5:latest"
MCP_URL="http://localhost:${MCP_PORT}/mcp"
HEXSTRIKE_URL="http://localhost:${HEXSTRIKE_PORT}"

# Session directory — pass an optional first argument to override the default.
if [[ -n "${1:-}" && "${1:-}" != "--tmux" ]]; then
    _sarg="${1/#\~/$HOME}"
    [[ "$_sarg" != /* ]] && _sarg="$HOME/$_sarg"
    SESSIONS_DIR="$_sarg"
    unset _sarg
    export HEXSTRIKE_SESSION_PATH="$SESSIONS_DIR"
else
    SESSIONS_DIR="$HOME/hexstrike_sessions"
fi

echo "============================================================"
echo "  mcpstrike stack"
echo "============================================================"

# ── Terminal helpers (inspired by TheFatRat open_terminal) ────────────────

_has_display() {
    [[ -n "$WAYLAND_DISPLAY" ]] && return 0
    if [[ -n "$DISPLAY" ]]; then
        command -v xdpyinfo &>/dev/null && xdpyinfo &>/dev/null && return 0
        local _d="${DISPLAY#*:}"; _d="${_d%%.*}"
        [[ -e "/tmp/.X11-unix/X${_d}" ]] && return 0
    fi
    return 1
}

_detect_terminal() {
    for term in gnome-terminal konsole qterminal xfce4-terminal lxterminal mate-terminal x-terminal-emulator; do
        command -v "$term" &>/dev/null && { MCP_TERM="$term"; return 0; }
    done
    MCP_TERM=""; return 1
}

# open_terminal TITLE CMD [GEOMETRY]
# Opens CMD in a new terminal window (background).
# GEOMETRY: X11 geometry string "COLSxROWS+X+Y" (e.g. "110x35+0+0")
# Priority: macOS Terminal.app → Linux GUI terminal → background with log
open_terminal() {
    local title="$1" cmd="$2" geo="${3:-}"

    # macOS: Terminal.app via osascript (always available on macOS)
    if [[ "$(uname)" == "Darwin" ]]; then
        local safe="${cmd//\\/\\\\}"
        safe="${safe//\"/\\\"}"
        osascript -e "tell application \"Terminal\" to do script \"$safe\"" 2>/dev/null
        sleep 1; return
    fi

    # Linux with X11/Wayland display
    if _has_display; then
        _detect_terminal
        local geo_flag=()
        [[ -n "$geo" ]] && geo_flag=(--geometry="$geo")
        case "$MCP_TERM" in
            gnome-terminal)
                gnome-terminal --title="$title" "${geo_flag[@]}" -- bash -c "$cmd; bash" 2>/dev/null &
                sleep 2; return ;;
            xfce4-terminal|lxterminal|mate-terminal)
                "$MCP_TERM" --title="$title" "${geo_flag[@]}" -e "bash -c '$cmd; bash'" 2>/dev/null &
                sleep 2; return ;;
            konsole)
                # konsole usa --geometry in pixel (WxH+X+Y), non in caratteri
                konsole --title "$title" -e bash -c "$cmd; bash" 2>/dev/null &
                sleep 2; return ;;
            qterminal)
                qterminal -e bash -c "$cmd; bash" 2>/dev/null &
                sleep 2; return ;;
            x-terminal-emulator)
                x-terminal-emulator -T "$title" "${geo_flag[@]}" -e bash -c "$cmd; bash" 2>/dev/null &
                sleep 2; return ;;
        esac
    fi

    # No GUI terminal available → background with log
    local log="/tmp/mcpstrike_${title// /_}.log"
    bash -c "$cmd" >"$log" 2>&1 &
    echo "  [${title}] PID $! — tail -f $log"
}

# ── Launch ────────────────────────────────────────────────────────────────

_FORCE_TMUX=false
[[ "${1:-}" = "--tmux" || "${2:-}" = "--tmux" ]] && _FORCE_TMUX=true

if ! $_FORCE_TMUX; then
    # Open servers in separate terminal windows; client runs in current terminal
    # geometry: COLSxROWS+X+Y — side by side on a 1920-wide screen
    open_terminal "hexstrike_server"  "hexstrike_server --port ${HEXSTRIKE_PORT}"                "110x35+0+0"
    sleep 1
    open_terminal "mcpstrike-server"  "HEXSTRIKE_BACKEND_URL=${HEXSTRIKE_URL} mcpstrike-server"  "110x35+960+0"
    sleep 2

    mcpstrike-client \
        --ollama-url "$OLLAMA_URL" \
        --model "$MODEL" \
        --mcp-url "$MCP_URL" \
        --sessions-dir "$SESSIONS_DIR"
else
    # --tmux: traditional split-pane layout
    if ! command -v tmux &>/dev/null; then
        echo "  [!] tmux not found. Run without --tmux to use the default terminal."
        exit 1
    fi
    SESSION="mcpstrike"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    tmux new-session -d -s "$SESSION"
    tmux set -g mouse on
    tmux split-window -v -t "${SESSION}:0.0" -p 70
    tmux split-window -h -t "${SESSION}:0.0" -p 50
    tmux send-keys -t "${SESSION}:0.0" "hexstrike_server --port ${HEXSTRIKE_PORT}" Enter
    sleep 1
    tmux send-keys -t "${SESSION}:0.1" "HEXSTRIKE_BACKEND_URL=${HEXSTRIKE_URL} mcpstrike-server" Enter
    sleep 2
    tmux send-keys -t "${SESSION}:0.2" \
        "mcpstrike-client --ollama-url ${OLLAMA_URL} --model ${MODEL} --mcp-url ${MCP_URL} --sessions-dir ${SESSIONS_DIR}" Enter
    tmux select-pane -t "${SESSION}:0.2"
    tmux attach-session -t "$SESSION"
fi
