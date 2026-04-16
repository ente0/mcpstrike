"""mcpstrike — stack launcher.

Avvia hexstrike_server, mcpstrike-server e mcpstrike-client in un unico
comando, con supporto per il terminale di default del sistema, tmux
(fallback) e background (ultimo ricorso).

Uso rapido:
    mcpstrike                                # default
    mcpstrike --model qwen3:8b
    mcpstrike --ollama-url http://10.0.0.5:11434
    mcpstrike --sessions-dir /opt/sessions
    mcpstrike --tmux                         # forza tmux split-pane
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ── helpers ────────────────────────────────────────────────────────────────

def _resolve_sessions_dir(raw: str) -> str:
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = Path.home() / p
    return str(p)


def _has_display() -> bool:
    """True se X11 o Wayland è disponibile (Linux)."""
    if os.environ.get("WAYLAND_DISPLAY"):
        return True
    display = os.environ.get("DISPLAY", "")
    if not display:
        return False
    if shutil.which("xdpyinfo"):
        result = subprocess.run(["xdpyinfo"], capture_output=True)
        if result.returncode == 0:
            return True
    # fallback: controlla il socket X
    disp_num = display.split(":")[1].split(".")[0] if ":" in display else ""
    if disp_num and Path(f"/tmp/.X11-unix/X{disp_num}").exists():
        return True
    return False


def _detect_terminal() -> str:
    """Trova il primo emulatore di terminale disponibile (Linux)."""
    for term in (
        "gnome-terminal", "konsole", "qterminal",
        "xfce4-terminal", "lxterminal", "mate-terminal",
        "x-terminal-emulator",
    ):
        if shutil.which(term):
            return term
    return ""


def open_terminal(title: str, cmd: str, geometry: str | None = None) -> None:
    """
    Apre CMD in una nuova finestra di terminale (background).
    geometry: X11 geometry string "COLSxROWS+X+Y" (es. "110x35+0+0").
    Priorità: macOS Terminal.app → terminale Linux → log in background
    """
    # macOS: Terminal.app via osascript (sempre disponibile)
    if sys.platform == "darwin":
        safe = cmd.replace("\\", "\\\\").replace('"', '\\"')
        subprocess.run(
            ["osascript", "-e", f'tell application "Terminal" to do script "{safe}"'],
            check=True,
        )
        time.sleep(1)
        return

    # Linux con display grafico
    if _has_display():
        term = _detect_terminal()
        geo = [f"--geometry={geometry}"] if geometry else []

        if term == "gnome-terminal":
            subprocess.Popen(
                ["gnome-terminal", f"--title={title}", *geo, "--", "bash", "-c", f"{cmd}; bash"],
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2); return
        elif term in ("xfce4-terminal", "lxterminal", "mate-terminal"):
            subprocess.Popen(
                [term, f"--title={title}", *geo, "-e", f"bash -c '{cmd}; bash'"],
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2); return
        elif term == "konsole":
            # konsole non supporta geometry in caratteri, solo posizione
            subprocess.Popen(
                ["konsole", "--title", title, "-e", "bash", "-c", f"{cmd}; bash"],
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2); return
        elif term == "qterminal":
            subprocess.Popen(
                ["qterminal", "-e", f"bash -c '{cmd}; bash'"],
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2); return
        elif term == "x-terminal-emulator":
            subprocess.Popen(
                ["x-terminal-emulator", "-T", title, *geo, "-e", "bash", "-c", f"{cmd}; bash"],
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2); return

    # Nessun terminale GUI → log in background
    log = f"/tmp/mcpstrike_{title.replace(' ', '_')}.log"
    with open(log, "w") as fh:
        p = subprocess.Popen(["bash", "-c", cmd], stdout=fh, stderr=fh)
    print(f"  [{title}] PID {p.pid} — tail -f {log}")


# ── tmux layout ────────────────────────────────────────────────────────────

def _launch_tmux(args: argparse.Namespace) -> None:
    hexstrike_url = f"http://localhost:{args.hexstrike_port}"
    mcp_url       = f"http://localhost:{args.mcp_port}/mcp"
    session       = "mcpstrike"

    subprocess.run(["tmux", "kill-session", "-t", session], stderr=subprocess.DEVNULL)
    subprocess.run(["tmux", "new-session", "-d", "-s", session], check=True)
    subprocess.run(["tmux", "set", "-g", "mouse", "on"])
    subprocess.run(["tmux", "split-window", "-v", "-t", f"{session}:0.0", "-p", "70"])
    subprocess.run(["tmux", "split-window", "-h", "-t", f"{session}:0.0", "-p", "50"])

    subprocess.run(["tmux", "send-keys", "-t", f"{session}:0.0",
                    f"hexstrike_server --port {args.hexstrike_port}", "Enter"])
    time.sleep(1)
    subprocess.run(["tmux", "send-keys", "-t", f"{session}:0.1",
                    f"HEXSTRIKE_BACKEND_URL={hexstrike_url} mcpstrike-server", "Enter"])
    time.sleep(2)
    subprocess.run(["tmux", "send-keys", "-t", f"{session}:0.2",
                    (f"mcpstrike-client"
                     f" --ollama-url {args.ollama_url}"
                     f" --model {args.model}"
                     f" --mcp-url {mcp_url}"
                     f" --sessions-dir {args.sessions_dir}"), "Enter"])
    subprocess.run(["tmux", "select-pane", "-t", f"{session}:0.2"])
    subprocess.run(["tmux", "attach-session", "-t", session])


# ── CLI ────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcpstrike",
        description="Avvia lo stack mcpstrike (hexstrike_server + mcpstrike-server + mcpstrike-client).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    net = p.add_argument_group("rete")
    net.add_argument("--ollama-url",
                     default=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
                     metavar="URL", help="URL del daemon Ollama")
    net.add_argument("--model",
                     default=os.environ.get("OLLAMA_MODEL", "qwen3.5:latest"),
                     metavar="NAME", help="Modello Ollama da usare")
    net.add_argument("--hexstrike-port", type=int,
                     default=int(os.environ.get("HEXSTRIKE_PORT", "8888")),
                     metavar="PORT", help="Porta di hexstrike_server")
    net.add_argument("--mcp-port", type=int,
                     default=int(os.environ.get("MCPSTRIKE_PORT", "8889")),
                     metavar="PORT", help="Porta di mcpstrike-server")

    ses = p.add_argument_group("sessioni")
    ses.add_argument("--sessions-dir",
                     default=os.environ.get("HEXSTRIKE_SESSION_PATH",
                                            str(Path.home() / "hexstrike_sessions")),
                     metavar="PATH", help="Directory dove salvare le sessioni")

    mode = p.add_argument_group("modalità avvio")
    mode.add_argument("--tmux", dest="force_tmux", action="store_true", default=False,
                      help="Forza tmux split-pane invece del terminale di default")

    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    args.sessions_dir = _resolve_sessions_dir(args.sessions_dir)

    print("=" * 73)
    print("  mcpstrike stack")
    print("=" * 73)

    hexstrike_url = f"http://localhost:{args.hexstrike_port}"
    mcp_url       = f"http://localhost:{args.mcp_port}/mcp"

    if args.force_tmux:
        if not shutil.which("tmux"):
            print("  [!] tmux non trovato. Rimuovi --tmux per usare il terminale di default.")
            sys.exit(1)
        _launch_tmux(args)
        return

    # Default: apri i server in finestre separate, client in foreground
    # geometry: COLSxROWS+X+Y — affiancate su uno schermo da 1920 di larghezza
    open_terminal("hexstrike_server",
                  f"hexstrike_server --port {args.hexstrike_port}",
                  geometry="110x35+0+0")
    time.sleep(1)
    open_terminal("mcpstrike-server",
                  f"HEXSTRIKE_BACKEND_URL={hexstrike_url} mcpstrike-server",
                  geometry="110x35+960+0")
    time.sleep(2)

    subprocess.run([
        "mcpstrike-client",
        "--ollama-url", args.ollama_url,
        "--model",      args.model,
        "--mcp-url",    mcp_url,
        "--sessions-dir", args.sessions_dir,
    ])


if __name__ == "__main__":
    main()
