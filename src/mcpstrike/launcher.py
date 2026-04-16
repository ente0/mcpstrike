"""mcpstrike — stack launcher.

Avvia hexstrike_server, mcpstrike-server e mcpstrike-client in un unico
comando, con supporto per xterm (GUI), tmux (fallback) e background (ultimo
ricorso).

Uso rapido:
    mcpstrike                                # default
    mcpstrike --model qwen3:8b
    mcpstrike --ollama-url http://10.0.0.5:11434
    mcpstrike --sessions-dir /opt/sessions
    mcpstrike --font-size 15 --screen-width 2560 --screen-height 1440
    mcpstrike --tmux                         # forza tmux anche se c'è DISPLAY
    mcpstrike --no-xterm                     # alias di --tmux
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

def _has_display() -> bool:
    """True se c'è un display grafico disponibile (Linux/macOS)."""
    if os.environ.get("DISPLAY"):
        return True
    if (
        sys.platform == "darwin"
        and not os.environ.get("SSH_CONNECTION")
        and not os.environ.get("SSH_TTY")
        and not os.environ.get("TMUX")
    ):
        return True
    return False


def _resolve_sessions_dir(raw: str) -> str:
    """Espande ~ e rende assoluto il path."""
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = Path.home() / p
    return str(p)


# ── xterm geometry ─────────────────────────────────────────────────────────

def _xterm_geometries(screen_w: int, screen_h: int) -> dict[str, str]:
    """
    Layout:
      ┌─────────────────────┬─────────────────────┐
      │   hexstrike_server  │  mcpstrike-server   │  top ~54%
      ├─────────────────────┴─────────────────────┤
      │           mcpstrike-client                │  bottom ~46%
      └───────────────────────────────────────────┘
    """
    half_w = screen_w // 2
    top_h  = int(screen_h * 0.54)
    bot_y  = top_h

    return {
        "hexstrike_server": f"110x35+0+0",
        "mcpstrike_server": f"110x35+{half_w}+0",
        "mcpstrike_client": f"220x40+0+{bot_y}",
    }


# ── launchers ──────────────────────────────────────────────────────────────

def _launch_xterm(args: argparse.Namespace) -> None:
    geo = _xterm_geometries(args.screen_width, args.screen_height)
    font_opts = ["-fa", "Monospace", "-fs", str(args.font_size)]

    hexstrike_url = f"http://localhost:{args.hexstrike_port}"
    mcp_url       = f"http://localhost:{args.mcp_port}/mcp"

    def xterm(title: str, cmd: str, geometry: str, wait: float = 0) -> subprocess.Popen:
        proc = subprocess.Popen([
            "xterm", "-title", title,
            *font_opts,
            "-geometry", geometry,
            "-e", f"{cmd}; read",
        ])
        if wait:
            time.sleep(wait)
        return proc

    xterm(
        "hexstrike_server",
        f"hexstrike_server --port {args.hexstrike_port}",
        geo["hexstrike_server"],
        wait=1,
    )
    xterm(
        "mcpstrike-server",
        f"HEXSTRIKE_BACKEND_URL={hexstrike_url} mcpstrike-server",
        geo["mcpstrike_server"],
        wait=2,
    )
    # client in foreground (blocca fino alla chiusura)
    subprocess.run([
        "xterm", "-title", "mcpstrike-client",
        *font_opts,
        "-geometry", geo["mcpstrike_client"],
        "-e",
        (
            f"mcpstrike-client"
            f" --ollama-url {args.ollama_url}"
            f" --model {args.model}"
            f" --mcp-url {mcp_url}"
            f" --sessions-dir {args.sessions_dir}"
            "; read"
        ),
    ])


def _launch_tmux(args: argparse.Namespace) -> None:
    hexstrike_url = f"http://localhost:{args.hexstrike_port}"
    mcp_url       = f"http://localhost:{args.mcp_port}/mcp"
    session       = "mcpstrike"

    subprocess.run(["tmux", "kill-session", "-t", session],
                   stderr=subprocess.DEVNULL)
    subprocess.run(["tmux", "new-session", "-d", "-s", session], check=True)
    subprocess.run(["tmux", "set", "-g", "mouse", "on"])

    # top 30% → servers, bottom 70% → client
    subprocess.run(["tmux", "split-window", "-v", "-t", f"{session}:0.0", "-p", "70"])
    subprocess.run(["tmux", "split-window", "-h", "-t", f"{session}:0.0", "-p", "50"])

    subprocess.run(["tmux", "send-keys", "-t", f"{session}:0.0",
                    f"hexstrike_server --port {args.hexstrike_port}", "Enter"])
    time.sleep(1)

    subprocess.run(["tmux", "send-keys", "-t", f"{session}:0.1",
                    f"HEXSTRIKE_BACKEND_URL={hexstrike_url} mcpstrike-server", "Enter"])
    time.sleep(2)

    subprocess.run(["tmux", "send-keys", "-t", f"{session}:0.2",
                    (
                        f"mcpstrike-client"
                        f" --ollama-url {args.ollama_url}"
                        f" --model {args.model}"
                        f" --mcp-url {mcp_url}"
                        f" --sessions-dir {args.sessions_dir}"
                    ), "Enter"])

    subprocess.run(["tmux", "select-pane", "-t", f"{session}:0.2"])
    subprocess.run(["tmux", "attach-session", "-t", session])


def _launch_background(args: argparse.Namespace) -> None:
    hexstrike_url = f"http://localhost:{args.hexstrike_port}"
    mcp_url       = f"http://localhost:{args.mcp_port}/mcp"

    print("xterm/tmux non trovati — esecuzione in background (log in /tmp/mcpstrike_*.log)")

    hex_log = "/tmp/mcpstrike_hexstrike.log"
    srv_log = "/tmp/mcpstrike_server.log"

    with open(hex_log, "w") as fh:
        p1 = subprocess.Popen(
            ["hexstrike_server", "--port", str(args.hexstrike_port)],
            stdout=fh, stderr=fh,
        )
    print(f"hexstrike_server PID {p1.pid} — tail -f {hex_log}")
    time.sleep(1)

    env = {**os.environ, "HEXSTRIKE_BACKEND_URL": hexstrike_url}
    with open(srv_log, "w") as fh:
        p2 = subprocess.Popen(
            ["mcpstrike-server"],
            stdout=fh, stderr=fh, env=env,
        )
    print(f"mcpstrike-server PID {p2.pid} — tail -f {srv_log}")
    time.sleep(2)

    subprocess.run([
        "mcpstrike-client",
        "--ollama-url", args.ollama_url,
        "--model",      args.model,
        "--mcp-url",    mcp_url,
        "--sessions-dir", args.sessions_dir,
    ])


# ── CLI ────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcpstrike",
        description="Avvia lo stack mcpstrike (hexstrike_server + mcpstrike-server + mcpstrike-client).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # ── connessione ───────────────────────────────────────────────────────
    net = p.add_argument_group("rete")
    net.add_argument(
        "--ollama-url",
        default=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        metavar="URL",
        help="URL del daemon Ollama",
    )
    net.add_argument(
        "--model",
        default=os.environ.get("OLLAMA_MODEL", "qwen3.5:latest"),
        metavar="NAME",
        help="Modello Ollama da usare",
    )
    net.add_argument(
        "--hexstrike-port",
        type=int,
        default=int(os.environ.get("HEXSTRIKE_PORT", "8888")),
        metavar="PORT",
        help="Porta di hexstrike_server",
    )
    net.add_argument(
        "--mcp-port",
        type=int,
        default=int(os.environ.get("MCPSTRIKE_PORT", "8889")),
        metavar="PORT",
        help="Porta di mcpstrike-server",
    )

    # ── sessioni ──────────────────────────────────────────────────────────
    ses = p.add_argument_group("sessioni")
    ses.add_argument(
        "--sessions-dir",
        default=os.environ.get("HEXSTRIKE_SESSION_PATH",
                               str(Path.home() / "hexstrike_sessions")),
        metavar="PATH",
        help="Directory dove salvare le sessioni",
    )

    # ── interfaccia grafica ───────────────────────────────────────────────
    gui = p.add_argument_group("GUI xterm")
    gui.add_argument(
        "--font-size",
        type=int,
        default=13,
        metavar="PT",
        help="Dimensione font xterm",
    )
    gui.add_argument(
        "--screen-width",
        type=int,
        default=1920,
        metavar="PX",
        help="Larghezza schermo in pixel (per posizionare le finestre)",
    )
    gui.add_argument(
        "--screen-height",
        type=int,
        default=1080,
        metavar="PX",
        help="Altezza schermo in pixel (per posizionare le finestre)",
    )

    # ── modalità ──────────────────────────────────────────────────────────
    mode = p.add_argument_group("modalità avvio")
    excl = mode.add_mutually_exclusive_group()
    excl.add_argument(
        "--tmux", "--no-xterm",
        dest="force_tmux",
        action="store_true",
        default=False,
        help="Forza tmux anche se c'è un display grafico",
    )
    excl.add_argument(
        "--xterm",
        dest="force_xterm",
        action="store_true",
        default=False,
        help="Forza xterm (fallisce se DISPLAY non è disponibile)",
    )

    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # normalizza sessions_dir
    args.sessions_dir = _resolve_sessions_dir(args.sessions_dir)

    print("=" * 73)
    print("  mcpstrike stack")
    print("=" * 73)

    use_xterm = (
        args.force_xterm
        or (not args.force_tmux and _has_display() and shutil.which("xterm"))
    )
    use_tmux  = not use_xterm and shutil.which("tmux")

    if use_xterm:
        _launch_xterm(args)
    elif use_tmux:
        _launch_tmux(args)
    else:
        _launch_background(args)


if __name__ == "__main__":
    main()
