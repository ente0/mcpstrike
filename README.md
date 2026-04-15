<img width="1928" height="608" alt="Frame 1" src="https://github.com/user-attachments/assets/2407495e-315e-4019-b542-df3d5c47bc4e" />
# mcpstrike

MCP server + Ollama-driven autonomous penetration testing framework.

mcpstrike connects an LLM (via Ollama) to security tools through the Model Context Protocol (MCP), enabling autonomous or guided penetration testing from a terminal interface.

## Architecture

```
mcpstrike-client          mcpstrike-server (MCP)         hexstrike_server
 (TUI + Ollama)   --->    (FastMCP, port 8889)    --->   (port 8888, must be running)
      |
      v
  Ollama LLM
  (llama3.2, qwen3.5, etc.)

  Optional: mcpstrike-backend can replace hexstrike_server for local testing
```

**Components:**

| Component | Role | Default port |
|---|---|---|
| **hexstrike_server** | External backend — must be started separately | 8888 |
| `mcpstrike-server` | MCP server exposing 15 tools for session/command management | 8889 |
| `mcpstrike-client` | Interactive TUI that drives an Ollama LLM to call MCP tools | — |
| `mcpstrike-backend` *(optional)* | Lightweight local alternative to hexstrike_server | **8890** |

## Installation

### With pipx (recommended)

```bash
# Standard install (uses hexstrike-server as backend)
pipx install .

# With optional standalone backend
pipx install ".[backend]"
```

### With pip

```bash
pip install --user .

# With optional standalone backend
pip install --user ".[backend]"
```

### Development

```bash
pip install -e ".[dev,backend]"
```

## Quick Start

**hexstrike_server must already be running** on port 8888 before starting mcpstrike.

### Automated (recommended)

```bash
./start.sh
```

`start.sh` contains your personal IPs/model names. It opens separate xterm windows (or falls back to background processes) for `mcpstrike-server` and `mcpstrike-client`.

### Manual

```bash
# Terminal 1: MCP server (points to hexstrike_server on 8888)
HEXSTRIKE_BACKEND_URL=http://localhost:8888 mcpstrike-server

# Terminal 2: Client
mcpstrike-client --ollama-url http://<ollama-host>:11434 --model qwen3.5
```

### With standalone backend (no hexstrike_server needed)

```bash
# Terminal 1: Local backend (port 8890, no conflict with hexstrike on 8888)
mcpstrike-backend

# Terminal 2: MCP server pointing to mcpstrike-backend
HEXSTRIKE_BACKEND_URL=http://localhost:8890 mcpstrike-server

# Terminal 3: Client
mcpstrike-client
```

Requires `pipx install ".[backend]"`.

## Commands

### mcpstrike-client

Interactive TUI for driving penetration tests with an Ollama LLM.

```
mcpstrike-client [OPTIONS]

Options:
  --mcp-url URL          MCP server URL (default: http://localhost:8889/mcp)
  --ollama-url URL       Ollama API URL (default: http://localhost:11434)
  --model, -m NAME       Ollama model (default: llama3.2)
  --sessions-dir PATH    Session files directory (default: ~/hexstrike_sessions)
  --no-native-tools      Force JSON fallback mode (for older models)
  --no-auto-parse        Disable automatic parser dispatch
  --debug                Enable verbose error tracebacks
```

#### Interactive Commands

| Command | Description |
|---|---|
| `/help` | Show all available commands |
| `/tools` | List MCP tools discovered on the server |
| `/agent` | Toggle autonomous agent mode (ON by default) |
| `/prompt <#> <target>` | Generate and load a pentest prompt template |
| `/prompts` | List available prompt templates with index numbers |
| `/status` | Show connection, model, and session info |
| `/model <name>` | Switch Ollama model at runtime |
| `/native` | Toggle native tool-calling vs JSON fallback |
| `/clear` | Clear conversation history |
| `/quit`, `/exit` | Exit the client |

#### Input Modes

| Mode | Usage |
|---|---|
| Normal | Type a message and press Enter |
| Multi-line | Start with `<<<`, type multiple lines, end with `>>>` |
| File input | `@path/to/file.txt` loads the file content as input |

#### Prompt Workflow

mcpstrike ships with pentest prompt templates. Use them to bootstrap an assessment:

```
/prompts                              # list templates with numbers
/prompt 1 192.168.1.100               # generate autonomous prompt for target
/prompt 2 10.0.0.5 -d example.com     # guided prompt with domain
go                                    # send any message to start execution
```

Templates are in `src/mcpstrike/client/prompts/templates/` — you can add your own `.txt` or `.md` files there.

### mcpstrike-server

FastMCP server exposing penetration testing tools via MCP protocol.

```
mcpstrike-server
```

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `HEXSTRIKE_BACKEND_URL` | `http://localhost:8888` | Backend API URL (hexstrike or mcpstrike-backend) |
| `MCPSTRIKE_HOST` | `0.0.0.0` | Server bind address |
| `MCPSTRIKE_PORT` | `8889` | Server bind port |
| `HEXSTRIKE_SESSION_PATH` | — | Absolute path for sessions (highest priority) |
| `HEXSTRIKE_SESSION_DIR` | — | Folder name in `$HOME` for sessions |

### mcpstrike-backend (optional)

Lightweight local backend — alternative to hexstrike-server. Executes security tools as subprocesses directly on the local machine.

**Requires the `backend` extra:** `pipx install ".[backend]"`

```
mcpstrike-backend [OPTIONS]

Options:
  --host TEXT    Bind address (default: 0.0.0.0)
  --port INT     Bind port (default: 8888)
```

Environment variables: `HEXSTRIKE_BACKEND_HOST`, `HEXSTRIKE_BACKEND_PORT`.

Endpoints:

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check with uptime |
| POST | `/api/command` | Execute a command, returns stdout/stderr/exit_code |

### mcpstrike-prompt

Standalone prompt generator CLI.

```
mcpstrike-prompt --target 192.168.1.100 --template autonomous
mcpstrike-prompt --list                    # list templates
mcpstrike-prompt -t 10.0.0.5 -d site.com --dry-run
mcpstrike-prompt -t 10.0.0.5 -o ./prompts_out/
```

## MCP Tools Reference

The MCP server exposes 14 tools that the LLM can invoke:

### Configuration

| Tool | Description |
|---|---|
| `get_config` | Return current server configuration |
| `set_session_directory` | Change session directory at runtime |

### Session Discovery

| Tool | Description |
|---|---|
| `discover_sessions` | Find sessions across multiple directories |
| `import_external_session` | Import a session folder from an external path |

### Execution

| Tool | Description |
|---|---|
| `health_check` | Ping the backend |
| `execute_command` | Run a security command on the backend |

### Session Files

| Tool | Description |
|---|---|
| `create_session` | Create a new pentest session |
| `list_sessions` | List all sessions |
| `write_session_file` | Write content to a session file |
| `read_session_file` | Read content from a session file |
| `list_session_files` | List files in a session |

### Parsers

| Tool | Description |
|---|---|
| `parse_output` | Parse raw tool output (nmap, whatweb, nuclei, nikto, dirb) |
| `auto_parse_output` | Auto-detect the tool and route to the correct parser |

### Findings

| Tool | Description |
|---|---|
| `update_session_findings` | Merge parsed findings into session_metadata.json |

## Agent Mode

When agent mode is ON (default), the client runs an autonomous loop:

1. Send the conversation + system prompt to Ollama
2. If the model returns tool calls, execute them via MCP
3. Feed tool results back into the conversation
4. Repeat until the model responds with text only (no tool calls)

Safety features:
- **Max iterations**: Stops after 20 consecutive tool-call cycles
- **Context pruning**: Sliding window keeps the last 40 messages to prevent Ollama context overflow
- **Ctrl+C**: Abort the current generation at any time
- **Auto-save**: Command output is automatically saved to session files
- **Auto-parse**: Output is parsed for structured findings (ports, vulns, etc.)
- **Findings persistence**: Parsed findings are merged into `session_metadata.json`

## Prompt Templates

Two templates ship with mcpstrike:

### autonomous

Full-autonomy prompt with decision framework. The model receives:
- Target information and scope boundaries
- Complete tool arsenal reference
- Decision framework (discovery -> enumeration -> exploitation -> documentation)
- Tool usage best practices and anti-patterns
- XSS/SQLi workflow examples

### guided

Step-by-step methodology with numbered phases (0-9). More structured, walks the model through each phase sequentially.

### Custom Templates

Add `.txt` or `.md` files to `src/mcpstrike/client/prompts/templates/`. Use `{{PLACEHOLDER}}` syntax:

| Placeholder | Description |
|---|---|
| `{{TARGET}}` | Target IP or hostname |
| `{{DOMAIN}}` | Domain name |
| `{{SESSION_ID}}` | Auto-generated session ID |
| `{{DATE}}` | Current date |
| `{{TEST_TYPE}}` | Test type (black_box, gray_box, web_app, network, full) |

## Configuration

All configuration is via environment variables or `.env` file:

```env
# Backend (hexstrike-server or mcpstrike-backend)
HEXSTRIKE_BACKEND_URL=http://localhost:8888

# MCP Server
MCPSTRIKE_HOST=0.0.0.0
MCPSTRIKE_PORT=8889

# Client
MCPSTRIKE_MCP_URL=http://localhost:8889/mcp
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Sessions
HEXSTRIKE_SESSION_PATH=/absolute/path/to/sessions
HEXSTRIKE_SESSION_DIR=my_sessions  # relative to $HOME
```

## Project Structure

```
src/mcpstrike/
  config.py                     # Centralized settings (pydantic-settings)
  backend/                      # OPTIONAL — standalone local backend
    app.py                      # FastAPI subprocess execution server
  server/
    wrapper.py                  # MCPServerWrapper (FastMCP lifecycle)
    app.py                      # MCP tool definitions (14 tools)
  client/
    wrapper.py                  # MCPClientWrapper (JSON-RPC + SSE)
    ollama_bridge.py            # Ollama streaming + tool-call dispatch
    tui.py                      # Interactive TUI (rich + prompt_toolkit)
    prompts/
      generator.py              # Template manager + prompt generation
      templates/
        autonomous.txt          # Full-autonomy pentest prompt
        guided.txt              # Step-by-step guided prompt
  common/
    filenames.py                # Smart filename allocation for output
    formatters.py               # Output extraction + report formatting
    parsers.py                  # nmap/whatweb/nuclei/nikto/dirb parsers
```

## Requirements

- Python >= 3.10
- Ollama running locally (or remotely via `--ollama-url`)
- **hexstrike_server** running on port 8888, OR install with `.[backend]` for the standalone alternative
- Security tools installed on the backend machine (nmap, nikto, sqlmap, etc.)
