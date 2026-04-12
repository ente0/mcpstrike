# mcpstrike

MCP server + Ollama-driven autonomous penetration testing framework.

mcpstrike connects an LLM (via Ollama) to security tools through the Model Context Protocol (MCP), enabling autonomous or guided penetration testing from a terminal interface.

## Architecture

```
mcpstrike-client          mcpstrike-server (MCP)         mcpstrike-backend
 (TUI + Ollama)   --->    (FastMCP, port 8889)    --->   (FastAPI, port 8888)
      |                         |                              |
      v                         v                              v
  Ollama LLM              MCP tools (14)               subprocess execution
  (llama3.2, etc.)        session management            (nmap, nikto, sqlmap...)
                          output parsing
                          findings persistence
```

**Three-tier design:**

| Component | Role | Default port |
|---|---|---|
| `mcpstrike-backend` | Runs security tools as subprocesses, returns stdout/stderr | 8888 |
| `mcpstrike-server` | MCP server exposing 14 tools for session/command management | 8889 |
| `mcpstrike-client` | Interactive TUI that drives an Ollama LLM to call MCP tools | — |

## Installation

### With pipx (recommended)

```bash
pipx install .
```

This installs four commands globally: `mcpstrike-server`, `mcpstrike-client`, `mcpstrike-backend`, and `mcpstrike-prompt`.

### With pip

```bash
pip install --user .
```

### Development

```bash
pip install -e ".[dev]"
```

## Quick Start

Start all three components (in separate terminals):

```bash
# Terminal 1: Backend (executes actual security tools)
mcpstrike-backend

# Terminal 2: MCP server (provides tools to the LLM)
mcpstrike-server

# Terminal 3: Client (interactive TUI)
mcpstrike-client
```

The client connects to the MCP server, which forwards `execute_command` calls to the backend.

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
| `HEXSTRIKE_BACKEND_URL` | `http://localhost:8888` | Backend API URL |
| `MCPSTRIKE_HOST` | `0.0.0.0` | Server bind address |
| `MCPSTRIKE_PORT` | `8889` | Server bind port |
| `HEXSTRIKE_SESSION_PATH` | — | Absolute path for sessions (highest priority) |
| `HEXSTRIKE_SESSION_DIR` | — | Folder name in `$HOME` for sessions |

### mcpstrike-backend

FastAPI backend that executes security tools as subprocesses.

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
- Decision framework (discovery → enumeration → exploitation → documentation)
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
# Backend
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
  backend/
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
- Security tools installed on the machine running `mcpstrike-backend` (nmap, nikto, etc.)

## License

MIT
