# IoCMCP

A minimal MCP server exposing a VirusTotal domain lookup tool.

## Setup

- Python 3.12+
- Virtual environment (recommended)
- OSINT provider API keys (as environment variables)

### Windows (PowerShell)

```pwsh
cd IoCMCP
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux/macOS (bash)

```bash
cd IoCMCP
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you plan to use the bash config script, ensure `jq` is installed:

```bash
# macOS
brew install jq
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y jq
```

## Configuration

Set your OSINT API keys via environment variables:

```pwsh
# PowerShell (Windows)
$Env:VIRUS_TOTAL_KEY = "<virustotal_key>"
$Env:SHODAN_API_KEY  = "<shodan_key>"
$Env:ABUSE_CH_KEY    = "<threatfox_key>"
```

```bash
# bash (Linux/macOS)
export VIRUS_TOTAL_KEY="<virustotal_key>"
export SHODAN_API_KEY="<shodan_key>"
export ABUSE_CH_KEY="<threatfox_key>"
```

You can also configure supported LLM clients to point at this MCP server using the provided scripts:

- PowerShell (Windows): `Set-IoC-MCP-Config.ps1`
- Bash (Linux/macOS): `set_mcp_config.sh`

Examples:

```pwsh
# Windows PowerShell — Gemini client
./Set-IoC-MCP-Config.ps1 -aiModel gemini

# Windows PowerShell — Claude client
./Set-IoC-MCP-Config.ps1 -aiModel claude
```

```bash
# Bash — Gemini client
bash ./set_mcp_config.sh --model gemini

# Bash — Claude client (Linux/macOS)
bash ./set_mcp_config.sh --model claude
```

Note: Copilot desktop config detection is supported on common paths; if your installation stores config elsewhere, specify the file manually or update the script.

⚠ Warning: Treat LLMs as untrusted for sensitive data. Do not paste secrets, API keys, or confidential indicators directly into prompts or conversation history. Prefer environment variables and server-side storage. Review your LLM client's settings and data retention policies carefully.

## Run

```pwsh
python .\server.py
```

This starts the MCP server using stdio transport.

Alternatively (Linux/macOS):

```bash
python3 ./server.py
```

## Quick test (optional)

You can directly import and call the tool function:

```pwsh
python - << 'PY'
import json
import server
print(json.dumps(server.virus_total_domain_lookup('example.com'), indent=2))
PY
```

If the API key is missing or invalid, the function returns a helpful error object.

## Troubleshooting

- Missing dependencies: Re-activate your venv and re-run `pip install -r requirements.txt`.
- No API keys: Ensure the environment variables are exported in the same shell session that launches `server.py`.
- LLM cannot see server: Verify the target config file was updated and that `.mcpServers.IoCMCP` exists.
- Paths on Windows: Use full paths or launch from the repo root to avoid relative path issues.

## Security Notes

- Avoid pasting secrets into LLM prompts; use environment variables.
- Treat outputs as assistive intelligence; verify with authoritative sources.
- Review your LLM client’s data retention settings before connecting MCP.
