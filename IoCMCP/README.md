# IoCMCP

A minimal MCP server exposing a VirusTotal domain lookup tool.

## Setup

- Python 3.12+
- Create/activate a venv (recommended), then install deps:

```pwsh
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

Set your VirusTotal API key via environment variable:

```pwsh
$Env:VIRUSTOTAL_API_KEY = "<your_api_key_here>"
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

Note: Copilot desktop config path logic is not defined yet in these scripts.

⚠ Warning: Treat LLMs as untrusted for sensitive data. Do not paste secrets, API keys, or confidential indicators directly into prompts or conversation history. Prefer environment variables and server-side storage. Review your LLM client's settings and data retention policies carefully.

## Run

```pwsh
python .\server.py
```

This starts the MCP server using stdio transport.

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
