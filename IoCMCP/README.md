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
