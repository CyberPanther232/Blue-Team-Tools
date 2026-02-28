#!/usr/bin/env bash

# Program: set_mcp_config.sh
# Purpose: Configure MCP settings for IoCMCP server (bash equivalent).
# Author: Ported from PowerShell by GitHub Copilot
# Date: 2025-12-05

set -euo pipefail

# Prints message to stderr
err() { printf "[ERROR] %s\n" "$*" >&2; }
warn() { printf "[WARN ] %s\n" "$*" >&2; }
info() { printf "[INFO ] %s\n" "$*"; }

# Require jq for JSON manipulation
require_jq() {
	if ! command -v jq >/dev/null 2>&1; then
		err "jq is required. Install with: sudo apt-get install jq (Linux) or brew install jq (macOS)."
		exit 1
	fi
}

usage() {
	cat <<EOF
Usage: $(basename "$0") [-m MODEL]

Options:
	-m, --model   AI client model to configure (gemini|claude|copilot). Default: copilot

Environment Variables consumed:
	VIRUS_TOTAL_KEY, SHODAN_API_KEY, ABUSE_CH_KEY

This script mirrors Set-IoC-MCP-Config.ps1 functionality for bash.
EOF
}

MODEL="copilot"
while [[ $# -gt 0 ]]; do
	case "$1" in
		-m|--model)
			MODEL=${2:-}; shift 2 ;;
		-h|--help)
			usage; exit 0 ;;
		*)
			err "Unknown argument: $1"; usage; exit 1 ;;
	esac
done

require_jq

# Resolve IoCMCP directory relative to this script
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IOCMCP_DIR="$SCRIPT_DIR"

# Verify directory exists
if [[ ! -d "$IOCMCP_DIR" ]]; then
	err "Directory 'IoCMCP' not found relative to script."
	exit 1
fi

# Compute paths (Unix-style venv layout)
VENV_PYTHON="$IOCMCP_DIR/.venv/bin/python"
SERVER_PATH="$IOCMCP_DIR/server.py"

if [[ ! -x "$VENV_PYTHON" ]]; then
	warn "Python venv not found at $VENV_PYTHON. Using system python if available."
	if command -v python3 >/dev/null 2>&1; then
		VENV_PYTHON=$(command -v python3)
	elif command -v python >/dev/null 2>&1; then
		VENV_PYTHON=$(command -v python)
	else
		err "No python interpreter found. Create venv: python3 -m .venv '$IOCMCP_DIR/.venv'"
		exit 1
	fi
fi

if [[ ! -f "$SERVER_PATH" ]]; then
	err "server.py not found at $SERVER_PATH"
	exit 1
fi

# Build the IoC MCP config object in JSON using jq
# Values come from environment variables if set; empty string otherwise
PYTHONUTF8="1"
VIRUS_TOTAL_KEY="${VIRUS_TOTAL_KEY:-}"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
ABUSE_CH_KEY="${ABUSE_CH_KEY:-}"

IOC_CONFIG_JSON=$(jq -n \
	--arg command "${VENV_PYTHON//\\/\/}" \
	--arg args0 "$SERVER_PATH" \
	--arg pythonutf8 "$PYTHONUTF8" \
	--arg vt "$VIRUS_TOTAL_KEY" \
	--arg shodan "$SHODAN_API_KEY" \
	--arg abuse "$ABUSE_CH_KEY" \
	--arg resourcePath "${IOCMCP_DIR//\\/\/}" \
	'{
		command: $command,
		args: [$args0],
		env: {
			PYTHONUTF8: $pythonutf8,
			VIRUS_TOTAL_KEY: $vt,
			SHODAN_API_KEY: $shodan,
			ABUSE_CH_KEY: $abuse
		},
		resourcePath: $resourcePath
	}')

# Determine target config file based on model
TARGET_CONFIG=""
case "$MODEL" in
	gemini)
		TARGET_CONFIG="$HOME/.gemini/settings.json"
		;;
	claude)
		# Common Linux/macOS path; adjust as needed per environment
		# Linux: ~/.config/Claude/claude_desktop_config.json
		# macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
		if [[ "$(uname)" == "Darwin" ]]; then
			TARGET_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
		else
			TARGET_CONFIG="$HOME/.config/Claude/claude_desktop_config.json"
		fi
		;;
	copilot)
		# Try common Copilot Desktop paths
		if [[ "$(uname)" == "Darwin" ]]; then
			CANDIDATES=(
				"$HOME/Library/Application Support/GitHub Copilot/settings.json"
				"$HOME/Library/Application Support/GitHub Copilot Desktop/settings.json"
			)
		else
			CANDIDATES=(
				"$HOME/.config/GitHub Copilot/settings.json"
				"$HOME/.config/GitHub Copilot Desktop/settings.json"
			)
		fi
		for c in "${CANDIDATES[@]}"; do
			if [[ -f "$c" ]]; then TARGET_CONFIG="$c"; break; fi
		done
		if [[ -z "$TARGET_CONFIG" ]]; then
			warn "Copilot configuration file not found in common locations."
		fi
		;;
	*)
		err "Unknown model: $MODEL"; exit 1 ;;
esac

if [[ -z "$TARGET_CONFIG" || ! -f "$TARGET_CONFIG" ]]; then
	warn "Configuration file for '$MODEL' not found at: $TARGET_CONFIG"
	exit 0
fi

info "Configuring $MODEL at: $TARGET_CONFIG"

# Load, ensure mcpServers exists, inject/overwrite IoCMCP key, and save
TMP_FILE=$(mktemp)

# Read existing JSON, ensure object
if ! jq '.' "$TARGET_CONFIG" >/dev/null 2>&1; then
	err "Target config is not valid JSON: $TARGET_CONFIG"
	rm -f "$TMP_FILE"
	exit 1
fi

# Perform update with jq: ensure mcpServers exists and set .mcpServers.IoCMCP = IOC_CONFIG_JSON
jq --argjson ioc "$IOC_CONFIG_JSON" \
	'(.mcpServers //= {}) | .mcpServers.IoCMCP = $ioc' \
	"$TARGET_CONFIG" > "$TMP_FILE"

mv "$TMP_FILE" "$TARGET_CONFIG"
info "Success! Configuration updated."

