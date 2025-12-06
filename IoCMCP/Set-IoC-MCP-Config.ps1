<#
Program: Set-IoC-MCP-Config.ps1
Purpose: This script configures the MCP (Multi-Cloud Platform) settings for deployment.
Author: CyberPanther232
Date Created: 2025-12-05
#>

# Sets the AI model for MCP configuration
param (
    [string]$aiModel = "copilot"
)

function Set-MCPConfig {
    param(
        [string]$ClientAIModel = "copilot"
    )

    # 1. Define Paths Robustly
    # We use Resolve-Path to ensure we get the real location, regardless of where the script runs
    if (-not (Test-Path "IoCMCP")) {
        Write-Error "Directory 'IoCMCP' not found in current location."
        return
    }
    $IoCMCPDirectory = (Resolve-Path "..\IoCMCP").Path
    $VenvPythonPath  = Join-Path $IoCMCPDirectory ".venv\Scripts\python.exe"
    $ServerPath      = Join-Path $IoCMCPDirectory "server.py"

    # 2. Create the Configuration as an OBJECT (Not a String)
    # This prevents the backslash/escaping issues entirely.
    $IoCConfigObject = @{
        command      = $VenvPythonPath
        args         = $ServerPath
        env          = @{
            PYTHONUTF8      = "1"
            VIRUS_TOTAL_KEY = $env:VIRUS_TOTAL_KEY
            SHODAN_API_KEY  = $env:SHODAN_API_KEY
            ABUSE_CH_KEY    = $env:ABUSE_CH_KEY
        }
        resourcePath = $IoCMCPDirectory
    }

    # 3. Determine Target Config File based on AI Model
    $TargetConfigFile = $null

    switch ($ClientAIModel) {
        "gemini" {
            # Looking for .gemini/settings.json in User Profile
            $Path = "$env:USERPROFILE\.gemini\settings.json"
            if (Test-Path $Path) { $TargetConfigFile = $Path }
        }
        "claude" {
            # Claude usually lives in AppData Roaming
            $Path = "$env:APPDATA\Claude\claude_desktop_config.json" 
            if (Test-Path $Path) { $TargetConfigFile = $Path }
        }
        "copilot" {
            # Try common Copilot Desktop paths on Windows
            $Candidates = @(
                "$env:APPDATA\GitHub Copilot\mcp.json",
                "$env:APPDATA\GitHub Copilot\settings.json",
                "$env:APPDATA\GitHub Copilot Desktop\settings.json"
            )
            foreach ($c in $Candidates) {
                if (Test-Path $c) { $TargetConfigFile = $c; break }
            }
            if (-not $TargetConfigFile) {
                Write-Warning "Copilot configuration file not found in common locations."
            }
        }
    }

    if (-not $TargetConfigFile) {
        Write-Warning "Configuration file for '$ClientAIModel' not found."
        return
    }

    # 4. Load, Modify, and Save
    Write-Host "Configuring $ClientAIModel at: $TargetConfigFile" -ForegroundColor Cyan

    try {
        $jsonContent = Get-Content -Path $TargetConfigFile -Raw | ConvertFrom-Json

        # Ensure 'mcpServers' exists; if not, create it as an object
        if (-not $jsonContent.PSObject.Properties['mcpServers']) {
            $jsonContent | Add-Member -Name 'mcpServers' -Value @{} -MemberType NoteProperty
        }

        # Check if IoCMCP exists using checking property names
        # We access the PSObject.Properties to check existence safely
        if ($jsonContent.mcpServers.PSObject.Properties['IoCMCP']) {
            Write-Warning "IoCMCP configuration already exists. Overwriting..."
        }

        # 5. INJECT THE OBJECT
        # We add the Hashtable ($IoCConfigObject) directly. 
        # Note: Depending on existing structure, we might need to force the add.
        
        # A robust way to add/update a property on a PSCustomObject:
        $jsonContent.mcpServers | Add-Member -Name "IoCMCP" -Value $IoCConfigObject -MemberType NoteProperty -Force

        # 6. Save with Depth
        $jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path $TargetConfigFile
        Write-Host "Success! Configuration updated." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to update configuration: $_"
    }
}

if ($aiModel -ne "") {

    Set-MCPConfig -ClientAIModel $aiModel

} else {
    Write-Host "No AI model specified. Using default settings."
}



