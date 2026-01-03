<#
Program: string-tool.ps1
Author: CyberPanther232
Date: 2025-09-10
Purpose: A PowerShell script to assist with string manipulation tasks.
#>

param (
    [string]$InputString,
    [string]$Operation,
    [string]$Output
)

function Show-Help {
    Write-Host "String Tool Help"
    Write-Host "Usage: .\string-tool.ps1 -InputString <string> -Operation <operation> -Output <output file>"
    Write-Host "Operations:"
    Write-Host "  reverse   - Reverse the input string"
    Write-Host "  uppercase - Convert the input string to uppercase"
    Write-Host "  lowercase - Convert the input string to lowercase"
    Write-Host "  length    - Get the length of the input string"
    Write-Host "  b64enc    - Base64 encode the input string"
    Write-Host "  b64dec    - Base64 decode the input string" 
    Write-Host "Example: .\string-tool.ps1 -InputString 'Hello World' -Operation reverse -Output result.txt"
}


if ($PSBoundParameters.ContainsKey('Help') -or -not $PSBoundParameters.ContainsKey('InputString') -or -not $PSBoundParameters.ContainsKey('Operation')) {
    Show-Help
    exit
}

switch ($Operation.ToLower()) {
    "reverse" {
        $StringArray = $InputString.ToCharArray()
        $Result = [array]::Reverse($StringArray)
        $Result = -join $StringArray

    }
    "uppercase" {
        $Result = $InputString.ToUpper()
    }
    "lowercase" {
        $Result = $InputString.ToLower()
    }
    "length" {
        $Result = $InputString.Length
    }
    "b64enc" {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        $Result = [Convert]::ToBase64String($Bytes)
    }

    "b64dec" {
        try {
            $Bytes = [Convert]::FromBase64String($InputString)
            $Result = [System.Text.Encoding]::UTF8.GetString($Bytes)
        } catch {
            Write-Host "Error: Invalid Base64 string."
            exit
        }
    }

    default {
        Write-Host "Invalid operation specified."
        Show-Help
        exit
    }
}

if ($PSBoundParameters.ContainsKey('Output')) {
    $Result | Out-File -FilePath $Output
    Write-Host "Result written to $Output"
} else {
    Write-Host "Result: $Result"
}