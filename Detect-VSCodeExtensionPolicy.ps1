<#
.SYNOPSIS
    Detection script for Intune Remediations. Checks whether the VS Code
    AllowedExtensions policy on the endpoint matches the allowlist defined below.

.NOTES
    Exit 0 = compliant, exit 1 = non-compliant (triggers remediation).
    Keep the JSON block in this file identical to the one in the remediation script.
#>

# === PASTE YOUR ALLOWED EXTENSIONS JSON BELOW ===
$allowedJson = @"
{
  "microsoft": true,
  "github": true,
  "ms-vscode.powershell": true,
  "ms-python.python": true,
  "redhat.vscode-yaml": true
}
"@
# === END JSON ===

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\VSCode"

# Validate the JSON in this script before anything else
try {
    $expectedValue = ($allowedJson | ConvertFrom-Json | ConvertTo-Json -Compress)
} catch {
    Write-Output "Invalid JSON in detection script: $_"
    exit 1
}

# Read current policy from registry and compare
try {
    $current = Get-ItemProperty -Path $regPath -Name "AllowedExtensions" -ErrorAction Stop
    $currentNormalized = ($current.AllowedExtensions | ConvertFrom-Json | ConvertTo-Json -Compress)

    if ($currentNormalized -eq $expectedValue) {
        Write-Output "Compliant"
        exit 0
    } else {
        Write-Output "Value mismatch - remediation required"
        exit 1
    }
} catch {
    Write-Output "Policy missing or unreadable - remediation required"
    exit 1
}
