<#
.SYNOPSIS
    Remediation script for Intune Remediations. Applies the VS Code
    AllowedExtensions policy and UpdateMode to the endpoint registry.

.NOTES
    Runs as SYSTEM via the Intune Management Extension. Writes to
    HKLM:\SOFTWARE\Policies\Microsoft\VSCode which is normally reserved
    for GPO - the IME bypasses that restriction.

    Keep the JSON block in this file identical to the one in the detection script.
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

$regPath    = "HKLM:\SOFTWARE\Policies\Microsoft\VSCode"
$updateMode = "start"   # options: start | none | default | manual

# Validate and compress the JSON before writing to registry
try {
    $allowedValue = ($allowedJson | ConvertFrom-Json | ConvertTo-Json -Compress)
} catch {
    Write-Output "Invalid JSON in remediation script: $_"
    exit 1
}

# Apply policy
try {
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    New-ItemProperty -Path $regPath -Name "AllowedExtensions" `
        -PropertyType String -Value $allowedValue -Force | Out-Null

    New-ItemProperty -Path $regPath -Name "UpdateMode" `
        -PropertyType String -Value $updateMode -Force | Out-Null

    Write-Output "Policy applied successfully"
    exit 0
} catch {
    Write-Output "Failed to apply policy: $_"
    exit 1
}
