<#
.SYNOPSIS
    Remediation script for Intune Remediations. Applies the VS Code
    AllowedExtensions policy and UpdateMode to the endpoint registry
    if VS Code is installed (any version).

.NOTES
    Runs as SYSTEM via the Intune Management Extension. Writes to
    HKLM:\SOFTWARE\Policies\Microsoft\VSCode - a path normally reserved
    for GPO. The IME bypasses that restriction because it runs in SYSTEM
    context, not through the Settings Catalog enforcement layer.

    The policy is pre-positioned on any machine with VS Code installed,
    regardless of version. Older versions (<1.96) will ignore the policy
    in the registry, but the policy is already in place for when they
    update, with no gap between upgrade and enforcement.

    Keep the JSON block identical to the one in the detection script.
#>

# === PASTE YOUR ALLOWED EXTENSIONS JSON BELOW ===
$allowedJson = @"
{
  "*": false,

  "microsoft": true,
  "ms-vscode.powershell": true,
  "ms-python.python": true,

  "github": true,
  "github.copilot": "stable",

  "redhat.vscode-yaml": true,
  "redhat.vscode-xml": true
}
"@
# === END JSON ===

$regPath    = "HKLM:\SOFTWARE\Policies\Microsoft\VSCode"
$updateMode = "start"   # options: start | none | default | manual

# --- Validate and compress the JSON before writing anything ---
try {
    $allowedValue = ($allowedJson | ConvertFrom-Json | ConvertTo-Json -Compress)
} catch {
    Write-Output "Invalid JSON in remediation script - fix the JSON block: $_"
    exit 1
}

# --- Confirm VS Code is installed (machine-wide or per-user) ---
$vsCodePath = $null

$machinePath = "$env:ProgramFiles\Microsoft VS Code\Code.exe"
if (Test-Path $machinePath) {
    $vsCodePath = $machinePath
} else {
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $userCodePath = Join-Path $_.FullName "AppData\Local\Programs\Microsoft VS Code\Code.exe"
        if ((-not $vsCodePath) -and (Test-Path $userCodePath)) {
            $vsCodePath = $userCodePath
        }
    }
}

if (-not $vsCodePath) {
    Write-Output "VS Code not installed - skipping policy application"
    exit 0
}

# Log installed version for troubleshooting visibility (not used as a gate)
$installedVersion = "unknown"
try {
    $installedVersion = (Get-Item $vsCodePath).VersionInfo.ProductVersion
} catch {}

# --- Apply policy ---
try {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    New-ItemProperty -Path $regPath -Name "AllowedExtensions" `
        -PropertyType String -Value $allowedValue -Force | Out-Null

    New-ItemProperty -Path $regPath -Name "UpdateMode" `
        -PropertyType String -Value $updateMode -Force | Out-Null

    Write-Output "Policy applied successfully (VS Code v$installedVersion)"
    exit 0
} catch {
    Write-Output "Failed to apply policy: $_"
    exit 1
}
