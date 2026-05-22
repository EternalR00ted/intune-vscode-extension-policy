<#
.SYNOPSIS
    Detection script for Intune Remediations. If VS Code is installed,
    verifies that the AllowedExtensions policy on the endpoint matches
    the allowlist defined below.

.NOTES
    Exit 0 = compliant (or VS Code not installed at all)
    Exit 1 = non-compliant (triggers remediation)

    Runs as SYSTEM via the Intune Management Extension.
    Keep the JSON block identical to the one in the remediation script.

    The policy is pre-positioned on any machine with VS Code installed,
    regardless of version. Older versions (<1.96) will ignore the policy
    in the registry, but the policy is already in place for when they
    update, with no gap between upgrade and enforcement.
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

$regPath   = "HKLM:\SOFTWARE\Policies\Microsoft\VSCode"
$valueName = "AllowedExtensions"

# --- Validate the script's own JSON before doing anything else ---
try {
    $expectedValue = ($allowedJson | ConvertFrom-Json | ConvertTo-Json -Compress)
} catch {
    Write-Output "Invalid JSON in detection script - fix the JSON block: $_"
    exit 1
}

# --- Locate VS Code (machine-wide first, then any per-user install) ---
$vsCodePath  = $null
$installType = $null

$machinePath = "$env:ProgramFiles\Microsoft VS Code\Code.exe"
if (Test-Path $machinePath) {
    $vsCodePath  = $machinePath
    $installType = "Machine"
} else {
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $userCodePath = Join-Path $_.FullName "AppData\Local\Programs\Microsoft VS Code\Code.exe"
        if ((-not $vsCodePath) -and (Test-Path $userCodePath)) {
            $vsCodePath  = $userCodePath
            $installType = "User ($($_.Name))"
        }
    }
}

if (-not $vsCodePath) {
    Write-Output "VS Code not installed - no action needed"
    exit 0
}

# Log installed version for troubleshooting visibility (not used as a gate)
$installedVersion = "unknown"
try {
    $installedVersion = (Get-Item $vsCodePath).VersionInfo.ProductVersion
} catch {}

Write-Output "VS Code v$installedVersion ($installType) - checking policy"

# --- Read current policy and compare to expected ---
try {
    $current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
} catch {
    Write-Output "Policy missing - remediation required"
    exit 1
}

# Try to normalize the current value. If it's not valid JSON, treat as non-compliant.
try {
    $currentNormalized = ($current.$valueName | ConvertFrom-Json | ConvertTo-Json -Compress)
} catch {
    Write-Output "Current policy value is not valid JSON (tampered or corrupted) - remediation required"
    exit 1
}

if ($currentNormalized -eq $expectedValue) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Policy value mismatch - remediation required"
    exit 1
}
