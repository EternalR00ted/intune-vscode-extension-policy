<#
.SYNOPSIS
    Checks the VS Code extension policy for Intune Remediations.
.NOTES
    Exit 0 = registry policy matches.
    Exit 1 = policy needs fixing; Intune runs remediation.
    Exit 2 = configuration or read error; Intune does not run remediation.

    Run as SYSTEM. Use 64-bit PowerShell in Intune.
    Keep the settings block the same in both scripts.
    This checks the registry, not the installed VS Code version.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$ValidateOnly)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# === SETTINGS - KEEP THESE THE SAME IN BOTH SCRIPTS ===

# Paste your policy here. This example blocks all non-built-in extensions.
# Add your own extension IDs or publisher rules before deploying broadly.
$allowedJson = @'
{
  "*": false
}
'@

# Leave this as $null to leave VS Code updates alone.
# To manage updates here, use 'start', 'default', 'manual', or 'none'.
$updateMode = $null

# Set this to $true to apply the same policy to VS Code Insiders.
$includeInsiders = $false

# === END SETTINGS ===

# === SHARED FUNCTIONS ===

function Write-Result {
    param([string]$Message)

    # Intune cuts off long output, so keep this to one short line.
    $line = $Message -replace '[\x00-\x1F\x7F]', ' '
    if ($line.Length -gt 1900) {
        $line = $line.Substring(0, 1897) + '...'
    }
    Write-Output $line
}

function ConvertTo-PolicyJson {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json)) {
        throw 'The JSON block is empty.'
    }
    if ($Json.Length -gt 1048576) {
        throw 'The JSON block is too large. Keep it below 1 MB of characters.'
    }

    # This policy is a flat object: booleans, "stable", or arrays of versions.
    # Check that shape first so comments, trailing commas, and nested objects fail.
    $space = '[ \t\r\n]*'
    $string = '"(?:[^"\\\x00-\x1F]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
    $array = '\[' + $space + '(?:' + $string + '(?:' + $space + ',' +
        $space + $string + ')*)?' + $space + '\]'
    $value = '(?:true|false|' + $string + '|' + $array + ')'
    $entry = '(?<key>' + $string + ')' + $space + ':' + $space + '(?<rule>' + $value + ')'
    $pattern = '\A' + $space + '\{' + $space + '(?:' + $entry +
        '(?:' + $space + ',' + $space + $entry + ')*)?' + $space + '\}' + $space + '\z'

    $match = [regex]::Match($Json, $pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant,
        [TimeSpan]::FromSeconds(5))
    if (-not $match.Success) {
        throw 'Invalid policy JSON. Use one object with true, false, "stable", or version arrays. No comments or trailing commas.'
    }

    $normalized = @{}
    $platforms = @(
        'win32-x64', 'win32-arm64', 'win32-ia32',
        'linux-x64', 'linux-arm64', 'linux-armhf',
        'alpine-x64', 'alpine-arm64',
        'darwin-x64', 'darwin-arm64', 'web', 'universal'
    )
    $versionPattern = '\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z'

    # Read one rule at a time. Parsing the whole object would hide duplicate keys.
    # Decoding also catches duplicates written with escapes, such as \u0067ithub.
    for ($i = 0; $i -lt $match.Groups['key'].Captures.Count; $i++) {
        $entryJson = '{"key":' + $match.Groups['key'].Captures[$i].Value +
            ',"rule":' + $match.Groups['rule'].Captures[$i].Value + '}'
        $decoded = ConvertFrom-Json -InputObject $entryJson -ErrorAction Stop
        $name = $decoded.key.ToLowerInvariant()
        $rule = $decoded.rule

        if ($normalized.ContainsKey($name)) {
            throw "Duplicate policy key: $name"
        }

        if ($name -cnotmatch '\A(?:\*|[a-z0-9_-]+(?:\.[a-z0-9_-]+)?)\z') {
            throw "Invalid policy key: $name. Use a publisher ID, publisher.extension, or *."
        }
        if ($name -eq '*' -and $rule -isnot [bool]) {
            throw 'The * rule must be true or false.'
        }

        if ($rule -is [bool]) {
            $normalized[$name] = $rule
        }
        elseif ($rule -is [string] -and $rule -ceq 'stable') {
            $normalized[$name] = 'stable'
        }
        elseif ($rule -is [array]) {
            if (-not $name.Contains('.')) {
                throw "Version arrays need a full extension ID, not a publisher: $name"
            }

            [string[]]$versions = @($rule)
            foreach ($version in $versions) {
                $parts = $version.Split('@')
                if ($parts.Count -gt 2 -or $parts[0] -cnotmatch $versionPattern) {
                    throw "Invalid version for ${name}: $version. Use exact versions, not ranges."
                }
                if ($parts.Count -eq 2) {
                    if ($platforms -cnotcontains $parts[1]) {
                        throw "Unknown platform for ${name}: $($parts[1])"
                    }
                    # VS Code's current matcher does not split this combination correctly.
                    if ($parts[0].Contains('-')) {
                        throw "Do not combine a prerelease suffix and @platform: $version"
                    }
                }
            }

            # Order does not change which versions are allowed. Keep case intact.
            [Array]::Sort($versions, [StringComparer]::Ordinal)
            $normalized[$name] = $versions
        }
        else {
            throw "Invalid value for $name. Use true, false, stable, or an array of exact versions."
        }
    }

    # Keep comparisons from changing just because someone reordered the JSON.
    [string[]]$names = @($normalized.GetEnumerator() | ForEach-Object { $_.Key })
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $ordered = [ordered]@{}
    foreach ($name in $names) {
        $ordered[$name] = $normalized[$name]
    }
    return (ConvertTo-Json -InputObject $ordered -Depth 5 -Compress -ErrorAction Stop)
}

function Get-PolicyIssues {
    param(
        [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$BaseKey,
        [Parameter(Mandatory = $true)][string]$SubKey,
        [Parameter(Mandatory = $true)][string]$ExpectedJson,
        [AllowNull()][object]$ExpectedUpdateMode
    )

    $key = $null
    $label = ($SubKey -split '\\')[-1]
    try {
        $key = $BaseKey.OpenSubKey($SubKey, $false)
        if ($null -eq $key) {
            return "${label}: policy key missing"
        }

        $current = $key.GetValue('AllowedExtensions', $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $current) {
            Write-Output "${label}: AllowedExtensions missing"
        }
        elseif ($key.GetValueKind('AllowedExtensions') -ne [Microsoft.Win32.RegistryValueKind]::String) {
            Write-Output "${label}: AllowedExtensions must be REG_SZ"
        }
        else {
            try {
                $currentJson = ConvertTo-PolicyJson -Json $current
                if ($currentJson -cne $ExpectedJson) {
                    Write-Output "${label}: AllowedExtensions mismatch"
                }
            }
            catch {
                Write-Output "${label}: AllowedExtensions contains invalid JSON or rules"
            }
        }

        if ($null -ne $ExpectedUpdateMode) {
            $currentMode = $key.GetValue('UpdateMode', $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $currentMode) {
                Write-Output "${label}: UpdateMode missing"
            }
            elseif ($key.GetValueKind('UpdateMode') -ne [Microsoft.Win32.RegistryValueKind]::String) {
                Write-Output "${label}: UpdateMode must be REG_SZ"
            }
            elseif ($currentMode -cne $ExpectedUpdateMode) {
                Write-Output "${label}: UpdateMode mismatch"
            }
        }
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
    }
}

# === END SHARED FUNCTIONS ===

# Check our settings before touching the registry.
try {
    $expectedJson = ConvertTo-PolicyJson -Json $allowedJson
    if ($null -ne $updateMode -and (
        $updateMode -isnot [string] -or
        @('start', 'default', 'manual', 'none') -cnotcontains $updateMode
    )) {
        throw 'UpdateMode must be $null, start, default, manual, or none.'
    }
    if ($includeInsiders -isnot [bool]) {
        throw 'includeInsiders must be $true or $false.'
    }

    $policyKeys = @('SOFTWARE\Policies\Microsoft\VSCode')
    if ($includeInsiders) {
        $policyKeys += 'SOFTWARE\Policies\Microsoft\VSCodeInsiders'
    }
}
catch {
    Write-Result "Configuration error - $($_.Exception.Message)"
    exit 2
}

# This only checks the file's settings. It does not read or write the registry.
if ($ValidateOnly) {
    Write-Result 'Configuration valid. No registry changes made.'
    exit 0
}

$baseKey = $null
$exitCode = 2
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This script needs Windows.' }

    # Open the native registry view, even if the host process is 32-bit.
    $view = [Microsoft.Win32.RegistryView]::Registry32
    if ([Environment]::Is64BitOperatingSystem) {
        $view = [Microsoft.Win32.RegistryView]::Registry64
    }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, $view)

    # Check every assigned device, including ones without VS Code installed yet.
    $issues = @(
        foreach ($subKey in $policyKeys) {
            Get-PolicyIssues -BaseKey $baseKey -SubKey $subKey `
                -ExpectedJson $expectedJson -ExpectedUpdateMode $updateMode
        }
    )

    if ($issues.Count -gt 0) {
        Write-Result ('Non-compliant - ' + ($issues -join '; '))
        $exitCode = 1
    }
    else {
        Write-Result 'Compliant - registry policy matches. VS Code enforcement is a separate check.'
        $exitCode = 0
    }
}
catch {
    # A read failure is not the same thing as a missing policy.
    Write-Result "Detection failed - $($_.Exception.Message)"
    $exitCode = 2
}
finally {
    if ($null -ne $baseKey) { $baseKey.Dispose() }
}
exit $exitCode
