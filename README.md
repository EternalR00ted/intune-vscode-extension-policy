# vscode-extension-lockdown

Lock down VS Code extensions on managed endpoints using Microsoft Intune.

Two PowerShell scripts (detection + remediation) you drop into Intune Remediations. Paste your allowlist as JSON, deploy, done.

## Why this exists

VS Code 1.96+ ships with a native `AllowedExtensions` policy. It overrides user settings, disables anything not on your allowlist, and greys out the Install button in the extensions UI for everything else. Microsoft ships an ADMX for it.

If you're a cloud-only Intune shop, you'll hit a wall.

The policy lives at:

```
HKLM:\SOFTWARE\Policies\Microsoft\VSCode
```

Intune's Settings Catalog and ADMX ingestion both block writes to `Software\Policies\Microsoft\*`. That path is reserved for traditional GPO to avoid conflicts in hybrid environments. So you can't just import the ADMX and call it a day - the policy will silently fail to apply.

The workaround is Intune Remediations. The scripts run as SYSTEM via the Intune Management Extension, which can write wherever it wants.

That's what these scripts do.

## What's in here

- `Detect-VSCodeExtensionPolicy.ps1` - checks if VS Code is installed, then verifies the policy matches your allowlist
- `Remediate-VSCodeExtensionPolicy.ps1` - applies the policy if it doesn't

Both scripts have a clearly marked JSON block at the top. That's the only thing you need to edit.

The scripts also handle a few real-world edge cases:
- Skips machines without VS Code installed (no noise in your reporting)
- Checks for both machine-wide and per-user VS Code installs
- Pre-positions the policy regardless of VS Code version - older versions ignore it, but it's there for when they update
- Treats tampered or corrupted registry values as non-compliant

## Setup

### 1. Edit your allowlist

Open both scripts. At the top you'll see:

```powershell
# === PASTE YOUR ALLOWED EXTENSIONS JSON BELOW ===
$allowedJson = @"
{
  "*": false,
  "microsoft": true,
  ...
}
"@
# === END JSON ===
```

Replace the JSON with your own. The same JSON must be in both files - if they don't match, detection will always flag non-compliant and remediation will run every cycle.

The default example uses a **default-deny pattern** (`"*": false` blocks everything, then explicit allows). That's the right starting posture for a security control.

### 2. JSON syntax

```
"*": false                                      block everything by default
"*": true                                       allow everything by default
"publisher-name": true                          allow all from this publisher
"publisher-name": false                         block all from this publisher
"publisher.extension-id": true                  allow this specific extension
"publisher.extension-id": false                 block this specific extension
"publisher.extension-id": "stable"              only stable, no pre-release
"publisher.extension-id": ["1.2.3", "1.2.4"]    pin to specific versions
```

Important rules from Microsoft's official docs:

- **The wildcard `"*"` is the only wildcard supported.** No `"redhat.*": true` style patterns. The publisher ID alone (e.g. `"redhat": true`) acts as the publisher-wide allow.
- **More specific selectors win.** `"*": false` plus `"microsoft": true` allows all Microsoft extensions and blocks everything else. The wildcard is the least specific, so explicit publishers and extension IDs override it.
- **Duplicate keys break the whole policy.** Including both `"microsoft": true` and `"microsoft": false` results in an invalid configuration and the policy won't apply at all.
- **Standard JSON.** Use normal JSON syntax. Some older blog posts claim you need a space before the colon - that's not accurate per Microsoft's docs. The scripts normalize the JSON via PowerShell anyway, so don't worry about it.

To grab an extension ID: in VS Code, right-click any extension in the sidebar and pick **Copy Extension ID**. Format is always `publisher.extension-name`.

### 3. Deploy in Intune

Intune admin center → **Devices** → **Scripts and remediations** → **Create script package**.

| Setting | Value |
|---|---|
| Detection script file | `Detect-VSCodeExtensionPolicy.ps1` |
| Remediation script file | `Remediate-VSCodeExtensionPolicy.ps1` |
| Run this script using the logged-on credentials | **No** (needs SYSTEM for HKLM\Policies) |
| Enforce script signature check | **No** (unless you sign internally) |
| Run script in 64-bit PowerShell | **Yes** |

Assign to a pilot group first. A schedule of every 8 hours or daily is reasonable for drift detection.

### 4. Verify

On a test endpoint:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\VSCode" | Select AllowedExtensions, UpdateMode
```

Then open VS Code → Extensions → search for something not on the list. Install button should be greyed out. Anything already installed that isn't allowed gets disabled with a notice.

You should also see a briefcase icon next to `Extensions: Allowed` in Settings, with the text "Managed by organization."

## UpdateMode

The remediation script also sets `UpdateMode`, which controls VS Code's own update behavior:

- `start` - check for updates on launch (default in this script)
- `none` - fully lock version, no updates, suppresses the update dialog
- `default` - normal automatic updates
- `manual` - user must manually check for updates

Change the `$updateMode` variable in the remediation script if you want something other than `start`.

## Version handling - pre-positioning, not skipping

The `AllowedExtensions` policy requires VS Code 1.96+. Older versions silently ignore the value in the registry.

The scripts deliberately **do not** version-gate. The policy gets written to any machine with VS Code installed, regardless of version. Reasons:

- The registry write is harmless on older versions - they just don't read it
- When a machine updates to 1.96+ (via Intune update rings, VS Code's own updater, or a fresh install), the policy is **already there** and takes effect immediately on next launch
- Version-gating creates a coverage gap between "user upgrades VS Code" and "next remediation cycle runs" - during which the machine is unprotected

The installed version is logged in the script output for visibility, but isn't used as a gate.

## Failure modes worth knowing about

**1. VS Code fails open on bad JSON.** If the policy value has any syntax error, VS Code silently reverts to "allow all" rather than failing closed. The scripts here validate the JSON before writing to the registry, so a bad paste fails the script rather than breaking the policy on the endpoint. That's the right behavior for a security control - but it means you should monitor your detection results. If you see devices flipping between compliant and non-compliant unexpectedly, check the VS Code Window log (`Ctrl+Shift+P` → **Show Window Log**) on a sample device for parse errors.

**2. Side-loaded .vsix files bypass this.** A determined user can install extensions via `code --install-extension --force` against a local `.vsix`. The policy disables them after the fact, but doesn't prevent the install. If that's in your threat model, layer WDAC or AppLocker on top.

**3. Devices on VS Code <1.96 show as compliant but aren't enforced yet.** The policy is in the registry waiting for the upgrade, but until then the device isn't actually protected. Pair this with an Intune compliance policy that requires VS Code 1.96+ if you need real enforcement coverage today rather than at upgrade time.

**4. Hybrid GPO + Intune.** If a device gets the same policy from both, the remediation will overwrite the GPO value on next run. Decide which is authoritative before flipping this on broadly.

## Related policies worth setting

Same registry hive, same approach. Useful for the AI/agent attack surface:

- `ChatMCP` (DWORD = 0) - disables MCP integration in chat
- `ChatToolsAutoApprove` (DWORD = 0) - prevents tool auto-approval ("YOLO mode")
- `ChatAgentMode` (DWORD = 0) - disables agent mode entirely
- `ChatAgentExtensionTools` (DWORD = 0) - blocks tools contributed by third-party extensions

The full enterprise policy reference is in the links below.

## References

- [VS Code: Manage extensions in enterprise environments](https://code.visualstudio.com/docs/enterprise/extensions)
- [VS Code: Centrally manage settings with policies](https://code.visualstudio.com/docs/enterprise/policies)
- [VS Code: Enterprise overview](https://code.visualstudio.com/docs/enterprise/overview)
- [Microsoft Intune: Remediations](https://learn.microsoft.com/en-us/mem/intune/fundamentals/remediations)
