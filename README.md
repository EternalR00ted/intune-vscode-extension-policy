# vscode-extension-lockdown

Lock down VS Code extensions on managed endpoints using Microsoft Intune.

Two PowerShell scripts (detection + remediation) that you drop into Intune Remediations. Paste your allowlist as JSON, deploy, done.

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

- `Detect-VSCodeExtensionPolicy.ps1` - checks if the policy on the endpoint matches your allowlist
- `Remediate-VSCodeExtensionPolicy.ps1` - applies it if it doesn't

Both scripts have a clearly marked JSON block at the top. That's the only thing you need to edit.

## Setup

### 1. Edit your allowlist

Open both scripts. At the top you'll see:

```powershell
# === PASTE YOUR ALLOWED EXTENSIONS JSON BELOW ===
$allowedJson = @"
{
  "microsoft": true,
  "github": true,
  ...
}
"@
# === END JSON ===
```

Replace the JSON with your own. The same JSON must be in both files - if they don't match, detection will always flag non-compliant and the remediation will run every cycle.

If you want a single source of truth, keep a separate `allowed-extensions.json` in the repo and paste from it into both scripts before each deploy.

### 2. JSON syntax

```
"publisher-name": true                          allow all from this publisher
"publisher-name": false                         block all from this publisher
"publisher.extension-id": true                  allow this specific extension
"publisher.extension-id": false                 block this specific extension
"publisher.extension-id": "stable"              only stable, no pre-release
"publisher.extension-id": ["1.2.3", "1.2.4"]    pin to specific versions
```

To grab an extension ID: in VS Code, right-click any extension in the sidebar and pick **Copy Extension ID**. Format is always `publisher.extension-name`.

### 3. Deploy in Intune

Intune admin center → **Devices** → **Remediations** → **Create script package**.

| Setting | Value |
|---|---|
| Detection script file | `Detect-VSCodeExtensionPolicy.ps1` |
| Remediation script file | `Remediate-VSCodeExtensionPolicy.ps1` |
| Run this script using the logged-on credentials | **No** (needs SYSTEM for HKLM\Policies) |
| Enforce script signature check | **No** (unless you sign internally) |
| Run script in 64-bit PowerShell | **Yes** |

Assign to a pilot group first. Daily schedule is reasonable for drift detection.

### 4. Verify

On a test endpoint:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\VSCode" | Select AllowedExtensions, UpdateMode
```

Then open VS Code → Extensions → search for something not on the list. Install button should be greyed out. Anything already installed that isn't allowed gets disabled with a notice.

## UpdateMode

The remediation script also sets `UpdateMode`, which controls VS Code's own update behavior:

- `start` - update on launch (default in this script)
- `none` - fully lock version, no updates
- `default` - normal auto-update behavior
- `manual` - user must manually check for updates

Change the `$updateMode` variable in the remediation script if you want something other than `start`.

## Things to be aware of

**Hybrid environments.** If a device gets the same policy from both GPO and Intune, the remediation will overwrite the GPO value on next run. Decide which is authoritative before flipping this on broadly.

**Side-loaded .vsix files.** A determined user can still install extensions via `code --install-extension --force` against a local `.vsix`. The policy disables them after the fact, but it doesn't prevent the install. If that's in your threat model, layer WDAC or AppLocker on top.

**Network egress.** Once your allowlist is stable, blocking `marketplace.visualstudio.com` for dev machines is a useful belt-and-suspenders control. GitHub Enterprise customers can also stand up a private VS Code marketplace and cut off the public one entirely.

**Related policies worth setting in the same hive.** Same registry path, same approach:

- `ChatMCP` (DWORD = 0) - disables MCP integration in chat
- `ChatToolsAutoApprove` (DWORD = 0) - prevents tool auto-approval
- `ChatAgentEnabled` (DWORD = 0) - gate agent mode entirely

Full reference: https://code.visualstudio.com/docs/enterprise/policies

## References

- VS Code enterprise policies: https://code.visualstudio.com/docs/enterprise/policies
- Managing extensions in enterprise environments: https://code.visualstudio.com/docs/enterprise/extensions
- Intune Remediations docs: https://learn.microsoft.com/en-us/mem/intune/fundamentals/remediations
