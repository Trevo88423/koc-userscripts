# Version Control Setup for KoC Userscripts

## Initial Setup (One-Time)

### 1. Run Database Migration

This creates the `script_versions` table:

```bash
cd /c/Projects/koc-roster-api
npm run migrate
```

## Managing Script Versions

### Current Scripts with Version Control

- **koc-data-centre** (KoC Data Centre) - v1.26.0

### Setting Version Requirements

Use this API call to update version requirements:

```bash
curl -X POST https://koc-roster-api-production.up.railway.app/script-version/update \
  -H "Content-Type: application/json" \
  -d '{
    "scriptName": "koc-data-centre",
    "minVersion": "1.26.0",
    "latestVersion": "1.26.0",
    "updateUrl": "https://github.com/Trevo88423/koc-userscripts",
    "blockingEnabled": false,
    "blockingMessage": "Your script is outdated. Please update for bug fixes and new features."
  }'
```

### When You Release a New Version

#### Scenario 1: Bug Fix (Block Old Version)

Found a critical bug in v1.26.0, releasing v1.27.0:

```bash
curl -X POST https://koc-roster-api-production.up.railway.app/script-version/update \
  -H "Content-Type: application/json" \
  -d '{
    "scriptName": "koc-data-centre",
    "minVersion": "1.27.0",
    "latestVersion": "1.27.0",
    "updateUrl": "https://github.com/Trevo88423/koc-userscripts",
    "blockingEnabled": true,
    "blockingMessage": "Critical bug fixed in v1.27.0. Previous versions may cause issues. Please update immediately."
  }'
```

#### Scenario 2: New Features (Don't Block Old Version)

Released v1.28.0 with new features, but v1.27.0 still works fine:

```bash
curl -X POST https://koc-roster-api-production.up.railway.app/script-version/update \
  -H "Content-Type: application/json" \
  -d '{
    "scriptName": "koc-data-centre",
    "minVersion": "1.27.0",
    "latestVersion": "1.28.0",
    "updateUrl": "https://github.com/Trevo88423/koc-userscripts",
    "blockingEnabled": false,
    "blockingMessage": "New features available in v1.28.0!"
  }'
```

### Checking Current Configuration

```bash
# See all script version configs
curl https://koc-roster-api-production.up.railway.app/script-version/all
```

### Emergency: Disable All Versions

If something breaks and you need to kill-switch the script:

```bash
curl -X POST https://koc-roster-api-production.up.railway.app/script-version/update \
  -H "Content-Type: application/json" \
  -d '{
    "scriptName": "koc-data-centre",
    "minVersion": "999.0.0",
    "latestVersion": "999.0.0",
    "updateUrl": "https://github.com/Trevo88423/koc-userscripts",
    "blockingEnabled": true,
    "blockingMessage": "This script is temporarily disabled due to game API changes. Check GitHub for updates."
  }'
```

## Adding Version Control to Other Scripts

To add version control to another userscript:

### 1. Add Version Check Code

Add this after the security check in your userscript:

```javascript
// ==================== VERSION CHECK ====================
const SCRIPT_NAME = 'your-script-name'; // Use kebab-case
const SCRIPT_VERSION = '1.0.0'; // Match @version in metadata
const VERSION_CHECK_API = 'https://koc-roster-api-production.up.railway.app';

async function checkScriptVersion() {
  try {
    const response = await fetch(`${VERSION_CHECK_API}/script-version/check/${SCRIPT_NAME}/${SCRIPT_VERSION}`);
    const data = await response.json();

    if (!data.allowed) {
      // Version is blocked - show error and stop script
      const errorDiv = document.createElement('div');
      errorDiv.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: #d32f2f;
        color: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        z-index: 99999;
        max-width: 500px;
        font-family: Arial, sans-serif;
      `;

      errorDiv.innerHTML = `
        <h3 style="margin: 0 0 10px 0;">⚠️ Script Version Outdated</h3>
        <p style="margin: 0 0 10px 0;">${data.message}</p>
        <p style="margin: 0 0 10px 0;">
          <strong>Your version:</strong> ${data.currentVersion}<br>
          <strong>Minimum required:</strong> ${data.minVersion}<br>
          <strong>Latest version:</strong> ${data.latestVersion}
        </p>
        <a href="${data.updateUrl}" target="_blank" style="
          display: inline-block;
          background: white;
          color: #d32f2f;
          padding: 10px 20px;
          text-decoration: none;
          border-radius: 4px;
          font-weight: bold;
        ">Update Now</a>
      `;

      document.body.appendChild(errorDiv);
      console.error(`[${SCRIPT_NAME}] Version ${SCRIPT_VERSION} is blocked. Please update.`);
      throw new Error('Script version blocked');
    }

    // If not latest, show non-blocking warning
    if (!data.isLatest) {
      console.warn(`[${SCRIPT_NAME}] A newer version (${data.latestVersion}) is available. Current: ${SCRIPT_VERSION}`);
      console.warn(`Update at: ${data.updateUrl}`);
    }

  } catch (error) {
    // If version check fails, allow script to continue (fail-open)
    if (error.message !== 'Script version blocked') {
      console.warn(`[${SCRIPT_NAME}] Version check failed:`, error.message);
    } else {
      throw error;
    }
  }
}

// Run version check before continuing
await checkScriptVersion();
```

### 2. Make Main Function Async

Change:
```javascript
(function() {
```

To:
```javascript
(async function() {
```

### 3. Register the Script

```bash
curl -X POST https://koc-roster-api-production.up.railway.app/script-version/update \
  -H "Content-Type: application/json" \
  -d '{
    "scriptName": "your-script-name",
    "minVersion": "1.0.0",
    "latestVersion": "1.0.0",
    "updateUrl": "https://github.com/Trevo88423/koc-userscripts",
    "blockingEnabled": false,
    "blockingMessage": "Your script is outdated. Please update."
  }'
```

## Quick Reference

### Enable Blocking
```bash
# Set blockingEnabled to true and update minVersion
"blockingEnabled": true
```

### Disable Blocking
```bash
# Set blockingEnabled to false
"blockingEnabled": false
```

### Version Format
Always use semantic versioning: `MAJOR.MINOR.PATCH`
- `1.2.3` = Major.Minor.Patch
- Increment MAJOR for breaking changes
- Increment MINOR for new features
- Increment PATCH for bug fixes

## Testing

1. Update script version in code
2. Set version requirement via API
3. Reload KoC page
4. Check console for version check messages
5. Try setting `minVersion` higher than your script version to test blocking

## Troubleshooting

### "Version check failed"
- API might be down (script continues anyway - fail-open design)
- Check API URL is correct
- Check network tab in browser dev tools

### Script still runs with old version
- Check `blockingEnabled` is `true`
- Verify script name matches exactly (case-sensitive)
- Clear browser cache and reload
- Check browser console for errors

### Users not seeing update prompt
- They need to reload the page
- Old cached version might still be running
- Check Tampermonkey/Greasemonkey updated the script
