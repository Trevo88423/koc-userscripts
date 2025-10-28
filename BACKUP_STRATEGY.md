# Backup Strategy for KoC Userscripts

## Automatic Backups

### Before Making Changes
Always run the backup script first:
```bash
cd C:\Projects\koc-userscripts
node backup-script.js
```

This creates two backups:
1. **Version backup**: `KoC Data Centre-1.42.6.user.js` (overwrites previous version)
2. **Timestamped backup**: `KoC Data Centre-1.42.6-2025-10-28T21-45-00.user.js` (never overwrites)

### Location
All backups are saved to: `C:\Projects\Koc old versions\`

## Git Tags for Releases

Tag important versions in git:
```bash
cd C:\Projects\koc-userscripts
git tag -a v1.42.6 -m "DataCentre v1.42.6 - Weapon aggregation"
git push origin v1.42.6
```

View all tagged versions:
```bash
git tag -l
```

Restore a tagged version:
```bash
git checkout v1.42.6
```

## Manual Backup Process

### When Installing a New Version in Tampermonkey:
1. Open Tampermonkey Dashboard
2. Click on the script → Export → Save to: `C:\Projects\Koc old versions\KoC Data Centre-[VERSION].user.js`
3. This gives you the ACTUAL running version (recommended!)

### Before Editing:
```bash
# Backup current version
node backup-script.js

# Make your changes
# ...

# Test changes
# ...

# Commit when satisfied
git add .
git commit -m "feat: Description of changes"
git push
```

## Recovery Process

### If Something Goes Wrong:

1. **Find the correct version:**
   ```bash
   ls "C:\Projects\Koc old versions\"
   ```

2. **Copy it back:**
   ```bash
   cp "C:\Projects\Koc old versions\KoC Data Centre-1.42.6.user.js" C:\Projects\koc-userscripts\userscripts\KoC-DataCentre.user.js
   ```

3. **Verify the version:**
   ```bash
   head -10 C:\Projects\koc-userscripts\userscripts\KoC-DataCentre.user.js
   ```

4. **Commit the recovery:**
   ```bash
   cd C:\Projects\koc-userscripts
   git add userscripts/KoC-DataCentre.user.js
   git commit -m "fix: Restore correct version from backup"
   git push --force-with-lease
   ```

## Best Practices

1. **Always backup before Claude Code edits** - Run `node backup-script.js`
2. **Export from Tampermonkey regularly** - This is your "ground truth" version
3. **Tag releases in git** - Makes it easy to find stable versions
4. **Keep timestamped backups** - Never delete these, disk space is cheap
5. **Check version numbers** - Always verify `@version` and `SCRIPT_VERSION` match

## Directory Structure

```
C:\Projects\
├── koc-userscripts\           # Main git repository
│   ├── userscripts\
│   │   └── KoC-DataCentre.user.js
│   └── backup-script.js
│
├── koc-roster-api\            # API + userscripts copy
│   └── userscripts\
│       └── KoC-DataCentre.user.js
│
└── Koc old versions\          # Backup directory
    ├── KoC Data Centre-1.42.6.user.js (latest version backup)
    ├── KoC Data Centre-1.42.6-2025-10-28T21-45-00.user.js (timestamped)
    ├── KoC Data Centre-1.42.5.user.js (previous version)
    └── ... (older versions)
```

## Automation Ideas

### Git Pre-commit Hook (optional)
Create `.git/hooks/pre-commit`:
```bash
#!/bin/sh
# Auto-backup before commit
node backup-script.js
git add "../Koc old versions"
```

### NPM Script
Add to `package.json`:
```json
{
  "scripts": {
    "backup": "node backup-script.js",
    "commit": "npm run backup && git add . && git commit"
  }
}
```

Then use:
```bash
npm run backup  # Manual backup
npm run commit  # Backup + commit in one step
```
