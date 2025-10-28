# Quick Start - Backup & Deploy

## Before Making ANY Changes

```bash
cd C:\Projects\koc-userscripts
npm run backup
```

This saves both version and timestamped backups to `C:\Projects\Koc old versions\`

## Making Changes with Claude Code

### Step 1: Backup First
```bash
npm run backup
```

### Step 2: Export from Tampermonkey (Recommended!)
1. Open Tampermonkey Dashboard
2. Click script name → Click again on script name in the editor
3. File → Save to: `C:\Projects\Koc old versions\KoC Data Centre-1.42.X.user.js`

**This is your source of truth!** Always export the actual running version.

### Step 3: Tell Claude Code the Correct File
```
Claude, I want to update the DataCentre script.
The current version is at: "C:\Projects\Koc old versions\KoC Data Centre-1.42.X.user.js"
Please read that file and make changes to it.
```

### Step 4: Review Changes
Check the diff before committing:
```bash
git diff userscripts/KoC-DataCentre.user.js
```

### Step 5: Commit & Deploy
```bash
git add .
git commit -m "feat: Description of what changed"
git push
```

Or use the shortcut:
```bash
npm run deploy
# This runs: backup → git add → git commit → git push
```

## Quick Commands

| Command | What It Does |
|---------|-------------|
| `npm run backup` | Create version + timestamped backup |
| `npm run list-backups` | Show all backups in old versions folder |
| `npm run list-tags` | Show all git tags (releases) |
| `git tag -a v1.42.6 -m "Message"` | Tag current version |
| `git push origin v1.42.6` | Push tag to GitHub |

## Recovery

If Claude Code worked on the wrong version:

```bash
# 1. Find your backup
npm run list-backups

# 2. Copy it back
cp "../Koc old versions/KoC Data Centre-1.42.6.user.js" userscripts/KoC-DataCentre.user.js

# 3. Verify version
head -10 userscripts/KoC-DataCentre.user.js

# 4. Push to git
git add userscripts/KoC-DataCentre.user.js
git commit -m "fix: Restore correct version from backup"
git push --force-with-lease
```

## Best Practice Workflow

```
┌─────────────────────────────────────┐
│ 1. Update script in Tampermonkey   │
│    (Test it works!)                 │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 2. Export from Tampermonkey         │
│    Save to: Koc old versions/       │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 3. npm run backup                   │
│    (Creates timestamped backup)     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 4. Copy to both repos:              │
│    - koc-userscripts/userscripts/   │
│    - koc-roster-api/userscripts/    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 5. git commit + push to both repos  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 6. (Optional) git tag for releases  │
│    git tag -a v1.42.6 -m "..."      │
└─────────────────────────────────────┘
```

## Pro Tips

1. **Always test in Tampermonkey first** before committing to git
2. **Export from Tampermonkey** regularly - it's your "ground truth"
3. **Timestamped backups never overwrite** - keep them all
4. **Tag major releases** with git tags for easy recovery
5. **Check version numbers** - `@version` and `SCRIPT_VERSION` must match
6. **When asking Claude Code** - always point to the correct file in "Koc old versions"
