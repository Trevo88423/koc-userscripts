// Backup script for KoC userscripts
// Run this before making changes: node backup-script.js

const fs = require('fs');
const path = require('path');

const BACKUP_DIR = '../Koc old versions';
const SCRIPTS_TO_BACKUP = [
  './userscripts/KoC-DataCentre.user.js',
  './userscripts/KoC-SlayingComp.user.js'
];

// Extract version from userscript header
function extractVersion(content) {
  const versionMatch = content.match(/@version\s+(\S+)/);
  return versionMatch ? versionMatch[1] : 'unknown';
}

// Create backup directory if it doesn't exist
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// Backup each script
SCRIPTS_TO_BACKUP.forEach(scriptPath => {
  if (fs.existsSync(scriptPath)) {
    const content = fs.readFileSync(scriptPath, 'utf8');
    const version = extractVersion(content);
    const scriptName = path.basename(scriptPath, '.user.js');
    const timestamp = new Date().toISOString().replace(/:/g, '-').slice(0, 19);

    // Backup with version number
    const backupName = `${scriptName}-${version}.user.js`;
    const backupPath = path.join(BACKUP_DIR, backupName);

    // Also create timestamped backup
    const timestampedName = `${scriptName}-${version}-${timestamp}.user.js`;
    const timestampedPath = path.join(BACKUP_DIR, timestampedName);

    fs.copyFileSync(scriptPath, backupPath);
    fs.copyFileSync(scriptPath, timestampedPath);

    console.log(`✅ Backed up ${scriptName} v${version}`);
    console.log(`   → ${backupName}`);
    console.log(`   → ${timestampedName}`);
  } else {
    console.log(`⚠️  Script not found: ${scriptPath}`);
  }
});

console.log(`\n📦 Backups saved to: ${path.resolve(BACKUP_DIR)}`);
