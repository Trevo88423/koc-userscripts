// ==UserScript==
// @name         KoC Slaying Competition Tracker
// @namespace    trevo88423
// @version      2.13.2
// @description  Track Attack Missions and Gold Stolen for slaying competitions (supports multiple concurrent competitions)
// @author       Blackheart
// @match        https://www.kingsofchaos.com/base.php*
// @match        https://*.kingsofchaos.com/base.php*
// @match        https://www.kingsofchaos.com/rewards.php*
// @match        https://*.kingsofchaos.com/rewards.php*
// @icon         https://www.kingsofchaos.com/favicon.ico
// @grant        none
// @updateURL    https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-SlayingComp.user.js
// @downloadURL  https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-SlayingComp.user.js
// ==/UserScript==

(function() {
  'use strict';

  // ⚠️ SECURITY: Don't run on login/security pages or when logged out
  if (location.pathname.includes("login.php") ||
      location.pathname.includes("security.php") ||
      !document.querySelector("a[href='logout.php']")) {
    console.log("❌ DataCentre disabled (security page or not logged in)");
    return;
  }


  const API_URL = "https://koc-roster-api-production.up.railway.app";
  const TOKEN_KEY = "KoC_SRAUTH";
  const COMP_SETTINGS_PREFIX = "KoC_CompSettings"; // Per-competition settings
  const STATS_KEY_PREFIX = "KoC_CompStats"; // Cache stats across pages (per competition)
  const LAST_SUBMIT_PREFIX = "KoC_CompLastSubmit"; // Per-competition submission tracking

  console.log("✅ Slaying Competition Tracker v2.13.2 loaded");

  // ========================
  // === Auth Management  ===
  // ========================

  function getStoredAuth() {
    try { return JSON.parse(localStorage.getItem(TOKEN_KEY) || "null"); }
    catch { return null; }
  }

  async function getValidToken() {
    const auth = getStoredAuth();
    if (!auth || Date.now() > auth.expiry) return null;
    return auth.token;
  }

  // ========================
  // === Competition Settings ===
  // ========================

  function getCompSettings(competitionId) {
    if (!competitionId) return {};
    const key = `${COMP_SETTINGS_PREFIX}_${competitionId}`;
    try { return JSON.parse(localStorage.getItem(key) || "{}"); }
    catch { return {}; }
  }

  function saveCompSettings(competitionId, settings) {
    if (!competitionId) return;
    const key = `${COMP_SETTINGS_PREFIX}_${competitionId}`;
    localStorage.setItem(key, JSON.stringify(settings));
  }

  function getCompStats(competitionId) {
    if (!competitionId) return {};
    const key = `${STATS_KEY_PREFIX}_${competitionId}`;
    try { return JSON.parse(localStorage.getItem(key) || "{}"); }
    catch { return {}; }
  }

  function saveCompStats(competitionId, stats) {
    if (!competitionId) return;
    const key = `${STATS_KEY_PREFIX}_${competitionId}`;
    localStorage.setItem(key, JSON.stringify(stats));
  }

  function clearOldCompData(activeCompIds) {
    // Clear stats, settings, and submission tracking for competitions not in activeCompIds
    const keys = Object.keys(localStorage);
    const activeIdSet = new Set(activeCompIds.map(id => String(id)));

    for (const key of keys) {
      // Check if it's a competition-related key
      if (key.startsWith(STATS_KEY_PREFIX) ||
          key.startsWith(COMP_SETTINGS_PREFIX) ||
          key.startsWith(LAST_SUBMIT_PREFIX)) {

        // Extract competition ID from key
        const parts = key.split('_');
        const compId = parts[parts.length - 1];

        // If this competition is not in the active list, remove it
        if (!activeIdSet.has(compId)) {
          console.log(`🗑️ Clearing old competition data: ${key}`);
          localStorage.removeItem(key);
        }
      }
    }
  }

  // ========================
  // === API Communication ===
  // ========================

  async function apiCall(endpoint, method = "GET", data = null) {
    const token = await getValidToken();
    if (!token) {
      console.warn("⚠️ No valid token for competition API call");
      return null;
    }

    const options = {
      method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
        "X-Script-Name": "koc-slaying-comp-tracker",
        "X-Script-Version": "2.13.2"
      }
    };

    if (data && method !== "GET") {
      options.body = JSON.stringify(data);
    }

    try {
      const resp = await fetch(`${API_URL}/${endpoint}`, options);
      if (!resp.ok) {
        console.error(`❌ API call failed: ${endpoint} (${resp.status})`);
        return null;
      }
      return await resp.json();
    } catch (err) {
      console.error(`❌ API call error: ${endpoint}`, err);
      return null;
    }
  }

  // ========================
  // === Stat Extraction ===
  // ========================

  function getSidebarValue(label) {
    const el = [...document.querySelectorAll("td")].find(td =>
      td.innerText.trim().startsWith(label)
    );
    if (!el) return null;
    const parts = el.innerText.split(":");
    if (parts.length < 2) return null;
    const numStr = parts[1].replace(/[(),]/g, "").trim();
    return parseInt(numStr, 10) || null;
  }

  function extractAttackMissions() {
    // Look for "Attack Missions" on rewards.php in the "Your Actions" table
    // Target the specific <td align="left"> element containing "Attack Missions"
    const cells = document.querySelectorAll('td[align="left"]');

    for (const cell of cells) {
      if (cell.textContent.includes('Attack Missions')) {
        // Find the <font color="goldenrod"> element within this cell
        const font = cell.querySelector('font[color="goldenrod"]');
        if (font) {
          // Extract the number before the "/" (e.g., "2166/100" → 2166)
          const match = font.textContent.match(/^(\d+)\//);
          if (match) {
            return parseInt(match[1], 10);
          }
        }
      }
    }
    return null;
  }

  function extractGoldStolen() {
    // Look for "Gold Stolen By You This Era" on base.php
    const rows = [...document.querySelectorAll("tr")];
    for (const row of rows) {
      const text = row.innerText;
      if (text.includes("Gold Stolen By You This Era")) {
        // Extract the number (with commas)
        const match = text.match(/Gold Stolen By You This Era\s+([\d,]+)/);
        if (match) {
          return parseInt(match[1].replace(/,/g, ""), 10);
        }
      }
    }
    return null;
  }

  function extractCurrentStats(competitionId) {
    const cached = getCompStats(competitionId);

    const experience = getSidebarValue("Experience");
    const turns = getSidebarValue("Turns");
    const gold = getSidebarValue("Gold");

    // Try to get from current page
    let attackMissions = extractAttackMissions();
    let goldStolenEra = extractGoldStolen();

    // If not found on current page, use cached values
    if (attackMissions === null) attackMissions = cached.attackMissions || null;
    if (goldStolenEra === null) goldStolenEra = cached.goldStolenEra || null;

    // Update cache if we found new values
    if (attackMissions !== null || goldStolenEra !== null) {
      saveCompStats(competitionId, {
        attackMissions: attackMissions !== null ? attackMissions : cached.attackMissions,
        goldStolenEra: goldStolenEra !== null ? goldStolenEra : cached.goldStolenEra,
        lastUpdate: Date.now()
      });
    }

    return { experience, turns, gold, attackMissions, goldStolenEra };
  }

  // ========================
  // === Active Competitions ===
  // ========================

  let activeCompetitions = [];
  let myEntries = new Map(); // competitionId -> entry data

  async function loadActiveCompetitions() {
    // Fetch all active competitions (API returns array)
    const comps = await apiCall("competitions/active");
    if (!comps || (Array.isArray(comps) && comps.length === 0)) {
      console.log("ℹ️ No active competitions");
      return false;
    }

    // Handle both single object (old API) and array (new API) responses
    activeCompetitions = Array.isArray(comps) ? comps : [comps];
    console.log(`📊 ${activeCompetitions.length} active competition(s) found`);

    // Clear old competition data from localStorage
    const activeIds = activeCompetitions.map(c => c.id);
    clearOldCompData(activeIds);

    // Load entries for each competition
    for (const comp of activeCompetitions) {
      console.log(`📊 Loading: ${comp.name}`);
      const entry = await apiCall(`competitions/${comp.id}/my-entry`);
      if (entry) {
        myEntries.set(comp.id, entry);
      }
    }

    return activeCompetitions.length > 0;
  }

  // ========================
  // === Submit Stats ===
  // ========================

  async function submitStats(competition) {
    if (!competition) return;

    const settings = getCompSettings(competition.id);

    // Check if we're enabled
    if (settings.enabled === false) {
      console.log(`⏸️ Competition tracking disabled for: ${competition.name}`);
      return;
    }

    const stats = extractCurrentStats(competition.id);

    // Only require attack missions for submission
    if (stats.attackMissions === null) {
      console.warn(`⚠️ Could not extract Attack Missions for: ${competition.name}`);
      return;
    }

    console.log(`📊 Submitting stats for ${competition.name}:`, stats);

    const result = await apiCall(
      `competitions/${competition.id}/entries`,
      "POST",
      stats
    );

    if (result) {
      console.log(`✅ Stats submitted successfully for: ${competition.name}`);
      myEntries.set(competition.id, result);
    }
  }

  async function submitAllStats() {
    // Submit stats for all active competitions
    for (const comp of activeCompetitions) {
      await submitStats(comp);
    }
  }

  // ========================
  // === Toggle Control ===
  // ========================

  async function toggleParticipation(competition, enabled) {
    if (!competition) return;

    const settings = getCompSettings(competition.id);
    settings.enabled = enabled;
    saveCompSettings(competition.id, settings);

    // If we have an entry, update it on the server
    const entry = myEntries.get(competition.id);
    if (entry) {
      await apiCall(
        `competitions/${competition.id}/toggle`,
        "POST",
        { enabled }
      );
    }

    console.log(`${enabled ? '▶️' : '⏸️'} ${competition.name} tracking ${enabled ? 'enabled' : 'disabled'}`);
  }

  // ========================
  // === Leaderboard Display ===
  // ========================

  async function showLeaderboard(competition) {
    if (!competition) {
      alert("No competition specified");
      return;
    }

    const leaderboard = await apiCall(`competitions/${competition.id}/leaderboard`);
    if (!leaderboard) {
      alert("Failed to load leaderboard");
      return;
    }

    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.id = 'comp-leaderboard-overlay';
    Object.assign(overlay.style, {
      position: 'fixed',
      top: '0', left: '0',
      width: '100%', height: '100%',
      backgroundColor: 'rgba(0,0,0,0.8)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: '9999'
    });

    const modal = document.createElement('div');
    Object.assign(modal.style, {
      background: '#1a1a1a',
      color: '#fff',
      padding: '20px',
      border: '2px solid #666',
      borderRadius: '8px',
      width: '90%',
      maxWidth: '800px',
      maxHeight: '80%',
      overflow: 'auto',
      position: 'relative'
    });

    const closeBtn = document.createElement('span');
    closeBtn.textContent = '×';
    Object.assign(closeBtn.style, {
      position: 'absolute',
      top: '10px', right: '15px',
      cursor: 'pointer',
      fontSize: '30px',
      color: '#999'
    });
    closeBtn.onclick = () => overlay.remove();

    const title = document.createElement('h2');
    title.textContent = `🏆 ${competition.name}`;
    title.style.marginTop = '0';
    title.style.color = 'gold';
    title.style.textAlign = 'center';

    const subtitle = document.createElement('p');
    subtitle.style.textAlign = 'center';
    subtitle.style.color = '#999';

    // Format dates with timezone info
    const startDate = new Date(competition.start_date);
    const endDate = new Date(competition.end_date);
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    subtitle.innerHTML = `
      Start: ${startDate.toLocaleString('en-US', { timeZone })} (${timeZone})<br>
      End: ${endDate.toLocaleString('en-US', { timeZone })} (${timeZone})
    `;

    // Build leaderboard table
    const table = document.createElement('table');
    table.style.width = '100%';
    table.style.borderCollapse = 'collapse';
    table.style.marginTop = '20px';

    const formatNum = (n) => {
      const num = Number(n) || 0;
      if (num >= 1e12) return (num / 1e12).toFixed(2) + 'T';
      if (num >= 1e9) return (num / 1e9).toFixed(2) + 'B';
      if (num >= 1e6) return (num / 1e6).toFixed(2) + 'M';
      if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
      return num.toLocaleString();
    };

    let tableHTML = `
      <thead>
        <tr style="background:#222; color:#6f6;">
          <th style="padding:8px; border:1px solid #444;">Rank</th>
          <th style="padding:8px; border:1px solid #444;">Player</th>
          <th style="padding:8px; border:1px solid #444;">⚔️ Attacks</th>
          <th style="padding:8px; border:1px solid #444;">💰 Gold Stolen</th>
          <th style="padding:8px; border:1px solid #444;">📊 Avg Gold/Attack</th>
        </tr>
      </thead>
      <tbody>
    `;

    leaderboard.forEach((entry, idx) => {
      const isMe = entry.player_id === getStoredAuth()?.id;
      const bgColor = isMe ? '#2a2a00' : (idx % 2 === 0 ? '#111' : '#1a1a1a');
      const rankColor = idx === 0 ? 'gold' : idx === 1 ? 'silver' : idx === 2 ? '#cd7f32' : '#999';
      const currentMedal = idx === 0 ? ' 🥇' : idx === 1 ? ' 🥈' : idx === 2 ? ' 🥉' : '';
      const permanentRibbons = entry.ribbons ? ` ${entry.ribbons}` : '';

      tableHTML += `
        <tr style="background:${bgColor};">
          <td style="padding:8px; border:1px solid #444; color:${rankColor}; font-weight:bold; text-align:center;">${idx + 1}</td>
          <td style="padding:8px; border:1px solid #444;">
            ${isMe ? '<strong>' : ''}
            ${entry.player_name || 'Unknown'}${currentMedal}${permanentRibbons}
            ${isMe ? '</strong>' : ''}
            ${!entry.enabled ? ' <span style="color:#999;">(hidden)</span>' : ''}
          </td>
          <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.attacks_completed)}</td>
          <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.gold_stolen)}</td>
          <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.avg_gold_per_attack)}</td>
        </tr>
      `;
    });

    tableHTML += '</tbody>';
    table.innerHTML = tableHTML;

    modal.appendChild(closeBtn);
    modal.appendChild(title);
    modal.appendChild(subtitle);
    modal.appendChild(table);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  }

  // ========================
  // === UI Controls ===
  // ========================

  function addCompetitionPanel(competition, insertAfter) {
    if (!competition) return null;

    const settings = getCompSettings(competition.id);
    const isEnabled = settings.enabled !== false;

    // Check if panel is minimized (per-competition)
    const minimizeKey = `KoC_CompPanelMinimized_${competition.id}`;
    const isMinimized = localStorage.getItem(minimizeKey) === "true";

    const panel = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 2;
    cell.style.padding = "10px";
    cell.style.background = "#1a1a1a";
    cell.style.borderTop = "2px solid gold";

    if (isMinimized) {
      // Minimized view - just show expand button
      cell.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="color:gold; font-size:12px;">🏆 ${competition.name}</span>
          <button class="comp-expand-btn" data-comp-id="${competition.id}" style="margin-left:auto; padding:4px 12px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px; font-size:11px;">
            ▼ Show Panel
          </button>
        </div>
      `;

      panel.appendChild(cell);
      insertAfter.parentNode.insertBefore(panel, insertAfter.nextSibling);

      const expandBtn = cell.querySelector(".comp-expand-btn");
      expandBtn?.addEventListener("click", () => {
        localStorage.setItem(minimizeKey, "false");
        location.reload();
      });
      return panel;
    }

    // Full panel view
    // Use UTC timestamps for accurate comparison across timezones
    const nowUTC = Date.now(); // UTC timestamp
    const startDate = new Date(competition.start_date);
    const endDate = new Date(competition.end_date);
    const startUTC = startDate.getTime(); // UTC timestamp
    const endUTC = endDate.getTime(); // UTC timestamp

    const hasStarted = nowUTC >= startUTC;
    const hasEnded = nowUTC > endUTC;

    // Get user's timezone for display
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    let statusText = "";
    if (!hasStarted) {
      const hoursUntilStart = Math.ceil((startUTC - nowUTC) / (1000 * 60 * 60));
      statusText = `⏳ Starts in ${hoursUntilStart} hours (${startDate.toLocaleString('en-US', { timeZone })})`;
    } else if (hasEnded) {
      statusText = `🏁 Competition Ended (${endDate.toLocaleString('en-US', { timeZone })})`;
    } else {
      const hoursUntilEnd = Math.ceil((endUTC - nowUTC) / (1000 * 60 * 60));
      statusText = `🔴 LIVE - Ends in ${hoursUntilEnd} hours (${endDate.toLocaleString('en-US', { timeZone })})`;
    }

    const cached = getCompStats(competition.id);
    const hasAttackData = cached.attackMissions !== undefined;
    const lastUpdate = cached.lastUpdate ? new Date(cached.lastUpdate).toLocaleTimeString() : 'Never';

    // Calculate current progress using FRESH localStorage data
    const myEntry = myEntries.get(competition.id);
    let attacksDisplay = '';
    if (myEntry && myEntry.baseline_attack_missions !== null && myEntry.baseline_attack_missions !== undefined) {
      // Use cached (localStorage) attacks if available, otherwise use server data
      const currentAttacks = cached.attackMissions || myEntry.current_attack_missions || 0;
      const attacksGained = currentAttacks - myEntry.baseline_attack_missions;
      attacksDisplay = `
        <div style="font-size:10px; color:#6f6;">
          ⚔️ Attacks: +${attacksGained} ${cached.attackMissions ? '📍' : ''}
          ${!hasAttackData ? ' <span style="color:#f44;">⚠️ Visit rewards.php</span>' : ''}
        </div>
        <div style="font-size:9px; color:#666; margin-top:4px;">
          Last captured: ${lastUpdate}
        </div>
      `;
    }

    cell.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
        <div style="color:gold; font-weight:bold;">
          🏆 ${competition.name}
        </div>
        <button class="comp-minimize-btn" data-comp-id="${competition.id}" style="padding:2px 8px; cursor:pointer; background:#555; color:white; border:none; border-radius:3px; font-size:10px;">
          ▲ Hide
        </button>
      </div>
      <div style="color:#999; font-size:11px; margin-bottom:8px;">
        ${statusText}
      </div>
      <div style="display:flex; gap:8px; margin-bottom:8px;">
        <button class="comp-toggle-btn" data-comp-id="${competition.id}" style="flex:1; padding:6px; cursor:pointer; background:${isEnabled ? '#4CAF50' : '#f44336'}; color:white; border:none; border-radius:4px;">
          ${isEnabled ? '▶️ Tracking is ON' : '⏸️ Tracking is OFF'}
        </button>
        <button class="comp-update-btn" data-comp-id="${competition.id}" style="flex:1; padding:6px; cursor:pointer; background:#FF9800; color:white; border:none; border-radius:4px;">
          🔄 Update Stats
        </button>
        <button class="comp-leaderboard-btn" data-comp-id="${competition.id}" style="flex:1; padding:6px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px;">
          📊 Leaderboard
        </button>
      </div>
      ${attacksDisplay}
    `;

    panel.appendChild(cell);
    insertAfter.parentNode.insertBefore(panel, insertAfter.nextSibling);

    // Add event listeners
    const minimizeBtn = cell.querySelector(".comp-minimize-btn");
    minimizeBtn?.addEventListener("click", () => {
      localStorage.setItem(minimizeKey, "true");
      location.reload();
    });

    const toggleBtn = cell.querySelector(".comp-toggle-btn");
    toggleBtn?.addEventListener("click", async () => {
      const newState = !isEnabled;
      await toggleParticipation(competition, newState);
      location.reload();
    });

    const updateBtn = cell.querySelector(".comp-update-btn");
    updateBtn?.addEventListener("click", () => {
      // Capture gold data from current page (base.php) before leaving
      const goldStolen = extractGoldStolen();
      if (goldStolen !== null) {
        const cached = getCompStats(competition.id);
        cached.goldStolenEra = goldStolen;
        cached.lastUpdate = Date.now();
        saveCompStats(competition.id, cached);
        console.log(`📊 Gold Stolen captured for ${competition.name}:`, goldStolen);
      }

      // Go to rewards.php to capture attack missions (user navigates back manually)
      window.location.href = "rewards.php";
    });

    const leaderboardBtn = cell.querySelector(".comp-leaderboard-btn");
    leaderboardBtn?.addEventListener("click", async () => {
      // Force a fresh submission before showing leaderboard to ensure latest data is shown
      const settings = getCompSettings(competition.id);
      if (settings.enabled !== false) {
        const cached = getCompStats(competition.id);
        if (cached.attackMissions) {
          console.log(`📊 Submitting fresh stats for ${competition.name}...`);
          await submitStats(competition);
          const submitKey = `${LAST_SUBMIT_PREFIX}_${competition.id}`;
          localStorage.setItem(submitKey, Date.now().toString());
        }
      }
      await showLeaderboard(competition);
    });

    return panel;
  }

  function addAllCompetitionPanels() {
    if (activeCompetitions.length === 0) return;

    const infoRow = document.querySelector("a[href='info.php']")?.closest("tr");
    if (!infoRow) return;

    // Insert panels one by one, each after the previous
    let insertAfter = infoRow;
    for (const comp of activeCompetitions) {
      const panel = addCompetitionPanel(comp, insertAfter);
      if (panel) {
        insertAfter = panel;
      }
    }
  }

  // ========================
  // === Initialization ===
  // ========================

  (async () => {
    // Only run on base.php and rewards.php
    const isBasePage = location.pathname.includes("base.php");
    const isRewardsPage = location.pathname.includes("rewards.php");

    if (!isBasePage && !isRewardsPage) {
      return; // Skip all other pages
    }

    const token = await getValidToken();
    if (!token) {
      console.warn("🔒 Slaying Comp disabled — not logged in");
      return;
    }

    const hasComps = await loadActiveCompetitions();
    if (!hasComps) {
      console.log("ℹ️ No active competitions");
      return;
    }

    // Collect stats from specific pages
    if (isRewardsPage) {
      const attackMissions = extractAttackMissions();
      if (attackMissions !== null) {
        // Update stats for ALL active competitions
        for (const comp of activeCompetitions) {
          const cached = getCompStats(comp.id);
          cached.attackMissions = attackMissions;
          cached.lastUpdate = Date.now();
          saveCompStats(comp.id, cached);
          console.log(`📊 Attack Missions captured for ${comp.name}:`, attackMissions);
        }
        console.log("✅ Stats updated! Navigate back to base.php manually.");
      }
    }

    if (isBasePage) {
      const goldStolen = extractGoldStolen();
      if (goldStolen !== null) {
        // Update gold stolen for ALL active competitions
        for (const comp of activeCompetitions) {
          const cached = getCompStats(comp.id);
          cached.goldStolenEra = goldStolen;
          cached.lastUpdate = Date.now();
          saveCompStats(comp.id, cached);
          console.log(`📊 Gold Stolen captured for ${comp.name}:`, goldStolen);
        }
      }

      // Add panels on base page for all competitions
      addAllCompetitionPanels();

      // Submit stats for each competition if enabled and we have the required data
      for (const comp of activeCompetitions) {
        const settings = getCompSettings(comp.id);
        if (settings.enabled !== false) {
          const cached = getCompStats(comp.id);

          // Only submit if we have attack missions data
          if (cached.attackMissions) {
            // Throttle submissions (max once per 5 minutes per competition)
            const submitKey = `${LAST_SUBMIT_PREFIX}_${comp.id}`;
            const lastSubmit = parseInt(localStorage.getItem(submitKey) || "0");
            const now = Date.now();
            if (now - lastSubmit > 5 * 60 * 1000) {
              await submitStats(comp);
              localStorage.setItem(submitKey, now.toString());
            }
          } else {
            console.log(`ℹ️ Visit rewards.php to capture Attack Missions data for ${comp.name}`);
          }
        }
      }
    }
  })();

})();
