// ==UserScript==
// @name         KoC Slaying Competition Tracker
// @namespace    trevo88423
// @version      2.9.0
// @description  Track Attack Missions and Gold Stolen for slaying competitions
// @author       Blackheart
// @match        https://www.kingsofchaos.com/*
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
  const COMP_KEY = "KoC_CompSettings";
  const STATS_KEY_PREFIX = "KoC_CompStats"; // Cache stats across pages (per competition)

  console.log("✅ Slaying Competition Tracker v2.9.0 loaded");

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

  function getCompSettings() {
    try { return JSON.parse(localStorage.getItem(COMP_KEY) || "{}"); }
    catch { return {}; }
  }

  function saveCompSettings(settings) {
    localStorage.setItem(COMP_KEY, JSON.stringify(settings));
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

  function clearOldCompStats(currentCompId) {
    // Clear all old competition stats from localStorage
    const keys = Object.keys(localStorage);
    for (const key of keys) {
      if (key.startsWith(STATS_KEY_PREFIX) && !key.endsWith(`_${currentCompId}`)) {
        console.log(`🗑️ Clearing old stats cache: ${key}`);
        localStorage.removeItem(key);
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
        "Authorization": "Bearer " + token
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
  // === Active Competition ===
  // ========================

  let activeCompetition = null;
  let myEntry = null;

  async function loadActiveCompetition() {
    const comp = await apiCall("competitions/active");
    if (comp) {
      activeCompetition = comp;
      console.log("📊 Active competition:", comp.name);

      // Clear old competition stats from localStorage
      clearOldCompStats(comp.id);

      // Load my entry
      myEntry = await apiCall(`competitions/${comp.id}/my-entry`);
      console.log("📊 My entry:", myEntry);

      return true;
    }
    return false;
  }

  // ========================
  // === Submit Stats ===
  // ========================

  async function submitStats() {
    if (!activeCompetition) return;

    const settings = getCompSettings();

    // Check if we're enabled
    if (settings.enabled === false) {
      console.log("⏸️ Competition tracking disabled by user");
      return;
    }

    const stats = extractCurrentStats(activeCompetition.id);

    // Only require attack missions for submission
    if (stats.attackMissions === null) {
      console.warn("⚠️ Could not extract Attack Missions - visit rewards.php first");
      return;
    }

    console.log("📊 Submitting stats:", stats);

    const result = await apiCall(
      `competitions/${activeCompetition.id}/entries`,
      "POST",
      stats
    );

    if (result) {
      console.log("✅ Stats submitted successfully");
      myEntry = result;
    }
  }

  // ========================
  // === Toggle Control ===
  // ========================

  async function toggleParticipation(enabled) {
    if (!activeCompetition) return;

    const settings = getCompSettings();
    settings.enabled = enabled;
    saveCompSettings(settings);

    // If we have an entry, update it on the server
    if (myEntry) {
      await apiCall(
        `competitions/${activeCompetition.id}/toggle`,
        "POST",
        { enabled }
      );
    }

    console.log(`${enabled ? '▶️' : '⏸️'} Competition tracking ${enabled ? 'enabled' : 'disabled'}`);
  }

  // ========================
  // === Leaderboard Display ===
  // ========================

  async function showLeaderboard() {
    if (!activeCompetition) {
      alert("No active competition");
      return;
    }

    const leaderboard = await apiCall(`competitions/${activeCompetition.id}/leaderboard`);
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
    title.textContent = `🏆 ${activeCompetition.name}`;
    title.style.marginTop = '0';
    title.style.color = 'gold';
    title.style.textAlign = 'center';

    const subtitle = document.createElement('p');
    subtitle.style.textAlign = 'center';
    subtitle.style.color = '#999';

    // Format dates with timezone info
    const startDate = new Date(activeCompetition.start_date);
    const endDate = new Date(activeCompetition.end_date);
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

  function addCompetitionPanel() {
    if (!activeCompetition) return;

    const infoRow = document.querySelector("a[href='info.php']")?.closest("tr");
    if (!infoRow) return;

    const settings = getCompSettings();
    const isEnabled = settings.enabled !== false;

    // Check if panel is minimized
    const isMinimized = localStorage.getItem("KoC_CompPanelMinimized") === "true";

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
          <span style="color:gold; font-size:12px;">🏆 Competition</span>
          <button id="comp-expand-btn" style="margin-left:auto; padding:4px 12px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px; font-size:11px;">
            ▼ Show Panel
          </button>
        </div>
      `;

      panel.appendChild(cell);
      infoRow.parentNode.insertBefore(panel, infoRow.nextSibling);

      document.getElementById("comp-expand-btn")?.addEventListener("click", () => {
        localStorage.setItem("KoC_CompPanelMinimized", "false");
        location.reload();
      });
      return;
    }

    // Full panel view
    // Use UTC timestamps for accurate comparison across timezones
    const nowUTC = Date.now(); // UTC timestamp
    const startDate = new Date(activeCompetition.start_date);
    const endDate = new Date(activeCompetition.end_date);
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

    const cached = getCompStats(activeCompetition.id);
    const hasAttackData = cached.attackMissions !== undefined;
    const lastUpdate = cached.lastUpdate ? new Date(cached.lastUpdate).toLocaleTimeString() : 'Never';

    // Calculate current progress using FRESH localStorage data
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
          🏆 ${activeCompetition.name}
        </div>
        <button id="comp-minimize-btn" style="padding:2px 8px; cursor:pointer; background:#555; color:white; border:none; border-radius:3px; font-size:10px;">
          ▲ Hide
        </button>
      </div>
      <div style="color:#999; font-size:11px; margin-bottom:8px;">
        ${statusText}
      </div>
      <div style="display:flex; gap:8px; margin-bottom:8px;">
        <button id="comp-toggle-btn" style="flex:1; padding:6px; cursor:pointer; background:${isEnabled ? '#4CAF50' : '#f44336'}; color:white; border:none; border-radius:4px;">
          ${isEnabled ? '▶️ Tracking is ON' : '⏸️ Tracking is OFF'}
        </button>
        <button id="comp-update-btn" style="flex:1; padding:6px; cursor:pointer; background:#FF9800; color:white; border:none; border-radius:4px;">
          🔄 Update Stats
        </button>
        <button id="comp-leaderboard-btn" style="flex:1; padding:6px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px;">
          📊 Leaderboard
        </button>
      </div>
      ${attacksDisplay}
    `;

    panel.appendChild(cell);
    infoRow.parentNode.insertBefore(panel, infoRow.nextSibling);

    // Add event listeners
    document.getElementById("comp-minimize-btn")?.addEventListener("click", () => {
      localStorage.setItem("KoC_CompPanelMinimized", "true");
      location.reload();
    });

    document.getElementById("comp-toggle-btn")?.addEventListener("click", async () => {
      const newState = !isEnabled;
      await toggleParticipation(newState);
      location.reload();
    });

    document.getElementById("comp-update-btn")?.addEventListener("click", () => {
      if (!activeCompetition) return;

      // Capture gold data from current page (base.php) before leaving
      const goldStolen = extractGoldStolen();
      if (goldStolen !== null) {
        const cached = getCompStats(activeCompetition.id);
        cached.goldStolenEra = goldStolen;
        cached.lastUpdate = Date.now();
        saveCompStats(activeCompetition.id, cached);
        console.log("📊 Gold Stolen captured before redirect:", goldStolen);
      }

      // Go to rewards.php to capture attack missions (user navigates back manually)
      window.location.href = "rewards.php";
    });

    document.getElementById("comp-leaderboard-btn")?.addEventListener("click", async () => {
      // Force a fresh submission before showing leaderboard to ensure latest data is shown
      const settings = getCompSettings();
      if (settings.enabled !== false) {
        const cached = getCompStats(activeCompetition.id);
        if (cached.attackMissions) {
          console.log("📊 Submitting fresh stats before showing leaderboard...");
          await submitStats();
          localStorage.setItem("KoC_CompLastSubmit", Date.now().toString());
        }
      }
      await showLeaderboard();
    });
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

    const hasComp = await loadActiveCompetition();
    if (!hasComp) {
      console.log("ℹ️ No active competition");
      return;
    }

    // Collect stats from specific pages
    if (isRewardsPage) {
      const attackMissions = extractAttackMissions();
      if (attackMissions !== null) {
        const cached = getCompStats(activeCompetition.id);
        cached.attackMissions = attackMissions;
        cached.lastUpdate = Date.now();
        saveCompStats(activeCompetition.id, cached);
        console.log("📊 Attack Missions captured:", attackMissions);
        console.log("✅ Stats updated! Navigate back to base.php manually.");
      }
    }

    if (isBasePage) {
      const goldStolen = extractGoldStolen();
      if (goldStolen !== null) {
        const cached = getCompStats(activeCompetition.id);
        cached.goldStolenEra = goldStolen;
        cached.lastUpdate = Date.now();
        saveCompStats(activeCompetition.id, cached);
        console.log("📊 Gold Stolen captured:", goldStolen);
      }

      // Add panel on base page
      addCompetitionPanel();

      // Submit stats if enabled and we have the required data
      const settings = getCompSettings();
      if (settings.enabled !== false) {
        const cached = getCompStats(activeCompetition.id);

        // Only submit if we have attack missions data
        if (cached.attackMissions) {
          // Throttle submissions (max once per 5 minutes)
          const lastSubmit = parseInt(localStorage.getItem("KoC_CompLastSubmit") || "0");
          const now = Date.now();
          if (now - lastSubmit > 5 * 60 * 1000) {
            await submitStats();
            localStorage.setItem("KoC_CompLastSubmit", now.toString());
          }
        } else {
          console.log("ℹ️ Visit rewards.php to capture Attack Missions data");
        }
      }
    }
  })();

})();
