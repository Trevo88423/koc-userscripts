// ==UserScript==
// @name         KoC Data Centre
// @namespace    trevo88423
// @version      1.11.0
// @description  Sweet Revenge alliance tool: tracks stats, syncs to API, adds dashboards, XP→Turn calculator, mini Top Stats panel, and battlefield intelligence tracking.
// @author       Blackheart
// @match        https://www.kingsofchaos.com/*
// @icon         https://www.kingsofchaos.com/favicon.ico
// @grant        none
// @updateURL    https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js
// @downloadURL  https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js
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


  const ver = (typeof GM_info !== "undefined" && GM_info.script && GM_info.script.version)
              ? GM_info.script.version : "dev";
  console.log(`✅ DataCentre+XPTool v${ver} loaded on`, location.pathname);

  const API_URL  = "https://koc-roster-api-production.up.railway.app";
  const TOKEN_KEY = "KoC_SRAUTH"; // unified storage
  const TIV_KEY  = "KoC_DataCentre"; // local TIV logs
  const MAP_KEY  = "KoC_NameMap";    // cached player snapshots


   // ========================
  // === Auth Management  ===
  // ========================

  function getStoredAuth() {
    try { return JSON.parse(localStorage.getItem(TOKEN_KEY) || "null"); }
    catch { return null; }
  }

  function saveAuth(token, id, name) {
    localStorage.setItem(TOKEN_KEY, JSON.stringify({
      token, id, name,
      expiry: Date.now() + 12 * 60 * 60 * 1000 // 12h
    }));
  }

  async function getValidToken() {
    const auth = getStoredAuth();
    if (!auth) return null;

    if (Date.now() < auth.expiry) {
      return auth.token; // ✅ still valid
    }

    // 🔄 refresh silently
    try {
      console.log("🔄 Refreshing token for:", auth.id, auth.name);
      const resp = await fetch(`${API_URL}/auth/koc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: auth.id, name: auth.name })
      });
      if (!resp.ok) throw new Error("Refresh failed " + resp.status);
      const data = await resp.json();
      saveAuth(data.token || data.accessToken, auth.id, auth.name);
      console.log("🔄 Token refreshed automatically");
      return data.token || data.accessToken;
    } catch (err) {
      console.warn("⚠️ Auto refresh failed:", err);
      localStorage.removeItem(TOKEN_KEY);
      return null;
    }
  }

    async function loginSR() {
    try {
      let id = null, name = null;

      // --- Look specifically for the "Name" row in the User Info table ---
      const nameRow = [...document.querySelectorAll("tr")]
        .find(tr => tr.textContent.includes("Name"));
      if (nameRow) {
        const link = nameRow.querySelector("a[href*='stats.php?id=']");
        if (link) {
          id = link.href.match(/id=(\d+)/)?.[1];
          name = link.textContent.trim();
        }
      }

      // --- Fallback: first stats.php link ---
      if (!id || !name) {
        const link = document.querySelector("a[href*='stats.php?id=']");
        if (link) {
          id = link.href.match(/id=(\d+)/)?.[1];
          name = link.textContent.trim();
        }
      }

      // --- Final fallback: localStorage ---
      if (!id) id = localStorage.getItem("KoC_MyId");
      if (!name) name = localStorage.getItem("KoC_MyName");

      if (!id || !name) {
        throw new Error("Could not detect your KoC ID/Name on this page");
      }

      console.log("🔍 Attempting login with:", { id, name });

      const resp = await fetch(`${API_URL}/auth/koc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, name })
      });
      if (!resp.ok) throw new Error("Auth failed " + resp.status);

      const data = await resp.json();
      saveAuth(data.token || data.accessToken, id, name);

      alert("✅ SR Login successful! Refreshing…");
      location.reload();
    } catch (err) {
      console.error("Login failed", err);
      alert("❌ Login failed: " + err.message);
    }
  }

  function logoutSR() {
    localStorage.removeItem(TOKEN_KEY);
    alert("Logged out.");
    location.reload();
  }

  function showToken() {
    const auth = getStoredAuth();
    if (!auth) {
      alert("❌ No token stored.");
      return;
    }
    alert(`📜 Token Info:\n\nID: ${auth.id}\nName: ${auth.name}\nExpiry: ${new Date(auth.expiry).toLocaleString()}\n\nToken: ${auth.token.substring(0,40)}...`);
    console.log("📜 Full token object:", auth);
  }


  // ==================
  // === Gatekeeper ===
  // ==================
  (async () => {
    const token = await getValidToken();
    if (!token) {
      if (location.pathname.includes("base.php")) {
        const box = document.createElement("div");
        box.style = "padding:12px;background:#111;color:#fff;border:1px solid #555;margin:12px;font-family:Arial;";
        box.innerHTML = `
          <h2>🔒 KoC Data Centre Login</h2>
          <p>You must log in with SR to enable the script.</p>
          <button id="srLoginBtn" style="padding:6px 12px;cursor:pointer;">Login to SR</button>
          <button id="srShowTokenBtn" style="padding:6px 12px;margin-left:10px;cursor:pointer;">Show Token</button>
        `;
        document.body.prepend(box);

        document.getElementById("srLoginBtn").addEventListener("click", loginSR);
        document.getElementById("srShowTokenBtn").addEventListener("click", showToken);
      } else {
        console.warn("🔒 Data Centre disabled — not logged in.");
      }
      return;
    }
    console.log("✅ Authenticated with SR, continuing…");
  })();

  // =========================
  // === Storage Helpers   ===
  // =========================

  function getTivLog() {
    try { return JSON.parse(localStorage.getItem(TIV_KEY) || "[]"); }
    catch { return []; }
  }
  function saveTivLog(arr) { localStorage.setItem(TIV_KEY, JSON.stringify(arr)); }

  function getNameMap() {
    try { return JSON.parse(localStorage.getItem(MAP_KEY) || "{}"); }
    catch { return {}; }
  }
  function saveNameMap(map) { localStorage.setItem(MAP_KEY, JSON.stringify(map)); }

  // =========================
  // === API Communication ===
  // =========================

 async function sendToAPI(endpoint, data, retries = 2) {
  const auth = getStoredAuth();
  if (!auth || Date.now() > auth.expiry) {
    console.warn("⚠️ Skipping API send, no valid token");
    return;
  }

  console.log(`🌐 Preparing API call → ${endpoint}`, data);

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const resp = await fetch(`${API_URL}/${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + auth.token
        },
        body: JSON.stringify(data)
      });
      const json = await resp.json().catch(() => ({ error: "Invalid JSON" }));
      console.log(`🌐 API response from ${endpoint}:`, json);
      return json;
    } catch (err) {
      if (attempt === retries) {
        console.error(`❌ API call failed → ${endpoint} after ${retries} attempts`, err);
        return null;
      }
      const delay = 1000 * attempt; // 1s, 2s
      console.warn(`⚠️ Retry ${attempt}/${retries} in ${delay}ms...`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
}
  // =========================
  // === Player Updates    ===
  // =========================

  function updatePlayerInfo(id, patch) {
    if (!id) return;
    const map = getNameMap();
    const prev = map[id] || {};

    // Clean patch
    const cleanPatch = {};
    for (const [k, v] of Object.entries(patch)) {
      if (v !== "Unknown" && v !== "" && v != null) {
        cleanPatch[k] = v;
      }
    }

    // Merge + save
    const updated = { ...prev, ...cleanPatch, lastSeen: new Date().toISOString() };
    map[id] = updated;
    saveNameMap(map);

    // Send if changed
    if (JSON.stringify(prev) !== JSON.stringify(updated)) {
      const apiPayload = {};
      for (const [k, v] of Object.entries(updated)) {
        if (v !== "Unknown" && v !== "" && v != null) {
          apiPayload[k] = v;
        }
      }
      sendToAPI("players", { id, ...apiPayload });
    }
  }




// ==============================
// === XP → Attacks Calculator ===
// ==============================
// Converts XP + Turns into maximum possible attacks
// Used by Sidebar, Popup, Recon pages, etc.
function calculateXPTradeAttacks(xp, turns) {
  const XP_PER_TRADE = 1425;
  const TURNS_PER_TRADE = 500;
  const TURNS_PER_ATTACK = 120;
  const XP_REFUND_PER_ATTACK = 120;

  let attacks = 0;

  // Spend current turns first
  while (turns >= TURNS_PER_ATTACK) {
    turns -= TURNS_PER_ATTACK;
    attacks++;
    xp += XP_REFUND_PER_ATTACK;
  }

  // Trade XP into turns, loop until exhausted
  let traded = true;
  while (traded) {
    traded = false;

    while (xp >= XP_PER_TRADE) {
      xp -= XP_PER_TRADE;
      turns += TURNS_PER_TRADE;
      traded = true;
    }

    while (turns >= TURNS_PER_ATTACK) {
      turns -= TURNS_PER_ATTACK;
      attacks++;
      xp += XP_REFUND_PER_ATTACK;
      if (xp >= XP_PER_TRADE) traded = true;
    }
  }

  return attacks;
}
// ===================================
// === Sidebar Turn Trading Calculator ===
// ===================================
// Injects a mini calculator under the sidebar Gold/XP panel
function initSidebarCalculator() {
  console.log("[XPTool] initSidebarCalculator called");
  const BOX_ID = "koc-xp-box";
  if (document.getElementById(BOX_ID)) return; // prevent duplicates

  const xpBox = document.createElement("table");
  xpBox.id = BOX_ID;
  xpBox.className = "table_lines";
  xpBox.style.marginTop = "5px";
  xpBox.innerHTML = `
    <tbody>
      <tr><th align="center">⚔️ Turn Trading Calculator</th></tr>
      <tr><td align="center" style="color:black;">Attacks Left <span id="xp-attacks">0</span></td></tr>
      <tr><td align="center" style="color:black;">XP Trade Attacks <span id="xp-trade">0</span></td></tr>
      <tr><td align="center" style="color:black;">Avg Gold/Atk <a href="attacklog.php" id="xp-gold-link" style="color:black;"><span id="xp-gold">0</span></a></td></tr>
      <tr><td align="center" style="color:black;">Total Potential Gold <span id="xp-total">0</span></td></tr>
      <tr><td align="center" style="color:black;">Banked <span id="xp-banked">—</span></td></tr>
      <!-- ✅ Sweet Revenge logo row -->
    <tr>
  <td align="center">
    <a href="stats.php?id=datacentre">
      <img src="https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/images/SR_Logo.png"
           alt="Sweet Revenge"
           style="max-width:110px; height:auto; margin-top:6px; display:block; margin-left:auto; margin-right:auto;">
    </a>
  </td>
</tr>

  </tbody>
`;

  // Find sidebar gold/XP panel and insert after it
  const sidebarTables = document.querySelectorAll("table");
  let goldTable = null;
  sidebarTables.forEach(tbl => {
    if (tbl.innerText.includes("Gold:") && tbl.innerText.includes("Experience:")) {
      goldTable = tbl;
    }
  });

  if (goldTable && goldTable.parentNode) {
    goldTable.parentNode.insertBefore(xpBox, goldTable.nextSibling);
  } else {
    // fallback: inject into sidebar cell
    const firstSidebar = document.querySelector("td.menu_cell");
    if (firstSidebar) firstSidebar.appendChild(xpBox);
  }

  // --- helpers ---
  function formatGold(num) {
    if (!num) return "0";
    if (num >= 1e9) return (num / 1e9).toFixed(1) + "B";
    if (num >= 1e6) return (num / 1e6).toFixed(1) + "M";
    return num.toLocaleString();
  }

  function getSidebarValue(label) {
    const el = [...document.querySelectorAll("td")].find(td =>
      td.innerText.trim().startsWith(label)
    );
    if (!el) return 0;
    const parts = el.innerText.split(":");
    if (parts.length < 2) return 0;
    return parseInt(parts[1].replace(/[(),]/g, ""), 10) || 0;
  }

  function updateXPBox() {
    const xpVal = getSidebarValue("Experience");
    const turnsVal = getSidebarValue("Turns");

    const attacksLeft = Math.floor(turnsVal / 120);
    const xpTradeAttacks = calculateXPTradeAttacks(xpVal, turnsVal);

    const avgGold = parseFloat(localStorage.getItem("xpTool_avgGold")) || 0;
    const totalPotential = xpTradeAttacks * avgGold;

    document.getElementById("xp-attacks").innerText = attacksLeft;
    document.getElementById("xp-trade").innerText = xpTradeAttacks;
    document.getElementById("xp-gold").innerText = formatGold(avgGold);
    document.getElementById("xp-total").innerText = formatGold(totalPotential);

    // --- Banking Efficiency ---
    const goldLost = parseInt(localStorage.getItem("KoC_GoldLost24h") || "0", 10);
    const myId = localStorage.getItem("KoC_MyId");
    const mapRaw = localStorage.getItem("KoC_NameMap") || "{}";
    const map = JSON.parse(mapRaw);
    let projectedIncome = 0;
if (map[myId]?.projectedIncome !== undefined) {
  projectedIncome = Number(map[myId].projectedIncome) || 0;
}

const dailyTbg = projectedIncome * 1440;
let bankedPctText = "—";

if (dailyTbg > 0) {
  const bankedGold = Math.max(0, dailyTbg - goldLost);
  const pct = (bankedGold / dailyTbg * 100).toFixed(1);

  // Pick pill background
  let bg = "#8b0000";   // 🔴 dark red
  if (pct >= 25) bg = "#b45309";   // 🟠 amber
  if (pct >= 50) bg = "#a67c00";   // 🟡 goldenrod
  if (pct >= 75) bg = "#006400";   // 🟢 dark green

  bankedPctText = `
    <span style="
      display:inline-block;
      background:${bg};
      color:#fff;
      padding:1px 6px;
      border-radius:6px;
      font-weight:bold;
      font-size:11px;
      line-height:1.2;
      border:1px solid rgba(0,0,0,0.2); /* subtle outline */
      vertical-align:middle;
    ">
      ${pct}%
    </span>`;
}

document.getElementById("xp-banked").innerHTML = bankedPctText;


   }

  updateXPBox();
  console.log("[XPTool] Sidebar box inserted into page");
}

// ==================================
// === Popup Turn Trading Calculator ===
// ==================================
// Opens a popup with manual inputs for XP, Turns, Avg Gold
function createAttackPopup() {
  const overlay = document.createElement('div');
  overlay.id = 'koc-popup-overlay';
  Object.assign(overlay.style, {
    position: 'fixed',
    top: '0', left: '0', width: '100%', height: '100%',
    backgroundColor: 'rgba(0,0,0,0.5)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    zIndex: '9999'
  });

  const popup = document.createElement('div');
  Object.assign(popup.style, {
    background: '#222',
    color: '#fff',
    padding: '15px',
    border: '2px solid #666',
    borderRadius: '8px',
    width: '300px',
    position: 'relative'
  });

  const closeBtn = document.createElement('span');
  closeBtn.textContent = '×';
  Object.assign(closeBtn.style, {
    position: 'absolute',
    top: '5px', right: '10px',
    cursor: 'pointer', fontSize: '20px'
  });
  closeBtn.onclick = () => overlay.remove();

  const title = document.createElement('h3');
  title.textContent = '⚔️ Turn Trading Calculator';
  title.style.marginTop = '0';
  title.style.textAlign = 'center';

  // Input fields
  const turnsInput = document.createElement('input');
  turnsInput.type = 'number';
  turnsInput.placeholder = 'Turns';
  turnsInput.style.width = '100%';
  turnsInput.style.marginBottom = '5px';

  const expInput = document.createElement('input');
  expInput.type = 'number';
  expInput.placeholder = 'Experience';
  expInput.style.width = '100%';
  expInput.style.marginBottom = '5px';

  const avgInput = document.createElement('input');
  avgInput.type = 'number';
  avgInput.placeholder = 'Avg Gold/Atk';
  avgInput.style.width = '100%';
  avgInput.style.marginBottom = '10px';

  const calcBtn = document.createElement('button');
  calcBtn.textContent = 'Calculate';
  calcBtn.style.width = '100%';
  calcBtn.style.marginBottom = '10px';

  const results = document.createElement('div');
  results.innerHTML = `
    <p>Max Attacks: <span id="koc-max-attacks">0</span></p>
    <p>Potential Gold: <span id="koc-pot-gold">0</span></p>
  `;

  calcBtn.onclick = () => {
    const turns = parseInt(turnsInput.value) || 0;
    const exp = parseInt(expInput.value) || 0;
    const avgGold = parseFloat(avgInput.value) || 0;

    const maxAttacks = calculateXPTradeAttacks(exp, turns);
    const potGold = maxAttacks * avgGold;

    results.querySelector('#koc-max-attacks').textContent = maxAttacks.toLocaleString();
    results.querySelector('#koc-pot-gold').textContent = potGold.toLocaleString();
  };

  // Assemble popup
  popup.appendChild(closeBtn);
  popup.appendChild(title);
  popup.appendChild(turnsInput);
  popup.appendChild(expInput);
  popup.appendChild(avgInput);
  popup.appendChild(calcBtn);
  popup.appendChild(results);

  overlay.appendChild(popup);
  document.body.appendChild(overlay);
}

// Hook: clicking the sidebar box header opens popup
function hookSidebarPopup() {
  const th = [...document.querySelectorAll("th")]
    .find(el => el.innerText.includes("Turn Trading Calculator"));
  if (th) {
    th.style.cursor = 'pointer';
    th.title = 'Click to open Turn Trading Calculator';
    th.onclick = createAttackPopup;
  }
}
// ===============================
// === Attack Log Enhancer (Avg Gold/Atk + Banking) ===
// ===============================
// Reads your attack log, calculates average gold/attack,
// captures Gold Lost (24h) for Banking Efficiency,
// updates sidebar + popup automatically
function enhanceAttackLog() {
  console.log("[XPTool] enhanceAttackLog called");

  const tables = document.querySelectorAll('table');
  for (let i = 0; i < tables.length; i++) {
    const tbl = tables[i];
    const txt = tbl.innerText.trim();

    // Look for the summary headers (allow AV suffix)
    if (txt.startsWith('Total By You Last 24 Hours') || txt.startsWith('Total On You Last 24 Hours')) {
      const dataTable = tables[i + 1];
      if (dataTable) {
        const rows = dataTable.querySelectorAll('tr');
        rows.forEach(r => {
          const cells = r.querySelectorAll('td');
          if (cells.length >= 3) {
            const label = cells[0].innerText.trim().toLowerCase();

            // === Average Gold per Attack (By You) ===
            if (label.startsWith('attacks')) {
              const numAttacks = parseInt(cells[1].innerText.replace(/,/g, ''), 10);
              const gold = parseInt(cells[2].innerText.replace(/,/g, ''), 10);

              if (numAttacks > 0) {
                const avg = gold / numAttacks;
                const labelTxt = (avg >= 1e9) ? (avg / 1e9).toFixed(1) + 'B AV'
                                              : (avg / 1e6).toFixed(1) + 'M AV';

                const th = tbl.querySelector('th');
                if (th && !th.innerHTML.includes('AV')) {
                  th.innerHTML = `<div style="text-align:center;">${th.innerText} (${labelTxt})</div>`;
                }

                // Save avg gold to localStorage for Sidebar + Popup
                if (txt.startsWith('Total By You Last 24 Hours')) {
                  localStorage.setItem('xpTool_avgGold', String(avg));
                  localStorage.setItem('xpTool_avgGold_time', String(Date.now()));
                  console.log("[XPTool] Avg Gold/Atk saved:", avg);
                }
              }
            }

            // === Gold Lost (On You) for Banking Efficiency ===
            if (txt.startsWith('Total On You Last 24 Hours') && label === 'total') {
              const goldLost = parseInt(cells[2].innerText.replace(/,/g, ''), 10) || 0;
              localStorage.setItem("KoC_GoldLost24h", String(goldLost));
              localStorage.setItem("KoC_GoldLost24h_time", new Date().toISOString());
              console.log("📊 Banking: Gold lost (24h) saved:", goldLost);
            }
          }
        });
      }
    }
  }
}

// ===============================
// === Recon Page: Add Max Attacks ===
// ===============================
// Shows how many attacks the target can make (XP+Turns)
function addMaxAttacksRecon() {
  const ROW_ID = "koc-max-attacks-row";
  if (document.getElementById(ROW_ID)) return; // avoid duplicates

  const tables = document.querySelectorAll('table');
  let usableResourcesTable = null;

  // Find the "Usable Resources" table
  tables.forEach(tbl => {
    const headers = tbl.querySelectorAll('th');
    headers.forEach(h => {
      if (h.innerText.includes('Usable Resources')) {
        usableResourcesTable = tbl;
      }
    });
  });

  if (!usableResourcesTable) return;

  // Extract Turns + Experience
  const rows = usableResourcesTable.querySelectorAll('tr');
  let turns = 0, exp = 0;

  rows.forEach(row => {
    const cells = row.querySelectorAll('td');
    if (cells.length >= 2) {
      if (cells[0].innerText.includes('Attack Turns')) {
        turns = parseInt(cells[1].innerText.replace(/,/g, ''), 10);
      }
      if (cells[0].innerText.includes('Experience')) {
        exp = parseInt(cells[1].innerText.replace(/,/g, ''), 10);
      }
    }
  });

  if (!turns && !exp) return;

  // Calculate Max Attacks
  const maxAttacks = calculateXPTradeAttacks(exp, turns);

  // Insert new row
  const newRow = document.createElement('tr');
  newRow.id = ROW_ID;
  const labelCell = document.createElement('td');
  labelCell.textContent = "Max Attacks:";
  const valueCell = document.createElement('td');
  valueCell.setAttribute("align", "right");
  valueCell.textContent = maxAttacks.toLocaleString();
  newRow.appendChild(labelCell);
  newRow.appendChild(valueCell);

  usableResourcesTable.appendChild(newRow);

  console.log("[XPTool] Recon Max Attacks row added:", maxAttacks);
}


// =========================
// === Battlefield Collector
// =========================
let battlefieldTimeout = null;
let collectedPlayers = new Set();

// Helper: Parse gold with age from battlefield cell (e.g., "640.07m(26s)")
function parseGoldWithAge(text) {
  if (!text) return { gold: null, ageMinutes: null };

  // Parse gold value
  const goldMatch = text.match(/^([\d\.,]+[kmbt]?)/i);
  let gold = null;
  if (goldMatch) {
    const str = goldMatch[1].toLowerCase().replace(/,/g, "");
    let multiplier = 1;
    if (str.endsWith('k')) multiplier = 1e3;
    else if (str.endsWith('m')) multiplier = 1e6;
    else if (str.endsWith('b')) multiplier = 1e9;
    else if (str.endsWith('t')) multiplier = 1e12;
    gold = parseFloat(str) * multiplier;
  }

  // Parse age (e.g., "(26s)", "(22m)", "(1h13m)")
  let ageMinutes = null;
  const hoursMatch = text.match(/\((\d+)\s*h(?:\s*(\d+)\s*m)?\)/);
  if (hoursMatch) {
    const hours = parseInt(hoursMatch[1], 10) || 0;
    const minutes = hoursMatch[2] ? (parseInt(hoursMatch[2], 10) || 0) : 0;
    ageMinutes = hours * 60 + minutes;
  } else {
    const minutesMatch = text.match(/\((\d+)\s*m(?:\s*(\d+)\s*s)?\)/);
    if (minutesMatch) {
      ageMinutes = parseInt(minutesMatch[1], 10) || 0;
    } else {
      const secondsMatch = text.match(/\((\d+)\s*s\)/);
      if (secondsMatch) {
        ageMinutes = (parseInt(secondsMatch[1], 10) || 0) / 60;
      }
    }
  }

  return { gold, ageMinutes };
}

async function collectFromBattlefield() {
  if (battlefieldTimeout) {
    clearTimeout(battlefieldTimeout);
  }

  battlefieldTimeout = setTimeout(async () => {
    const rows = document.querySelectorAll("tr[user_id]");
    let newCount = 0;
    const goldUpdates = []; // Batch gold updates

    rows.forEach(row => {
      const id = row.getAttribute("user_id");
      if (collectedPlayers.has(id)) return;

      const cells = row.querySelectorAll("td");
      const treasuryText = cells[5]?.innerText.trim() || "";
      const { gold, ageMinutes } = parseGoldWithAge(treasuryText);

      const player = {
        id,
        name:     cells[2]?.innerText.trim() || "Unknown",
        alliance: cells[1]?.innerText.trim() || "",
        army:     cells[3]?.innerText.trim() || "",
        race:     cells[4]?.innerText.trim() || "",
        treasury: gold,
        recon:    cells[6]?.innerText.trim() || "",
        rank:     cells[7]?.innerText.trim() || ""
      };

      updatePlayerInfo(player.id, player);
      collectedPlayers.add(id);
      newCount++;

      // Add to bulk gold update if we have valid gold data
      if (gold !== null) {
        goldUpdates.push({
          playerId: id,
          gold: gold,
          ageMinutes: ageMinutes
        });
      }
    });

    if (newCount > 0) {
      console.log(`[DataCentre] Captured ${newCount} new players from battlefield`);
    }

    // Send bulk gold updates to API
    if (goldUpdates.length > 0) {
      console.log(`[DataCentre] Sending ${goldUpdates.length} gold updates to API`);
      await sendToAPI("battlefield/bulk-gold-update", { updates: goldUpdates });
    }

    battlefieldTimeout = null;
  }, 500);
}

if (location.pathname.includes("battlefield.php")) {
  collectFromBattlefield();
  const table = document.querySelector("table.battlefield") || document.querySelector("table.table_lines");
  if (table) {
    const observer = new MutationObserver((mutations) => {
      if (mutations.length > 1) {
        collectFromBattlefield();
      }
    });
    observer.observe(table, { childList: true, subtree: true });
    console.log("[DataCentre] Battlefield observer active");
  }
}

// =========================
// === Attack TIV Collector
// =========================
async function collectTIVFromAttackPage() {
  const idMatch  = location.search.match(/id=(\d+)/);

  // Check for Invalid User ID error
  if (document.body.textContent.includes("Invalid User ID")) {
    if (idMatch) {
      const id = idMatch[1];
      console.warn(`⚠️ Invalid User ID detected for player ${id} - marking as deleted`);
      await sendToAPI(`players/${id}/mark-inactive`, {
        status: "deleted",
        error: "Invalid User ID"
      });
    }
    return;
  }

  const tivMatch = document.body.textContent.match(/Total Invested Value:\s*\(([\d,]+)\)/i);
  if (!idMatch || !tivMatch) return;

  const id  = idMatch[1];
  const tiv = parseInt(tivMatch[1].replace(/,/g, ""), 10);
  const now = new Date().toISOString();

  // === Save locally ===
  const log = getTivLog();
  log.push({ id, tiv, time: now });
  saveTivLog(log);

  updatePlayerInfo(id, { tiv, lastTivTime: now });

  console.log("📊 Attack TIV saved", { id, tiv });

  // === Push to API ===
  await sendToAPI("tiv", { playerId: id, tiv, time: now });
}

if (location.pathname.includes("attack.php")) {
  // run async without blocking page load
  collectTIVFromAttackPage();
}

// =========================
// === Attack Log Collector (detail.php)
// =========================
async function collectAttackLog() {
  console.log("📊 Attack log collector triggered");

  // Extract attack ID from URL
  const urlParams = new URLSearchParams(location.search);
  const attackId = urlParams.get('attack_id');
  if (!attackId) {
    console.log("⚠️ No attack_id found in URL");
    return;
  }

  const bodyText = document.body.textContent || '';
  const myId = localStorage.getItem("KoC_MyId");

  // Extract gold stolen
  const goldMatch = bodyText.match(/you\s+stole\s+([\d,\.]+)\s*gold\s+while\s+attacking/i);
  const goldStolen = goldMatch ? parseInt(goldMatch[1].replace(/,/g, ''), 10) : 0;

  // Extract target name
  const targetMatch = bodyText.match(/attacking\s+([^']+)'s\s+camp/i);
  const targetName = targetMatch ? targetMatch[1].trim() : 'Unknown';

  // Extract hostages
  const hostagesMatch = bodyText.match(/made\s+off\s+with\s+([\d,]+)\s+hostages/i);
  const hostages = hostagesMatch ? parseInt(hostagesMatch[1].replace(/,/g, ''), 10) : 0;

  // Extract casualties
  const casualtiesMatch = bodyText.match(/\(Attack:\s*(\d+),\s*Defense:\s*(\d+),\s*Untrained:\s*(\d+),\s*Spies:\s*(\d+),\s*Sentries:\s*(\d+)\)/i);
  const casualties = casualtiesMatch ? {
    attack: parseInt(casualtiesMatch[1]) || 0,
    defense: parseInt(casualtiesMatch[2]) || 0,
    untrained: parseInt(casualtiesMatch[3]) || 0,
    spies: parseInt(casualtiesMatch[4]) || 0,
    sentries: parseInt(casualtiesMatch[5]) || 0
  } : null;

  // Extract your army stats
  const yourTrainedMatch = bodyText.match(/([\d,]+)\s+of your soldiers are trained attack specialists/i);
  const yourUntrainedMatch = bodyText.match(/([\d,]+)\s+of your army consists of untrained soldiers/i);
  const yourArmy = {
    trained: yourTrainedMatch ? parseInt(yourTrainedMatch[1].replace(/,/g, ''), 10) : null,
    untrained: yourUntrainedMatch ? parseInt(yourUntrainedMatch[1].replace(/,/g, ''), 10) : null
  };

  // Extract enemy army stats
  const enemyTrainedMatch = bodyText.match(/enemy has\s+([\d,]+)\s+trained soldiers with weapons/i);
  const enemyUntrainedMatch = bodyText.match(/enemy's\s+([\d,]+)\s+untrained soldiers/i);
  const enemyArmy = {
    trained: enemyTrainedMatch ? parseInt(enemyTrainedMatch[1].replace(/,/g, ''), 10) : null,
    untrained: enemyUntrainedMatch ? parseInt(enemyUntrainedMatch[1].replace(/,/g, ''), 10) : null
  };

  // Extract damage dealt
  const damageMatch = bodyText.match(/inflict\s+([\d,]+)\s+damage/i);
  const damageDealt = damageMatch ? parseInt(damageMatch[1].replace(/,/g, ''), 10) : 0;

  // Extract enemy casualties
  const enemyCasualtiesMatch = bodyText.match(/enemy sustains\s+([\d,]+)\s+casualties/i);
  const enemyCasualties = enemyCasualtiesMatch ? parseInt(enemyCasualtiesMatch[1].replace(/,/g, ''), 10) : 0;

  // Find target ID
  let targetId = null;
  const allStatsLinks = document.querySelectorAll('a[href*="stats.php?id="]');
  for (const link of allStatsLinks) {
    try {
      const id = new URL(link.href, location.origin).searchParams.get('id');
      if (id && /^\d+$/.test(id) && id !== myId) {
        targetId = id;
        break;
      }
    } catch (error) {
      // Skip invalid links
    }
  }

  if (!targetId) {
    console.log("⚠️ Could not find target ID");
    return;
  }

  // Build attack log payload
  const attackLog = {
    attackId,
    attackerId: myId,
    targetId,
    targetName,
    goldStolen,
    hostages,
    damageDealt,
    enemyCasualties,
    casualties,
    yourArmy,
    enemyArmy
  };

  console.log("📊 Attack log collected:", attackLog);

  // Send to API
  await sendToAPI("battlefield/attack-log", attackLog);
}

// Hook into detail.php (attack results page)
if (location.pathname.includes("detail.php") && /attack_id=/.test(location.search)) {
  collectAttackLog();
  setTimeout(collectAttackLog, 600); // Delayed check for late-loading content
}

// --- Helper: Military Stats Parser (RB-style) ---
function collectMilitaryStats() {
  const header = document.evaluate(
    `.//th[contains(., "Military Effectiveness")]`,
    document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null
  ).singleNodeValue;
  if (!header) return {};

  const table = header.closest("table");
  const stats = {};
  table.querySelectorAll("tr").forEach(row => {
    const cells = row.querySelectorAll("td");
    if (cells.length < 2) return;

    const label = cells[0].innerText.trim().toLowerCase();
    const value = cells[1].innerText.trim();

    if (label.startsWith("strike"))    stats.strikeAction    = value;
    if (label.startsWith("defense"))   stats.defensiveAction = value;
    if (label.startsWith("spy"))       stats.spyRating       = value;
    if (label.startsWith("sentry"))    stats.sentryRating    = value;
    if (label.startsWith("poison"))    stats.poisonRating    = value;
    if (label.startsWith("antidote"))  stats.antidoteRating  = value;
    if (label.startsWith("theft"))     stats.theftRating     = value;
    if (label.startsWith("vigilance")) stats.vigilanceRating = value;
  });
  return stats;
}


// =========================
// === Base Page Collector (Self ID + Economy + Military Stats) ===
// =========================
function collectFromBasePage() {
  let myId = localStorage.getItem("KoC_MyId");
  let myName = localStorage.getItem("KoC_MyName");

  // --- Capture my ID/Name if missing ---
  const myLink = document.querySelector("a[href*='stats.php?id=']");
  if (myLink) {
    myId = myLink.href.match(/id=(\d+)/)?.[1] || myId || "self";
    myName = myLink.textContent.trim() || myName || "Me";
    localStorage.setItem("KoC_MyId", myId);
    localStorage.setItem("KoC_MyName", myName);
    console.log("📊 Stored my KoC ID/Name:", myId, myName);
  }

  let projectedIncome, treasury, economy, xpPerTurn, turnsAvailable;

  // --- Economy / Treasury block ---
  const rows = [...document.querySelectorAll("tr")];
  rows.forEach(tr => {
    const txt = tr.innerText.trim();

    if (txt.includes("Projected Income")) {
      const match = txt.match(/([\d,]+)\s+Gold/);
      if (match) projectedIncome = parseInt(match[1].replace(/,/g, ""), 10);
    }

    if (txt.startsWith("Economy")) {
      const match = txt.match(/([\d,]+)/);
      if (match) economy = parseInt(match[1].replace(/,/g, ""), 10);
    }
    if (txt.includes("Experience Per Turn")) {
      const match = txt.match(/([\d,]+)/);
      if (match) xpPerTurn = parseInt(match[1].replace(/,/g, ""), 10);
    }
  });

  // --- Military Effectiveness block (RB-style parser) ---
  const stats = {};
  const header = document.evaluate(
    `.//th[contains(., "Military Effectiveness")]`,
    document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null
  ).singleNodeValue;

  if (header) {
    const table = header.closest("table");
    table.querySelectorAll("tr").forEach(row => {
      const cells = row.querySelectorAll("td");
      if (cells.length < 2) return;

      const label = cells[0].innerText.trim().toLowerCase();
      const value = cells[1].innerText.trim();

      if (label.startsWith("strike"))    stats.strikeAction    = value;
      if (label.startsWith("defense"))   stats.defensiveAction = value;
      if (label.startsWith("spy"))       stats.spyRating       = value;
      if (label.startsWith("sentry"))    stats.sentryRating    = value;
      if (label.startsWith("poison"))    stats.poisonRating    = value;
      if (label.startsWith("antidote"))  stats.antidoteRating  = value;
      if (label.startsWith("theft"))     stats.theftRating     = value;
      if (label.startsWith("vigilance")) stats.vigilanceRating = value;
    });
  }

  const payload = {
    name: myName,
    projectedIncome,
    treasury,
    economy,
    xpPerTurn,
    turnsAvailable,
    ...stats,
    lastSeen: new Date().toISOString()
  };

  // === Save locally ===
  updatePlayerInfo(myId, payload);
  console.log("📊 Base.php self stats captured", payload);

  // === Push to API ===
  sendToAPI("players", { id: myId, ...payload });
}
// ✅ Run automatically when base.php loads
if (location.pathname.includes("base.php")) {
  collectFromBasePage();
}
// ===============================
// === Sweet Revenge Stats Panel ===
// ===============================
async function insertTopStatsPanel() {
  const infoRow = document.querySelector("a[href='info.php']")?.closest("tr");
  if (!infoRow) return;

  // --- Fetch players (API → fallback to cache) ---
  let players = [];
  try {
    const token = await getValidToken();
    const resp = await fetch(`${API_URL}/players`, {
      headers: { "Authorization": "Bearer " + token }
    });
    if (resp.ok) players = await resp.json();
  } catch (err) {
    console.warn("TopStats API failed, using cache", err);
    players = Object.values(getNameMap());
  } 

  // ✅ Only Sweet Revenge
  players = players.filter(p => p.alliance === "Sweet Revenge");

  // --- Abbreviated numbers (RB-style) ---
  function formatNumber(n) {
    const num = Number(n) || 0;
    if (num >= 1e12) return (num / 1e12).toFixed(2) + "T";
    if (num >= 1e9)  return (num / 1e9).toFixed(2) + "B";
    if (num >= 1e6)  return (num / 1e6).toFixed(2) + "M";
    return num.toLocaleString();
  }

  // --- Sort helper ---
  function sortedBy(field, asc = false) {
    return [...players]
      .filter(p => p[field] !== undefined && p[field] !== null)
      .sort((a, b) => {
        const av = Number(a[field]) || 0;
        const bv = Number(b[field]) || 0;
        return asc ? (av - bv) : (bv - av);
      })
      .map((p, i) => ({
        id: p.id,
        rank: i + 1,
        name: p.name || "Unknown",
        value: formatNumber(p[field])
      }));
  }

  // --- Stat definitions with IDs for individual toggles ---
  const statDefs = [
    { key: "tiv", label: "💰 TIV", id: "tiv" },
    { key: "strikeAction", label: "⚔️ Strike", id: "strike" },
    { key: "spyRating", label: "🕵️ Spy", id: "spy" },
    { key: "poisonRating", label: "☠️ Poison", id: "poison" },
    { key: "theftRating", label: "🪙 Theft", id: "theft" },
    { key: "rank", label: "🏅 Rank", id: "rank", asc: true },
    { key: "defensiveAction", label: "🛡️ Defense", id: "defense" },
    { key: "sentryRating", label: "👀 Sentry", id: "sentry" },
    { key: "antidoteRating", label: "💊 Antidote", id: "antidote" },
    { key: "vigilanceRating", label: "🔎 Vigilance", id: "vigilance" }
  ];

  // --- Build responsive mini table with tighter rows and consistent width ---
  function makeRBTable(def, rows) {
    const wrap = document.createElement("div");
    wrap.className = `sr-stat-${def.id}`;
    wrap.style.cssText = `
      flex: 1 1 0;
      min-width: 130px;
      max-height: 230px;
      overflow-y: auto;
      border: 1px solid #333;
      margin: 2px;
    `;
    wrap.innerHTML = `
      <table style="width:100%; font-size:10px; border-collapse:collapse; background:#111; color:#ccc;">
        <thead style="background:#222; color:#6f6; position:sticky; top:0;">
          <tr><th colspan="2" style="text-align:center; padding:4px;">${def.label}</th></tr>
        </thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              <td style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:90px; padding:2px 4px; line-height:1.2;">
                ${r.rank}. <a href="stats.php?id=${r.id}" style="color:#9cf; text-decoration:none;">${r.name}</a>
              </td>
              <td align="right" style="white-space:nowrap; padding:2px 4px; line-height:1.2;">${r.value}</td>
            </tr>`).join("")}
        </tbody>
      </table>
    `;
    return wrap;
  }

  // --- Container row ---
  const container = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 2;
  container.appendChild(cell);

  // --- Header with individual toggles ---
  const header = document.createElement("div");
  header.style.cssText = "margin-bottom:8px; color:gold; font-size:12px; font-weight:bold;";
  header.innerHTML = `<div style="margin-bottom:6px;">Sweet Revenge Stats</div>`;

  // Create toggle checkboxes
  const toggleContainer = document.createElement("div");
  toggleContainer.style.cssText = "display:flex; flex-wrap:wrap; gap:8px; font-size:10px; color:#ccc; margin-bottom:6px;";

  statDefs.forEach(def => {
    const label = document.createElement("label");
    label.style.cssText = "cursor:pointer; white-space:nowrap;";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = `sr-toggle-${def.id}`;
    checkbox.style.cssText = "vertical-align:middle; margin-right:2px;";

    // Load saved state (default: visible = checked)
    const savedState = localStorage.getItem(`srStat_${def.id}`);
    if (savedState === "hidden") {
      checkbox.checked = false;
    } else {
      checkbox.checked = true; // Default visible
    }

    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(def.label));
    toggleContainer.appendChild(label);
  });

  header.appendChild(toggleContainer);

  // --- Two-row container that splits visible tables evenly ---
  const tablesContainer = document.createElement("div");
  tablesContainer.id = "sr-stats-tables";

  const row1 = document.createElement("div");
  row1.id = "sr-stats-row1";
  row1.style.cssText = "display:flex; gap:0; align-items:stretch; margin-bottom:4px;";

  const row2 = document.createElement("div");
  row2.id = "sr-stats-row2";
  row2.style.cssText = "display:flex; gap:0; align-items:stretch;";

  tablesContainer.appendChild(row1);
  tablesContainer.appendChild(row2);

  // Generate all tables and store references
  const allTables = [];
  statDefs.forEach(def => {
    const table = makeRBTable(def, sortedBy(def.key, def.asc));
    table.dataset.statId = def.id;

    // Set initial visibility
    const savedState = localStorage.getItem(`srStat_${def.id}`);
    if (savedState === "hidden") {
      table.style.display = "none";
    }

    allTables.push(table);
  });

  // Function to redistribute tables between rows
  function redistributeTables() {
    // Clear both rows
    row1.innerHTML = "";
    row2.innerHTML = "";

    // Get visible tables
    const visibleTables = allTables.filter(t => t.style.display !== "none");

    // Split evenly between rows
    const midpoint = Math.ceil(visibleTables.length / 2);
    visibleTables.forEach((table, i) => {
      if (i < midpoint) {
        row1.appendChild(table);
      } else {
        row2.appendChild(table);
      }
    });

    // Hide row2 if empty
    row2.style.display = visibleTables.length <= midpoint ? "none" : "flex";
  }

  // Initial distribution
  redistributeTables();

  // --- Add toggle event listeners with redistribution (checked = visible) ---
  statDefs.forEach(def => {
    const checkbox = toggleContainer.querySelector(`#sr-toggle-${def.id}`);
    checkbox.addEventListener("change", e => {
      const table = allTables.find(t => t.dataset.statId === def.id);
      if (e.target.checked) {
        table.style.display = "block";
        localStorage.setItem(`srStat_${def.id}`, "visible");
      } else {
        table.style.display = "none";
        localStorage.setItem(`srStat_${def.id}`, "hidden");
      }
      redistributeTables();
    });
  });

  // Build cell
  cell.appendChild(header);
  cell.appendChild(tablesContainer);

  infoRow.parentNode.insertBefore(container, infoRow.nextSibling);
}

// Run automatically on base.php
if (location.pathname.includes("base.php")) {
  insertTopStatsPanel();
}



// =========================
// === Armory Self Collector (TIV + Military Stats) ===
// =========================
async function collectTIVAndStatsFromArmory() {
  const myId = localStorage.getItem("KoC_MyId") || "self";
  const myName = localStorage.getItem("KoC_MyName") || "Me";

  // --- TIV ---
  const header = [...document.querySelectorAll("th.subh")]
    .find(th => th.textContent.includes("Total Invested Value"));
  const tivCell = header?.closest("tr").nextElementSibling?.querySelector("td b");
  const tiv = tivCell ? parseInt(tivCell.textContent.replace(/,/g, "").trim(), 10) : 0;

  // --- Military Stats table ---
  const msTable = document.evaluate(
    `.//th[contains(., "Military Effectiveness")]`,
    document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null
  ).singleNodeValue?.closest("table");
  const msRows = msTable?.querySelectorAll("tr");

  const stats = {
    strikeAction:    msRows?.[2]?.cells[1]?.innerText.trim() || "—",
    defensiveAction: msRows?.[3]?.cells[1]?.innerText.trim() || "—",
    spyRating:       msRows?.[4]?.cells[1]?.innerText.trim() || "—",
    sentryRating:    msRows?.[5]?.cells[1]?.innerText.trim() || "—",
    poisonRating:    msRows?.[6]?.cells[1]?.innerText.trim() || "—",
    antidoteRating:  msRows?.[7]?.cells[1]?.innerText.trim() || "—",
    theftRating:     msRows?.[8]?.cells[1]?.innerText.trim() || "—",
    vigilanceRating: msRows?.[9]?.cells[1]?.innerText.trim() || "—"
  };

  const now = new Date().toISOString();

  // Save to TIV log
  if (tiv) {
    const log = getTivLog();
    log.push({ id: myId, tiv, time: now });
    saveTivLog(log);

    // 🔥 Send TIV to API
    await sendToAPI("tiv", { playerId: myId, tiv, time: now });
  }

  // Merge into NameMap + API push
  const payload = {
    name: myName,
    tiv,
    ...stats,
    lastTivTime: now,
    lastRecon: now
  };

  updatePlayerInfo(myId, payload);

  // 🔥 Send self stats to API
  await sendToAPI("players", { id: myId, ...payload });

  console.log("📊 Armory self stats captured", { id: myId, name: myName, tiv, ...stats });
}

if (location.pathname.includes("armory.php")) {
  // important: call the async function, but don't await here to avoid blocking page load
  collectTIVAndStatsFromArmory();
}

// =========================
// === Recon Data Collector
// =========================
function getTableByHeader(text) {
  return document.evaluate(`.//th[contains(., "${text}")]`,
    document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null
  ).singleNodeValue?.closest("table") || null;
}

function grabStat(id, key, cell) {
  const val = cell?.innerText.trim();
  const prev = getNameMap()[id] || {};
  if (val && val !== "???") {
    return { value: val, time: new Date().toISOString() };
  } else {
    return { value: prev[key] || "???", time: prev[key + "Time"] };
  }
}

async function collectFromReconPage() {
  console.log("📊 Recon collector triggered");

  const link = document.querySelector('a[href*="stats.php?id="]');
  const match = link?.href.match(/id=(\d+)/);
  const id = match ? match[1] : null;

  if (!id) {
    console.log("⚠️ Recon: Could not find player ID");
    return;
  }
  console.log("ℹ️ Recon target ID:", id);

  // Check for Invalid User ID error
  if (document.body.textContent.includes("Invalid User ID")) {
    console.warn(`⚠️ Invalid User ID detected for player ${id} - marking as deleted`);
    await sendToAPI(`players/${id}/mark-inactive`, {
      status: "deleted",
      error: "Invalid User ID"
    });
    return;
  }

  const ms = getTableByHeader("Military Stats")?.querySelectorAll("tr");
  const treasury = getTableByHeader("Treasury")?.querySelectorAll("tr");

  const stats = {};
  function set(key, row) {
    const { value, time } = grabStat(id, key, row?.cells[1]);
    stats[key] = value;
    if (time) stats[key + "Time"] = time;
  }

  set("strikeAction",       ms?.[1]);
  set("defensiveAction",    ms?.[2]);
  set("spyRating",          ms?.[3]);
  set("sentryRating",       ms?.[4]);
  set("poisonRating",       ms?.[5]);
  set("antidoteRating",     ms?.[6]);
  set("theftRating",        ms?.[7]);
  set("vigilanceRating",    ms?.[8]);
  set("covertSkill",        ms?.[10]);
  set("sentrySkill",        ms?.[11]);
  set("siegeTechnology",    ms?.[12]);
  set("toxicInfusionLevel", ms?.[13]);
  set("viperbaneLevel",     ms?.[14]);
  set("shadowmeldLevel",    ms?.[15]);
  set("sentinelVigilLevel", ms?.[16]);
  set("economy",            ms?.[17]);
  set("technology",         ms?.[18]);
  set("experiencePerTurn",  ms?.[19]);
  set("soldiersPerTurn",    ms?.[20]);
  set("attackTurns",        ms?.[22]);
  set("experience",         ms?.[23]);

  // Treasury values
  stats.treasury = treasury?.[1]?.cells[0]?.innerText.split(" ")[0];
  stats.projectedIncome = treasury?.[3]?.innerText.split(" Gold")[0];

  // Save + push
  updatePlayerInfo(id, stats);
  console.log("📊 Recon data saved", stats);

  // Send to API
  await sendToAPI("players", { id, ...stats });
  if (stats.tiv) {
    await sendToAPI("tiv", { playerId: id, tiv: stats.tiv, time: stats.tivTime });
  }

  // Send gold update to battlefield tracker (fresh recon = age 0)
  if (stats.treasury && stats.treasury !== "???") {
    const goldValue = parseInt(stats.treasury.replace(/,/g, ''), 10);
    if (!isNaN(goldValue)) {
      await sendToAPI("battlefield/gold-update", {
        playerId: id,
        gold: goldValue,
        ageMinutes: 0,  // Fresh recon
        source: "recon"
      });
    }
  }

  // Kick off API-first filler
  enhanceReconUI(id).catch(err => console.warn("enhanceReconUI failed:", err));
}

// Hook - only called once
if (location.pathname.includes("inteldetail.php")) {
  collectFromReconPage();
}
// =========================
// === Recon UI Enhancer ===
// =========================
function reconTimeAgo(input) {
  const d = input instanceof Date ? input : new Date(input);
  if (!d || isNaN(d)) return "";
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 0) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function fillMissingReconValue(cell, cachedValue, cachedTime) {
  if (!cell) return;
  if (cell.textContent.trim() === "???" && cachedValue && cachedValue !== "???") {
    const rel = cachedTime ? reconTimeAgo(cachedTime) : "";
    const abs = cachedTime ? new Date(cachedTime).toLocaleString() : "";
    cell.innerHTML = `
      <div style="float:left;color:#FBC;font-size:0.8em;" title="${abs} • from cache">
        ${rel}
      </div>
      <div title="${abs} • from cache">${cachedValue}</div>
    `;
  }
}

async function enhanceReconUI(id) {
  let prev = {};

  // API-first
  try {
    const token = await getValidToken();
    if (token) {
      const resp = await fetch(`${API_URL}/players/${id}`, {
        headers: { "Authorization": "Bearer " + token }
      });
      if (resp.ok) {
        prev = await resp.json();
        console.log("🌐 Recon fallback loaded from API:", prev);
      }
    }
  } catch (err) {
    console.warn("⚠️ API recon lookup failed, using local cache", err);
  }

  // Fallback to local cache
  if (!prev || Object.keys(prev).length === 0) {
    const map = getNameMap();
    prev = map[id] || {};
  }

  // Fill UI
  const ms = getTableByHeader("Military Stats")?.querySelectorAll("tr");
  if (!ms) return;

  fillMissingReconValue(ms?.[1]?.cells[1],  prev.strikeAction,       prev.strikeActionTime);
  fillMissingReconValue(ms?.[2]?.cells[1],  prev.defensiveAction,    prev.defensiveActionTime);
  fillMissingReconValue(ms?.[3]?.cells[1],  prev.spyRating,          prev.spyRatingTime);
  fillMissingReconValue(ms?.[4]?.cells[1],  prev.sentryRating,       prev.sentryRatingTime);
  fillMissingReconValue(ms?.[5]?.cells[1],  prev.poisonRating,       prev.poisonRatingTime);
  fillMissingReconValue(ms?.[6]?.cells[1],  prev.antidoteRating,     prev.antidoteRatingTime);
  fillMissingReconValue(ms?.[7]?.cells[1],  prev.theftRating,        prev.theftRatingTime);
  fillMissingReconValue(ms?.[8]?.cells[1],  prev.vigilanceRating,    prev.vigilanceRatingTime);
  fillMissingReconValue(ms?.[10]?.cells[1], prev.covertSkill,        prev.covertSkillTime);
  fillMissingReconValue(ms?.[11]?.cells[1], prev.sentrySkill,        prev.sentrySkillTime);
  fillMissingReconValue(ms?.[12]?.cells[1], prev.siegeTechnology,    prev.siegeTechnologyTime);
  fillMissingReconValue(ms?.[13]?.cells[1], prev.toxicInfusionLevel, prev.toxicInfusionLevelTime);
  fillMissingReconValue(ms?.[14]?.cells[1], prev.viperbaneLevel,     prev.viperbaneLevelTime);
  fillMissingReconValue(ms?.[15]?.cells[1], prev.shadowmeldLevel,    prev.shadowmeldLevelTime);
  fillMissingReconValue(ms?.[16]?.cells[1], prev.sentinelVigilLevel, prev.sentinelVigilLevelTime);
  fillMissingReconValue(ms?.[17]?.cells[1], prev.economy,            prev.economyTime);
  fillMissingReconValue(ms?.[18]?.cells[1], prev.technology,         prev.technologyTime);
  fillMissingReconValue(ms?.[19]?.cells[1], prev.experiencePerTurn,  prev.experiencePerTurnTime);
  fillMissingReconValue(ms?.[20]?.cells[1], prev.soldiersPerTurn,    prev.soldiersPerTurnTime);
  fillMissingReconValue(ms?.[22]?.cells[1], prev.attackTurns,        prev.attackTurnsTime);
  fillMissingReconValue(ms?.[23]?.cells[1], prev.experience,         prev.experienceTime);

}

// ==============================
// === Data Centre Roster Page ===
// ==============================
// Now redirects to React app with auth token
if (location.search.includes("id=datacentre")) {
  console.log("[DataCentre] Redirecting to React app...");

  const auth = getStoredAuth();
  console.log("[DataCentre] Auth from storage:", auth);

  if (auth && auth.token) {
    console.log("[DataCentre] Valid auth found, redirecting with token");
    // Pass auth via query parameter instead of hash
    const authData = btoa(JSON.stringify({
      token: auth.token,
      id: auth.id,
      name: auth.name,
      expiry: auth.expiry
    }));
    const targetUrl = `https://koc-roster-client-production.up.railway.app?auth=${authData}`;
    console.log("[DataCentre] Redirecting to:", targetUrl);
    window.location.href = targetUrl;
  } else {
    console.log("[DataCentre] No valid auth found, redirecting without token");
    window.location.href = "https://koc-roster-client-production.up.railway.app";
  }
}


/// =========================
// === Button Injection ===
// =========================
function addButtons() {
  // Only inject if logged in (logout link present)
  if (!document.querySelector("a[href='logout.php']")) return;

  const infoRow = document.querySelector("a[href='info.php']")?.closest("tr");
  if (!infoRow) {
    setTimeout(addButtons, 500);
    return;
  }

  // NOTE: Don't clear the row - competition panel needs it
  // infoRow.innerHTML = "";
}


// Command Center (base.php) → add buttons + sidebar calc
if (location.pathname.includes("base.php") && document.querySelector("a[href='logout.php']")) {
  addButtons();
  initSidebarCalculator();
}

// Any page with sidebar (menu_cell) → show sidebar calc (only if logged in)
if (document.querySelector("td.menu_cell") && document.querySelector("a[href='logout.php']")) {
  initSidebarCalculator();
  hookSidebarPopup();
}

// Attack log → enhance (only if logged in)
if (location.pathname.includes("attacklog.php") && document.querySelector("a[href='logout.php']")) {
  enhanceAttackLog();
}

// Recon detail → add max attacks (only if logged in)
if (location.pathname.includes("inteldetail.php") && document.querySelector("a[href='logout.php']")) {
  addMaxAttacksRecon();
}


  // =========================
  // === Styling (Hover Effect)
  // =========================
  const style = document.createElement("style");
  style.textContent = `
    a.koc-button img {
      transition: transform 0.2s ease, filter 0.2s ease;
    }
    a.koc-button img:hover {
      transform: scale(1.05);
      filter: drop-shadow(0 0 6px gold);
    }
  `;
  document.head.appendChild(style);
// =========================
// === Debug Helpers     ===
// =========================

// View a player (or all players if no id is passed)
window.showPlayer = function(id) {
  console.log("🔍 showPlayer() called with id:", id);
  const raw = localStorage.getItem("KoC_NameMap") || "{}";
  const map = JSON.parse(raw);
  if (!id) {
    console.log("📊 Full NameMap:", map);
    return map;
  }
  console.log("📊 Player record:", map[id]);
  return map[id] || null;
};

// View the full TIV history (attack + armory logs)
window.showTivLog = function() {
  console.log("📊 Full TIV log requested");
  const raw = localStorage.getItem("KoC_DataCentre") || "[]";
  const log = JSON.parse(raw);
  console.log("📊 Log:", log);
  return log;
};






})();