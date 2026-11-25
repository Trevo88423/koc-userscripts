// ==UserScript==
// @name         KoC Data Centre
// @namespace    trevo88423
// @version      3.0.2
// @description  Sweet Revenge alliance tool for Kings of Chaos. Adds display panels and calculators to game pages, and can share the stats you see with the Sweet Revenge roster. Every feature and every data share can be switched off from ⚙ Data Centre in the sidebar.
// @author       Blackheart
// @match        https://www.kingsofchaos.com/*
// @exclude      https://*.kingsofchaos.com/login.php*
// @exclude      https://*.kingsofchaos.com/confirm.login.php*
// @exclude      https://*.kingsofchaos.com/
// @exclude      https://*.kingsofchaos.com/index.php*
// @exclude      https://*.kingsofchaos.com/security.php*
// @exclude      https://*.kingsofchaos.com/error.php*
// @exclude      https://*.kingsofchaos.com/recruit.php*
// @exclude      https://*.kingsofchaos.com/farmlist.php*
// @exclude      https://*.kingsofchaos.com/error.php
// @exclude      https://*.kingsofchaos.com
// @icon         https://www.kingsofchaos.com/favicon.ico
// @grant        none
// @updateURL    https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.meta.js
// @downloadURL  https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js
// ==/UserScript==

(async function() {
  'use strict';

  // ==================== SECURITY CHECK ====================
  // Don't run on login/security pages or when logged out — with one exception.
  // The Inactive Accounts page opens without logging in, and a player on
  // vacation cannot log in at all, so on that page alone a logged-out visit
  // runs the Inactive Accounts collector and nothing else (see FEATURE_STEPS).
  // It authenticates with the identity saved at the member's last login.
  const onSecurityPage = location.pathname.includes("login.php") ||
                         location.pathname.includes("security.php");
  const loggedIn = !!document.querySelector("a[href='logout.php']");
  const LOGGED_OUT_INACTIVES = !onSecurityPage && !loggedIn && location.pathname.includes("inactives.php");
  if (onSecurityPage || (!loggedIn && !LOGGED_OUT_INACTIVES)) {
    console.log("❌ DataCentre disabled (security page or not logged in)");
    return;
  }

  // Read-only pages. The game's rules say, word for word, "Alliance scripts
  // cannot make any changes to warlist.php and farmlist.php at all" — not a
  // row, not a style, not a toast. The War List is still the best single page
  // in the game for reading targets, so the script runs there, but only the
  // collectors marked readOnly (see FEATURE_STEPS), and every piece of shared
  // machinery that could draw something — the version-check overlay, error
  // toasts, the stylesheet at the end of this file — stands down. farmlist.php
  // is @excluded as well; it is listed here so the guard holds even if a
  // script manager ignores the exclude. The War List is warlistv4.php; any
  // "v<N>" version of either page counts too.
  const READ_ONLY_PAGE = /\/(warlist|farmlist)(v\d+)?\.php/i.test(location.pathname);

  // ==================== SCRIPT MANAGER CHECK ====================
  // Check if this script is enabled in Script Manager
  if (window.KoC_ScriptManager && !window.KoC_ScriptManager.isEnabled('data-centre')) {
    console.log("❌ DataCentre disabled by Script Manager");
    return;
  }

  // ==================== VERSION CHECK ====================
  // Check if this script version is allowed to run
  const SCRIPT_NAME = 'koc-data-centre';
  const SCRIPT_VERSION = '3.0.2'; // Must match @version above
  const API_URL = "https://koc-roster-api-production.up.railway.app";   // the Sweet Revenge server
  // What the API said about the public release: { latestVersion, updateUrl,
  // isLatest }, or null when it could not say. The sidebar box and the ⚙ panel
  // show an Update link from it. The link goes to the raw .user.js;
  // the member's userscript manager then asks them to confirm the update —
  // nothing here fetches or installs anything.
  let scriptUpdate = null;
  const SCRIPT_UPDATE_URL = 'https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js';

  async function checkScriptVersion() {
    try {
      const response = await netFetch('login', `${API_URL}/script-version/check/${SCRIPT_NAME}/${SCRIPT_VERSION}`);
      const data = await response.json();

      if (!data.allowed) {
        // On a read-only page the overlay itself would break the game's rule,
        // so a blocked version just stops without drawing anything.
        if (READ_ONLY_PAGE) {
          console.error(`[${SCRIPT_NAME}] Version ${SCRIPT_VERSION} is blocked. Please update.`);
          throw new Error('Script version blocked');
        }

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
          <p style="margin: 0 0 10px 0;">${escapeHtml(data.message)}</p>
          <p style="margin: 0 0 10px 0;">
            <strong>Your version:</strong> ${escapeHtml(data.currentVersion)}<br>
            <strong>Minimum required:</strong> ${escapeHtml(data.minVersion)}<br>
            <strong>Latest version:</strong> ${escapeHtml(data.latestVersion)}
          </p>
          <a href="${escapeHtml(data.updateUrl)}" target="_blank" rel="noopener" style="
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

        // Stop script execution
        console.error(`[${SCRIPT_NAME}] Version ${SCRIPT_VERSION} is blocked. Please update.`);
        throw new Error('Script version blocked');
      }

      // Show a non-blocking "update available" warning ONLY when the server
      // actually reports a newer version. When version checking is disabled for a
      // script, the server returns {allowed:true, "Version checking disabled"} with
      // no isLatest/latestVersion fields — guarding on latestVersion here prevents a
      // spurious "A newer version (undefined) is available" log in that case.
      if (data.latestVersion) {
        scriptUpdate = {
          latestVersion: String(data.latestVersion),
          updateUrl: data.updateUrl || SCRIPT_UPDATE_URL,
          isLatest: data.isLatest !== false
        };
      }
      if (data.isLatest === false && data.latestVersion) {
        console.warn(`[${SCRIPT_NAME}] A newer version (${data.latestVersion}) is available. Current: ${SCRIPT_VERSION}`);
        console.warn(`Update at: ${data.updateUrl}`);
      }

    } catch (error) {
      // If version check fails, allow script to continue (fail-open)
      if (error.message !== 'Script version blocked') {
        console.warn(`[${SCRIPT_NAME}] Version check failed:`, error.message);
      } else {
        // Re-throw blocking error to stop script
        throw error;
      }
    }
  }

  // Run version check before continuing
  await checkScriptVersion();

  // ==================== CONSTANTS ====================

  // LocalStorage Keys
  const TOKEN_KEY = "KoC_SRAUTH";               // the old login's token in localStorage: read once, then deleted
  const LEGACY_ID_KEY = "KoC_SRLegacyLogin";     // { id, name } of the old login, no token; used only by the old login
  // Login
  const DEVICE_DB = "KoC_SR_DEVICE";             // IndexedDB: this browser's key
  const SESSION_KEY = "KoC_SRSESSION";           // sessionStorage: the current token, this tab only
  const SESSION_CHANNEL = "KoC_SR_SESSION";      // BroadcastChannel: open tabs pass the token to each other
  const NOTICE_KEY = "KoC_SRLoginNotice";        // sessionStorage: one message kept across the reload after Login
  // Whose in-game inbox the login codes can go to. Any one of them will do: the
  // server lets any Sweet Revenge admin approve any code, so this list is only
  // what the login box tells members. Two, so a login never waits on one person.
  const SR_APPROVER_NAMES = ["Blackheart-SR", "Tobi-SR"];
  const SR_APPROVERS_TEXT = SR_APPROVER_NAMES.join(" or ");
  const MAP_KEY = "KoC_NameMap";

  // Authentication & API
  const TOKEN_EXPIRY_MS = 12 * 60 * 60 * 1000; // fallback only — the JWT's exp wins
  const TOKEN_EXPIRY_MARGIN_MS = 2 * 60 * 1000; // renew when the token has under two minutes left
  const RETRY_ATTEMPTS = 2;
  const RETRY_DELAY_BASE_MS = 1000; // 1 second

  // Game Mechanics
  const TURNS_PER_ATTACK = 120;
  const TURNS_PER_TRADE = 500;
  const XP_REFUND_PER_ATTACK = 120;
  const MINUTES_PER_DAY = 1440;
  // EXP regenerates 1 turn/minute at the player's "Increase Experience" rate (1–6 EXP/min).
  // The rate isn't shown on safe.php, so we capture it from upgrades.php and cache it here.
  const DEFAULT_EXP_PER_TURN = 6;            // KoC max "Increase Experience" level
  const EXP_PER_TURN_KEY = "KoC_ExpPerTurn"; // cached rate (EXP per turn == per minute)
  // Gold-cost upgrade timer (upgrades.php). Its one off-page input is cached here:
  //   - Safe deposit per minute = "SAFE Gold Deposited / Every Minute", captured on safe.php
  const SAFE_DEPOSIT_PER_MIN_KEY = "KoC_SafeDepositPerMin";
  const SAFE_GOLD_CAP = 10e9;                // safe balance caps at 10 Billion
  // "SAFE Forecasts" milestones on safe.php (the SAFE_GOLD_CAP entry is labelled "(MAX)")
  const SAFE_FORECAST_MILESTONES = [1e9, 2e9, 5e9, 9e9, 10e9];

  // Timeouts & Delays
  const ATTACK_LOG_DELAY_MS = 600;
  const NOTIFICATION_DURATION_MS = 5000;

  // Storage & Validation
  const MAX_STRING_LENGTH = 1000;
  const MAX_PLAYER_FIELD_LENGTH = 200;
  const ASSUMED_STORAGE_LIMIT_MB = 5;

  // Performance
  const BATTLEFIELD_DEBOUNCE_MS = 300; // Debounce battlefield observer
  const BATTLEFIELD_COLLECT_DELAY_MS = 200; // Delay before collecting battlefield data

  // ==================== NETWORK GATE ====================
  // Every request this script makes goes through netFetch(); nothing else in
  // the file calls fetch(). Each request names its kind:
  //   'login' — the Sweet Revenge login and the version check. Always allowed.
  //   'read'  — reads alliance data for something drawn on the page. Made only
  //             while "Read from the Sweet Revenge server" is on.
  //   a SYNCS id — sends game data out. Made only while "Send data to the
  //             Sweet Revenge server" is on AND that one share is on.
  // A request that is not allowed is never made: netFetch returns null.
  // The switches live in the ⚙ Data Centre panel.

  const FEATURES_KEY = "KoC_DataCentre_Features";   // one map for every switch in the ⚙ panel
  const NET_DEFAULT_SEND = true;                     // "Send data" when the member has never set it
  const NET_DEFAULT_READ = true;                     // "Read" when the member has never set it

  // Everything the script can send. Each entry is one switch in the ⚙ panel.
  const SYNCS = [
    { id: 'own-stats', name: 'Your Command Centre stats',
      desc: 'When you open your Command Centre: your name, projected income per turn, a last-seen time and your stat ranks.' },
    { id: 'armory', name: 'Your Armory stats',
      desc: 'When you open your Armory: your TIV, your eight ratings with the time they were read, your stat ranks and your gold per stat point.' },
    { id: 'own-history', name: 'Your account history',
      desc: 'Your sidebar balances (gold, safe, vault, experience, turns, rank) at most every 15 minutes, the tables on your own Command Centre, Armory, Upgrades, Safe, Training, Trade, Rewards, Conquest and Game Logs pages when they change, and each conquest result you see.' },
    { id: 'banking-snapshots', name: 'Banked % snapshots',
      desc: 'From the sidebar calculator, at most every 30 minutes: your banked %, gold on hand, gold lost to attacks and projected income.' },
    { id: 'recon', name: 'Recon and stats pages',
      desc: 'When you open a recon report or a player’s stats page: the stats you can see there. When you open your Rewards page: your Unsuccessful Recons and Recon Missions counts.' },
    { id: 'war-list', name: 'War List',
      desc: 'When you open the War List: each player’s sentry, the recommended sab weapon and how many they hold, when and why they were added, and your own 24-hour sab, poison and theft counters for each.' },
    { id: 'attack-pages', name: 'Attack pages and battle reports',
      desc: 'When you open an attack page: the target’s TIV. When you open a battle report of your own attack or raid: gold stolen, hostages and casualties.' },
    { id: 'target-checks', name: 'Target checks',
      desc: 'When you open an attack page: that you checked the target, whether it showed as maxed, how much of its daily sab and theft caps is used, your attempt counters and your ratings with the limits the page shows.' },
    { id: 'sab-caps', name: 'Sabotage caps',
      desc: 'When you open an attack page: the target’s two sabotage numbers, "Total lost from sabbs in the last 24hours" and "Maximum Daily Sabotage loss".' },
    { id: 'missions', name: 'Mission history',
      desc: 'When you open your Intelligence page, an Intelligence file, the Poison, Theft or Attack Log, or one of your own sab, theft or battle reports: the missions listed there, with their results.' },
    { id: 'battlefield', name: 'Battlefield',
      desc: 'When you scroll the battlefield: each player’s name, alliance and rank.' },
    { id: 'inactives', name: 'Inactive Accounts',
      desc: 'When you open the Inactive Accounts page: who is on vacation, since when, and who has been deleted.' },
    { id: 'competitions', name: 'Competitions',
      desc: 'For each running competition you take part in: your attack missions, gold stolen, experience, turns and gold on hand, and your team choice when you pick one.' },
    { id: 'alt-watch-flags', name: 'Alt Watch flags',
      desc: 'Only when you press Save to Alt Watch on a stats page: the flag you chose and your note.' }
  ];
  const SYNC_IDS = new Set(SYNCS.map(s => s.id));

  function netSwitches() {
    const flags = SafeStorage.get(FEATURES_KEY, {});
    return (flags && typeof flags === 'object') ? flags : {};
  }

  function netSendOn() {
    const v = netSwitches()['net:send'];
    return v === undefined ? NET_DEFAULT_SEND : v === true;
  }

  function netReadOn() {
    const v = netSwitches()['net:read'];
    return v === undefined ? NET_DEFAULT_READ : v === true;
  }

  function syncOn(id) {
    return netSwitches()['sync:' + id] !== false;
  }

  function netAllowed(kind) {
    if (kind === 'login') return true;
    if (kind === 'read') return netReadOn();
    return SYNC_IDS.has(kind) && netSendOn() && syncOn(kind);   // an unknown kind never goes out
  }

  async function netFetch(kind, url, options) {
    if (!netAllowed(kind)) {
      debugLog(`⛔ Not sent (${kind} is switched off): ${String(url).split('?')[0]}`);
      return null;
    }
    return fetch(url, options);
  }

  // ==================== DEBUG MODE SYSTEM ====================

  /**
   * Debug Mode System
   * - Stores debug state in localStorage
   * - Provides conditional logging functions
   * - Toggle from the console: KoCDebug.toggle()
   */
  const DEBUG_KEY = "KoC_DebugMode";

  const DebugMode = {
    isEnabled() {
      // Use localStorage directly to avoid circular dependency with SafeStorage
      return localStorage.getItem(DEBUG_KEY) === "true";
    },

    enable() {
      localStorage.setItem(DEBUG_KEY, "true");
      console.log("✅ Debug mode ENABLED - All logs will now be visible");
    },

    disable() {
      localStorage.setItem(DEBUG_KEY, "false");
      console.log("🔇 Debug mode DISABLED - Logs will be hidden");
    },

    toggle() {
      if (this.isEnabled()) {
        this.disable();
      } else {
        this.enable();
      }
      return this.isEnabled();
    }
    // Server debug functions (serverEnable, serverDisable, serverStatus) added later after auth is created
  };

  // Expose to window for console access
  window.KoCDebug = DebugMode;

  /**
   * Conditional debug logger
   * Only logs if debug mode is enabled
   */
  function debugLog(...args) {
    if (DebugMode.isEnabled()) {
      console.log(...args);
    }
  }

  /**
   * Always-visible important messages
   * Use sparingly for critical info only
   */
  function infoLog(...args) {
    console.log(...args);
  }

  // Always show script load message
  infoLog(`✅ KoC Data Centre v${SCRIPT_VERSION} loaded on`, location.pathname);
  if (DebugMode.isEnabled()) {
    infoLog("🐛 Debug mode is ENABLED - Toggle with: KoCDebug.toggle()");
  }

  // ==================== KOC SERVER TIME UTILITIES ====================

  /**
   * Parse KoC Server Time from page and convert to UTC ISO string
   * Server Time is displayed in left panel on all pages
   * Server Time is UTC; timestamps from before 3 Nov 2026 were US Eastern (kocOffsetHours)
   */
  function getKoCServerTimeUTC() {
    try {
      // Find "Server Time" text in the page
      const serverTimeElement = [...document.querySelectorAll('td, div, span')]
        .find(el => el.textContent.includes('Server Time') || el.textContent.match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/));

      if (!serverTimeElement) {
        console.warn('⚠️ Could not find KoC Server Time on page, using local time as fallback');
        return new Date().toISOString();
      }

      // Extract timestamp from text (format: "2025-10-13 06:36:06")
      const match = serverTimeElement.textContent.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
      if (!match) {
        console.warn('⚠️ Could not parse KoC Server Time, using local time as fallback');
        return new Date().toISOString();
      }

      const serverTimeStr = match[1];
      return convertKoCServerTimeToUTC(serverTimeStr);
    } catch (err) {
      console.warn('⚠️ Error parsing KoC Server Time:', err);
      return new Date().toISOString();
    }
  }

  /**
   * The element holding the page's Server Time: a leaf with ONLY a datetime
   * in it. On every page: td.menu_cell > p "Server
   * Time" > table > tbody > tr > th > b "2026-09-19 08:27:16" — the label is
   * in the <p>, six levels up, and the stamp's own table holds nothing else.
   * So, in order:
   *   1. a leaf in the sidebar (td.menu_cell) whose nearest <p> or <td> says
   *      "Server Time" — the clock itself, whatever else the page prints;
   *   2. else the leaf nearest a "Server Time" label, up to 8 levels up (or
   *      in its own table) — the nearest only: a lone stamp in a mission box
   *      is also 8 levels under the whole page's layout row, so a tie is no
   *      answer;
   *   3. else the page's only datetime leaf.
   * null when none of those settles it (never a guess). Read-only.
   */
  function findServerTimeLeaf() {
    const leaves = [...document.querySelectorAll('b,td,th,span,div,font')].filter(e =>
      e.children.length === 0 && /^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\s*$/.test(e.textContent || ''));
    if (!leaves.length) return null;
    const said = (el) => !!el && /Server Time/i.test(el.textContent || '');
    const sidebar = leaves.filter(e => e.closest('td.menu_cell') && said(e.closest('p,td')));
    if (sidebar.length === 1) return sidebar[0];
    const depth = (e) => {
      let c = e.parentNode;
      for (let d = 1; d <= 8 && c; d++, c = c.parentNode) { if (said(c)) return d; }
      return said(e.closest('table')) ? 9 : Infinity;
    };
    const ranked = (sidebar.length ? sidebar : leaves).map(e => ({ e, d: depth(e) }))
      .filter(x => x.d < Infinity).sort((a, b) => a.d - b.d);
    if (ranked.length && (ranked.length === 1 || ranked[0].d < ranked[1].d)) return ranked[0].e;
    return leaves.length === 1 ? leaves[0] : null;
  }

  /**
   * The Server Time this page was drawn with, as the game printed it
   * ('YYYY-MM-DD HH:MM:SS', KoC time), or null. Strict: no fallback, never
   * the member's own clock. Only right as the page is read (PAGE_KOC_TIME):
   * once the clock below starts ticking, the leaf holds the ticking time.
   */
  function readPageServerTime() {
    const leaf = findServerTimeLeaf();
    const m = leaf && (leaf.textContent || '').match(/^\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\s*$/);
    return m ? `${m[1]} ${m[2]}` : null;
  }

  // The page's own Server Time as the game rendered it, read ONCE by the
  // first statement of runFeatures — before any step, the ticking clock
  // included. A sab or theft report the member lands on is stamped with it,
  // and every attack-page check and War List read carries it (pageInfo).
  let PAGE_KOC_TIME = null;

  /** This page view's navigation entry: { type, redirects }, each null when the browser does not say. */
  function pageNavEntry() {
    try {
      const nav = performance.getEntriesByType('navigation')[0];
      return {
        type: nav && typeof nav.type === 'string' ? nav.type : null,
        redirects: nav && Number.isFinite(nav.redirectCount) ? nav.redirectCount : null
      };
    } catch (e) {
      return { type: null, redirects: null };
    }
  }

  /** 'navigate' | 'reload' | 'back_forward' | 'prerender', or null. */
  function pageNavType() {
    return pageNavEntry().type;
  }

  /**
   * How this page was reached and when it was drawn: { nav, at } for the
   * roster, which skips a page restored with Back / Forward or drawn more
   * than 10 minutes before it arrived — those counters are old, not a new look.
   */
  function pageInfo() {
    return { nav: pageNavType(), at: PAGE_KOC_TIME };
  }

  // ==================== ONE SHARED SIDEBAR TICK ====================
  // The sidebar has three clocks: the game's own "Era N ends in …" countdown
  // (age-countdown.js) plus our Server Time clock and Era day line. Ticking on
  // separate timers they drift apart by a second. So ours follow the GAME's
  // countdown: each time it rewrites its text, both of ours redraw from the
  // same number — server time = era end − remaining, elapsed = remaining's
  // complement. One second, three clocks, always agreeing. Display-only.

  /** The sidebar's era countdown span (has data-end), or null. */
  function findEraCountdown() {
    const span = document.querySelector('td.menu_cell span[data-age-countdown]');
    return span && +span.getAttribute('data-end') ? span : null;
  }

  /** Seconds left on the countdown as its text reads right now, or null. */
  function countdownRemaining(span) {
    const t = (span && span.textContent) || '';
    if (!/ends in/i.test(t)) return null;
    const units = { day: 0, hour: 0, minute: 0, second: 0 };
    let hit = false;
    t.replace(/(\d+)\s*(day|hour|minute|second)s?\b/gi, (all, num, unit) => { units[unit.toLowerCase()] = +num; hit = true; return all; });
    if (!hit) return null;
    const n = (u) => units[u];
    return n('day') * 86400 + n('hour') * 3600 + n('minute') * 60 + n('second');
  }

  const __gameTickFns = [];
  let __gameTickObs = null;
  /**
   * Calls fn(remainingSeconds, span) now and on every redraw of the game's
   * countdown. false when there is no readable countdown (the caller then
   * keeps its own timer).
   */
  function onGameTick(fn) {
    const span = findEraCountdown();
    if (!span || countdownRemaining(span) == null) return false;
    __gameTickFns.push(fn);
    fn(countdownRemaining(span), span);
    if (!__gameTickObs) {
      let last = null;
      __gameTickObs = new MutationObserver(() => {
        const r = countdownRemaining(span);
        if (r == null || r === last) return;
        last = r;
        __gameTickFns.forEach(f => { try { f(r, span); } catch (e) { /* one clock never stops the other */ } });
      });
      __gameTickObs.observe(span, { characterData: true, childList: true, subtree: true });
    }
    return true;
  }

  // Live-ticking Server Time clock. DISPLAY-ONLY: anchors to the value KoC rendered and
  // advances it in step with the game's era countdown (onGameTick), or locally each
  // second on a page without one (re-synced on every page load, so it can't drift).
  // Compliant — no network, no game actions; it only rewrites the clock's own text node.
  let __serverClockId = null;
  function startServerClock() {
    if (__serverClockId) return;
    // The leaf holding ONLY a datetime — the sidebar clock (findServerTimeLeaf);
    // null when ambiguous: skip rather than tick the wrong one.
    const leaf = findServerTimeLeaf();
    if (!leaf) return;
    const m = (leaf.textContent || '').match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
    if (!m) return;
    const p = n => (n < 10 ? '0' + n : '' + n);
    // Follow the game's countdown: the printed time minus (end − remaining) is
    // the clock's zone offset (whole quarter-hours; 0 while the clock is UTC).
    const span = findEraCountdown();
    const r0 = countdownRemaining(span);
    if (span && r0 != null) {
      const end = +span.getAttribute('data-end');
      const printed = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
      const offset = Math.round((printed - (end - r0)) / 900) * 900;
      __serverClockId = 'game';
      onGameTick((r) => {
        if (!leaf.isConnected) return;
        const d = new Date((end - r + offset) * 1000);
        leaf.textContent = `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
      });
      debugLog('🕐 Server clock following the era countdown');
      return;
    }
    const baseMs = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();
    const t0 = Date.now();
    __serverClockId = setInterval(() => {
      if (!leaf.isConnected) { clearInterval(__serverClockId); __serverClockId = null; return; }
      const d = new Date(baseMs + (Date.now() - t0));
      leaf.textContent = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    }, 1000);
    debugLog('🕐 Server clock ticking');
  }

  // When each era opened, in UTC epoch seconds. The page gives only the era's
  // END (span[data-age-countdown] data-end), so the start has to be known.
  // Era 24 opened 3 Nov 2026 11:00 server time (UTC). Add a line here when a
  // new era opens — an era not listed
  // simply shows no "day" line.
  const ERA_STARTS = {
    24: Date.UTC(2026, 10, 3, 11, 0, 0) / 1000
  };

  /**
   * "Era 24 day 5 of 83 — 4 days 11 hours 4 minutes 45 seconds in." under the
   * sidebar's Game Time countdown. DISPLAY-ONLY: elapsed = (end − start) −
   * the countdown's own remaining time, redrawn on the countdown's tick
   * (onGameTick), so the two lines always add up to the era's length. Adds a
   * line beside the game's span and never touches the span. No network.
   */
  let __eraElapsedOn = false;
  function startEraElapsed() {
    if (__eraElapsedOn || document.getElementById('dc-era-elapsed')) return;
    const span = findEraCountdown();
    if (!span || !span.parentNode) return;
    const label = span.getAttribute('data-label') || (span.textContent.match(/Era \d+/) || [''])[0];
    const era = +((label.match(/Era (\d+)/) || [])[1]);
    const start = ERA_STARTS[era];
    const end = +span.getAttribute('data-end');
    if (!start || !(end > start)) return;
    const line = document.createElement('div');
    line.id = 'dc-era-elapsed';
    line.style.cssText = 'margin-top:4px;font-size:9pt;font-weight:bold;color:#9fdcff;text-align:center;';
    const totalDays = Math.round((end - start) / 86400);
    const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
    const ok = onGameTick((r) => {
      const s = Math.max(0, end - start - r);
      const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
      line.textContent = `${label} day ${d + 1} of ${totalDays} — ` +
        `${plural(d, 'day')} ${plural(h, 'hour')} ${plural(m, 'minute')} ${plural(sec, 'second')} in.`;
    });
    if (!ok) return;
    span.parentNode.appendChild(line);
    __eraElapsedOn = true;
    debugLog('📅 Era elapsed line ticking');
  }

  // ==================== VAULT TAX WARNING ====================
  // Vault gold can't be stolen, but the game takes 5% of it every 6 hours, at
  // 00:00, 06:00, 12:00 and 18:00 server time (Game Logs: "Vault Tax 5% every
  // 6 hours", e.g. 7,292,797 → 364,640 deducted at 18:00:01). When the sidebar
  // shows gold in your Vault, a warning with a live countdown appears in the
  // "Era N ends in …" banner from VAULT_TAX_LEAD_SECS before each tax.
  // DISPLAY-ONLY: reads the sidebar and the clock; no network, no game actions.
  const VAULT_TAX_RATE = 0.05;
  const VAULT_TAX_EVERY_SECS = 6 * 3600;
  const VAULT_TAX_LEAD_SECS = 15 * 60;

  /** The main "Era N ends in …" banner cell (not the sidebar's), or null. */
  function findEraBannerCell() {
    const inSide = el => !!el.closest('td.menu_cell');
    const span = [...document.querySelectorAll('[data-age-countdown]')].find(el => !inSide(el));
    if (span) return span.closest('th,td') || span.parentNode;
    const cell = [...document.querySelectorAll('th,td')].find(el =>
      !inSide(el) && /^\s*Era \d+ ends in\b/i.test(el.textContent || '') && (el.textContent || '').trim().length < 120);
    return cell || null;
  }

  /** "Vault tax in 4m 12s — …" text for secs left and vault gold (pure: offline-tested). */
  function vaultTaxWarningText(secsLeft, vault) {
    const m = Math.floor(secsLeft / 60), sec = secsLeft % 60;
    const when = m > 0 ? `${m}m ${String(sec).padStart(2, '0')}s` : `${sec}s`;
    const loss = Math.round(vault * VAULT_TAX_RATE);   // the game rounds: 7,292,797 → 364,640
    return `⚠️ Vault tax in ${when} — you will lose ${loss.toLocaleString('en-US')} gold if you don't spend your vault`;
  }

  /** Seconds from a server wall-clock time (epoch secs, read as UTC) to the next tax. */
  function vaultTaxSecsLeft(serverSecs) {
    const into = ((serverSecs % VAULT_TAX_EVERY_SECS) + VAULT_TAX_EVERY_SECS) % VAULT_TAX_EVERY_SECS;
    return into === 0 ? 0 : VAULT_TAX_EVERY_SECS - into;
  }

  let __vaultTaxOn = false;
  function startVaultTaxWarning() {
    if (__vaultTaxOn || document.getElementById('dc-vault-tax')) return;
    const side = readOwnSidebar();
    const vault = side && side.vaultN;
    if (!(vault > 0)) return;                 // nothing in the vault, nothing to warn about
    const cell = findEraBannerCell() || (findEraCountdown() || {}).parentNode;
    if (!cell) return;

    const line = document.createElement('div');
    line.id = 'dc-vault-tax';
    line.style.cssText = 'display:none;margin-top:4px;font-weight:bold;font-size:10pt;color:#fbbf24;text-align:center;';
    cell.appendChild(line);
    __vaultTaxOn = true;

    const paint = serverSecs => {
      if (!line.isConnected) return;
      const left = vaultTaxSecsLeft(Math.floor(serverSecs));
      if (left > VAULT_TAX_LEAD_SECS || left === 0) { line.style.display = 'none'; return; }
      line.textContent = vaultTaxWarningText(left, vault);
      line.style.color = left <= 60 ? '#f87171' : '#fbbf24';
      line.style.display = '';
    };

    // The page's printed Server Time (KoC wall clock), read once at page load.
    const printedM = (PAGE_KOC_TIME || readPageServerTime() || '').match(/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
    const printed = printedM ? Date.UTC(+printedM[1], +printedM[2] - 1, +printedM[3], +printedM[4], +printedM[5], +printedM[6]) / 1000 : null;

    // Follow the game's own era countdown, like the Server Time clock does.
    const span = findEraCountdown();
    const r0 = countdownRemaining(span);
    if (span && r0 != null) {
      const end = +span.getAttribute('data-end');
      // Wall clock = UTC + offset (0 while the clock is UTC); whole quarter-hours.
      const offset = printed != null ? Math.round((printed - (end - r0)) / 900) * 900 : 0;
      if (onGameTick(r => paint(end - r + offset))) { debugLog(`🏦 Vault tax warning armed (vault ${vault.toLocaleString()})`); return; }
    }
    // No readable countdown: tick off the page's printed time (or this device's UTC).
    const base = printed != null ? printed : Date.now() / 1000;
    const t0 = Date.now();
    const id = setInterval(() => {
      if (!line.isConnected) { clearInterval(id); return; }
      paint(base + (Date.now() - t0) / 1000);
    }, 1000);
    paint(base);
    debugLog(`🏦 Vault tax warning armed, local timer (vault ${vault.toLocaleString()})`);
  }

  /**
   * Whether US Eastern DST (EDT, UTC-4) applies on the given date.
   * US DST: 2nd Sunday in March to 1st Sunday in November.
   */
  // KoC's clock is UTC from 3 Nov 2026 and was US Eastern before. The date
  // the game printed decides. Same rule as the server's utils/koc-clock.js.
  const KOC_UTC_FROM = '2026-11-03';
  const KOC_UTC_FROM_MS = Date.UTC(2026, 10, 3);

  /** Hours to ADD to a KoC wall-clock time (month 0-11) to get UTC. */
  function kocOffsetHours(year, month, day) {
    const iso = year + '-' + String(month + 1).padStart(2, '0') + '-' + String(day).padStart(2, '0');
    if (iso >= KOC_UTC_FROM) return 0;
    return isEasternDST(year, month, day) ? 4 : 5; // EDT = UTC-4, EST = UTC-5
  }

  function isEasternDST(year, month, day) {
    const marchFirst = new Date(year, 2, 1);
    const dstStart = 8 + (7 - marchFirst.getDay()) % 7; // 2nd Sunday in March

    const novFirst = new Date(year, 10, 1);
    const dstEnd = 1 + (7 - novFirst.getDay()) % 7; // 1st Sunday in November

    const currentDate = new Date(year, month, day);
    return currentDate >= new Date(year, 2, dstStart) && currentDate < new Date(year, 10, dstEnd);
  }

  /**
   * Convert KoC Server Time string to UTC ISO format
   * @param {string} serverTimeStr - Format: "2025-10-13 06:36:06"
   * @returns {string} UTC ISO string like "2025-10-13T10:36:06.000Z"
   */
  function convertKoCServerTimeToUTC(serverTimeStr) {
    try {
      const parts = serverTimeStr.match(/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
      if (!parts) throw new Error('Invalid timestamp format');

      const year = parseInt(parts[1]);
      const month = parseInt(parts[2]) - 1; // JS months are 0-indexed
      const day = parseInt(parts[3]);
      const hour = parseInt(parts[4]);
      const minute = parseInt(parts[5]);
      const second = parseInt(parts[6]);

      const offset = kocOffsetHours(year, month, day); // 0 for UTC dates

      // Wall-clock time in KoC's zone -> UTC by adding the offset
      const date = new Date(Date.UTC(year, month, day, hour + offset, minute, second));
      return date.toISOString();
    } catch (err) {
      console.warn('⚠️ Error converting KoC Server Time to UTC:', err);
      return new Date().toISOString();
    }
  }

  /**
   * Convert UTC ISO string to KoC Server Time string
   * @param {string} utcIsoString - UTC ISO string like "2026-11-22T13:57:05.000Z"
   * @returns {string} KoC Server Time string like "2026-11-22 13:57:05"
   */
  function convertUTCToKoCServerTime(utcIsoString) {
    try {
      const utcDate = new Date(utcIsoString);
      const year = utcDate.getUTCFullYear();
      const month = utcDate.getUTCMonth();
      const day = utcDate.getUTCDate();
      const hour = utcDate.getUTCHours();
      const minute = utcDate.getUTCMinutes();
      const second = utcDate.getUTCSeconds();

      // The game's clock is UTC; before 3 Nov 2026 it was US Eastern
      const offset = utcDate.getTime() >= KOC_UTC_FROM_MS
        ? 0
        : (isEasternDST(year, month, day) ? 4 : 5); // EDT = UTC-4, EST = UTC-5

      // Subtract offset from UTC to get KoC's wall clock
      const easternHour = hour - offset;
      const easternDate = new Date(Date.UTC(year, month, day, easternHour, minute, second));

      // Format as "YYYY-MM-DD HH:MM:SS"
      const y = easternDate.getUTCFullYear();
      const m = String(easternDate.getUTCMonth() + 1).padStart(2, '0');
      const d = String(easternDate.getUTCDate()).padStart(2, '0');
      const h = String(easternDate.getUTCHours()).padStart(2, '0');
      const min = String(easternDate.getUTCMinutes()).padStart(2, '0');
      const sec = String(easternDate.getUTCSeconds()).padStart(2, '0');

      return `${y}-${m}-${d} ${h}:${min}:${sec}`;
    } catch (err) {
      console.warn('⚠️ Error converting UTC to KoC Server Time:', err);
      return '';
    }
  }

  // ==================== ERROR HANDLING UTILITIES ====================

  /**
   * Error handler with user-friendly messages
   */
  class ErrorHandler {
    static LOG_LEVELS = {
      ERROR: 'error',
      WARN: 'warn',
      INFO: 'info',
      DEBUG: 'debug'
    };

    static log(level, message, error = null, context = {}) {
      const timestamp = new Date().toISOString();
      const prefix = `[KoC-DataCentre ${timestamp}]`;

      const logData = {
        level,
        message,
        error: error ? {
          message: error.message,
          stack: error.stack,
          name: error.name
        } : null,
        context
      };

      switch (level) {
        case this.LOG_LEVELS.ERROR:
          console.error(`${prefix} ❌`, message, logData);
          break;
        case this.LOG_LEVELS.WARN:
          console.warn(`${prefix} ⚠️`, message, logData);
          break;
        case this.LOG_LEVELS.INFO:
          console.info(`${prefix} ℹ️`, message, logData);
          break;
        case this.LOG_LEVELS.DEBUG:
          debugLog(`${prefix} 🔍`, message, logData);
          break;
      }
    }

    static getUserFriendlyMessage(error, context = '') {
      if (!error) return 'An unknown error occurred';

      // Network errors
      if (error.message.includes('fetch') || error.message.includes('NetworkError') || error instanceof TypeError) {
        return `Network error: Unable to connect to server. Please check your internet connection.`;
      }

      // Auth errors
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        return `Authentication failed. Please log in again.`;
      }

      // localStorage quota
      if (error.name === 'QuotaExceededError') {
        return `Browser storage is full. Some features may not work properly. Try clearing old data.`;
      }

      // API errors
      if (error.message.includes('API') || error.message.includes('500')) {
        return `Server error. The Sweet Revenge API may be experiencing issues. Please try again later.`;
      }

      // Default
      return context ? `${context}: ${error.message}` : error.message;
    }

    static showUserError(message, error = null) {
      const friendlyMsg = error ? this.getUserFriendlyMessage(error) : message;
      console.error('User error shown:', friendlyMsg, error);

      // Show non-intrusive notification
      this.showNotification(friendlyMsg, 'error');
    }

    static showNotification(message, type = 'info') {
      // No toasts on read-only pages (War List / Farm List): a toast is a DOM
      // change, and the game allows none there. The console still has it.
      if (READ_ONLY_PAGE) {
        debugLog(`[toast suppressed on read-only page] ${message}`);
        return;
      }

      // Create non-intrusive notification div
      const notification = document.createElement('div');
      notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'error' ? '#f44336' : type === 'warn' ? '#ff9800' : '#4CAF50'};
        color: white;
        padding: 15px 20px;
        border-radius: 4px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        z-index: 10000;
        max-width: 350px;
        font-family: Arial, sans-serif;
        font-size: 14px;
        line-height: 1.4;
        animation: slideIn 0.3s ease-out;
      `;
      notification.textContent = message;

      // Add animation (style injected once, reused by every toast)
      if (!document.getElementById('kdc-toast-style')) {
        const style = document.createElement('style');
        style.id = 'kdc-toast-style';
        style.textContent = `
          @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
          }
        `;
        document.head.appendChild(style);
      }
      document.body.appendChild(notification);

      // Auto-remove after configured duration
      setTimeout(() => {
        notification.style.transition = 'opacity 0.3s';
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
      }, NOTIFICATION_DURATION_MS);
    }
  }

  /**
   * Safe localStorage wrapper with quota handling
   */
  class SafeStorage {
    static get(key, defaultValue = null) {
      try {
        const item = localStorage.getItem(key);
        if (item === null) return defaultValue;

        try {
          return JSON.parse(item);
        } catch {
          return item; // Return as string if not JSON
        }
      } catch (error) {
        ErrorHandler.log(ErrorHandler.LOG_LEVELS.ERROR, `Failed to read from localStorage: ${key}`, error);
        return defaultValue;
      }
    }

    static set(key, value) {
      try {
        const serialized = typeof value === 'string' ? value : JSON.stringify(value);
        localStorage.setItem(key, serialized);
        return true;
      } catch (error) {
        if (error.name === 'QuotaExceededError') {
          ErrorHandler.log(ErrorHandler.LOG_LEVELS.ERROR, 'localStorage quota exceeded', error, { key });

          // Try once more (the browser may have freed space)
          try {
            const serialized = typeof value === 'string' ? value : JSON.stringify(value);
            localStorage.setItem(key, serialized);
            ErrorHandler.log(ErrorHandler.LOG_LEVELS.INFO, 'Successfully stored after cleanup', null, { key });
            return true;
          } catch (retryError) {
            ErrorHandler.showUserError(null, error);
            return false;
          }
        } else {
          ErrorHandler.log(ErrorHandler.LOG_LEVELS.ERROR, `Failed to write to localStorage: ${key}`, error);
          return false;
        }
      }
    }

    static remove(key) {
      try {
        localStorage.removeItem(key);
        return true;
      } catch (error) {
        ErrorHandler.log(ErrorHandler.LOG_LEVELS.ERROR, `Failed to remove from localStorage: ${key}`, error);
        return false;
      }
    }

    static getUsage() {
      try {
        let total = 0;
        for (let key in localStorage) {
          if (localStorage.hasOwnProperty(key)) {
            total += localStorage[key].length + key.length;
          }
        }
        return {
          used: total,
          usedKB: (total / 1024).toFixed(2),
          // Most browsers allow 5-10MB
          percentUsed: ((total / (ASSUMED_STORAGE_LIMIT_MB * 1024 * 1024)) * 100).toFixed(1)
        };
      } catch (error) {
        return { used: 0, usedKB: 0, percentUsed: 0 };
      }
    }
  }


  // ==================== SECURITY UTILITIES ====================

  /**
   * Escape HTML to prevent XSS attacks
   * Converts dangerous characters to HTML entities
   */
  function escapeHtml(unsafe) {
    if (unsafe == null || unsafe === undefined) return '';
    return String(unsafe)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /**
   * Sanitize numeric input
   * Returns a safe number or default value
   */
  function sanitizeNumber(value, defaultValue = 0, min = 0, max = Number.MAX_SAFE_INTEGER) {
    // Remove commas before parsing (e.g., "21,081,172" → "21081172")
    const cleanValue = typeof value === 'string' ? value.replace(/,/g, '') : value;
    const num = parseFloat(cleanValue);

    // Check for invalid numbers
    if (isNaN(num) || !isFinite(num)) {
      return defaultValue;
    }

    // Clamp to bounds
    return Math.max(min, Math.min(max, num));
  }

  /**
   * Sanitize integer input
   */
  function sanitizeInteger(value, defaultValue = 0, min = 0, max = Number.MAX_SAFE_INTEGER) {
    return Math.floor(sanitizeNumber(value, defaultValue, min, max));
  }

  /**
   * Sanitize string input
   * Removes control characters and limits length
   */
  function sanitizeString(value, maxLength = MAX_STRING_LENGTH) {
    if (value == null || value === undefined) return '';

    let str = String(value);

    // Remove control characters except newline/tab
    str = str.replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '');

    // Limit length
    if (str.length > maxLength) {
      str = str.substring(0, maxLength);
    }

    return str.trim();
  }

  /**
   * Sanitize player data object
   * Ensures all fields are safe before storage/display
   */
  function sanitizePlayerData(data) {
    const sanitized = {};

    for (const [key, value] of Object.entries(data)) {
      if (value == null) continue;

      // Skip timestamp fields (e.g., strikeActionTime, spyRatingTime) - keep as ISO strings
      if (key.endsWith('Time') || key.endsWith('UpdatedBy') || key === 'lastSeen') {
        sanitized[key] = value; // Keep timestamps as-is
        continue;
      }

      // Player ID - keep as string but validate it's numeric
      if (key === 'id' || key === 'playerId' || key === 'attackerId' || key === 'targetId') {
        // Ensure it's a valid ID (numeric string or number)
        const numericValue = String(value).replace(/[^0-9]/g, '');
        sanitized[key] = numericValue || value; // Keep as string
      }
      // Numeric fields (convert to integer)
      else if (key === 'tiv' || key === 'gold' || key === 'treasury' ||
          key === 'economy' || key === 'projectedIncome' ||
          key.includes('Rating') || key.includes('Action')) {
        sanitized[key] = sanitizeInteger(value);
      }
      // Age minutes - keep decimal precision
      else if (key === 'ageMinutes') {
        sanitized[key] = sanitizeNumber(value);
      }
      // String fields
      else if (typeof value === 'string') {
        sanitized[key] = sanitizeString(value, MAX_PLAYER_FIELD_LENGTH);
      }
      // Keep other types as-is (dates, booleans, etc.)
      else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Validate and sanitize calculator inputs
   */
  function validateCalculatorInput(turns, exp, avgGold) {
    const result = {
      valid: true,
      errors: [],
      values: {
        turns: sanitizeInteger(turns, 0, 0, 1000000),
        exp: sanitizeInteger(exp, 0, 0, 100000000),
        avgGold: sanitizeNumber(avgGold, 0, 0, 1000000000000)
      }
    };

    // Check for obviously invalid inputs
    if (result.values.turns === 0 && result.values.exp === 0) {
      result.errors.push('Please enter turns and/or experience');
      result.valid = false;
    }

    return result;
  }

  // ==================== PERFORMANCE UTILITIES ====================

  /**
   * Debounce function - delays execution until after delay has passed since last call
   * Useful for expensive operations that shouldn't run on every event
   *
   * @param {Function} func - The function to debounce
   * @param {number} delay - The delay in milliseconds
   * @returns {Function} - The debounced function
   */
  function debounce(func, delay) {
    let timeoutId = null;

    return function debounced(...args) {
      // Clear the previous timeout
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      // Set a new timeout
      timeoutId = setTimeout(() => {
        func.apply(this, args);
      }, delay);
    };
  }

  // ==================== OWN IDENTITY ON THE PAGE ====================

  // True when an element lives inside script-injected UI (SR stats panel,
  // competition panels, calculators) rather than native KoC markup.
  function isInjectedContent(el) {
    return !!el.closest('[data-koc-injected], #sr-stats-tables, [id^="koc-comp-panel"], [class*="sr-stat-"]');
  }

  // Find your own id/name from the native "User Info" table on base.php:
  // a row whose label cell is exactly "Name" and whose value cell holds your
  // stats.php link. Never read identity from the first stats.php link on the
  // page — injected leaderboards and farm lists come first in DOM order.
  function findOwnIdentityRow() {
    for (const row of document.querySelectorAll("tr")) {
      const labelCell = row.querySelector("td, th");
      if (!labelCell || !/^name:?$/i.test(labelCell.innerText.trim())) continue;
      const link = row.querySelector("a[href*='stats.php?id=']");
      if (!link || isInjectedContent(link)) continue;
      const id = link.href.match(/id=(\d+)/)?.[1];
      const name = link.textContent.trim();
      if (id && name) return { id, name, row };
    }
    return null;
  }

  function findOwnIdentityOnPage() {
    const own = findOwnIdentityRow();
    return own ? { id: own.id, name: own.name } : null;
  }

  // ==================== SR LOGIN: device key store ====================
  // One record per browser profile, kept in
  // IndexedDB "KoC_SR_DEVICE" (store "device", key "current"):
  //   { v, deviceId, playerId, playerName, privateKey, publicJwk, label,
  //     status: "pending" | "active" | "suspended",
  //     code, codeExpiresAt, codeExpired, enrolledAt, lastCheckAt, mismatch }
  // privateKey is a NON-EXTRACTABLE CryptoKey: page code can sign with it but
  // cannot read it, so a copy of the browser's storage files is not a login.
  const SrDeviceStore = {
    _run(mode, fn) {
      return new Promise((resolve, reject) => {
        let open;
        try { open = indexedDB.open(DEVICE_DB, 1); } catch (err) { reject(err); return; }
        open.onupgradeneeded = () => { open.result.createObjectStore("device"); };
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const idb = open.result;
          try {
            const tx = idb.transaction("device", mode);
            const req = fn(tx.objectStore("device"));
            tx.oncomplete = () => { idb.close(); resolve(req ? req.result : undefined); };
            tx.onabort = tx.onerror = () => { idb.close(); reject(tx.error); };
          } catch (err) { idb.close(); reject(err); }
        };
      });
    },
    async load() { return (await this._run("readonly", (s) => s.get("current"))) || null; },
    async save(rec) { await this._run("readwrite", (s) => s.put(rec, "current")); },
    async clear() { await this._run("readwrite", (s) => s.delete("current")); }
  };

  // ==================== SR LOGIN: protocol ====================
  // What the browser says to the API. Nothing here touches the game: every
  // request goes to the Sweet Revenge server, and the code that proves who
  // owns the account is sent in an in-game message BY HAND.

  const srOnCommandCentre = () => /\/base\.php/i.test(location.pathname);

  function srB64u(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // "Chrome on Windows": so a member can tell their browsers apart in the list.
  function srBrowserLabel() {
    const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
    const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
      : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
    const os = /Android/.test(ua) ? "Android" : /iPhone|iPad|iPod/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows"
      : /Mac OS X/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : "";
    return os ? `${browser} on ${os}` : browser;
  }

  // One request to the API. Resolves { status, body } for any HTTP answer and
  // throws only when the server could not be reached (or took over 15 s).
  async function srFetch(path, { method = "GET", body, token } = {}) {
    const headers = { "X-Script-Name": SCRIPT_NAME, "X-Script-Version": SCRIPT_VERSION };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers["Authorization"] = "Bearer " + token;
    const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), 15000) : null;
    try {
      const resp = await netFetch('login', `${API_URL}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: ctl ? ctl.signal : undefined
      });
      return { status: resp.status, body: (await resp.json().catch(() => ({}))) || {} };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  // How long a waiting browser leaves between "am I approved yet?" checks.
  // The server allows 60 session calls per browser per hour, so the checks
  // thin out: every 10 s for the first minute, every minute up to ten
  // minutes, then every two minutes.
  function srPendingCheckDelay(rec, now) {
    const age = now - (rec.enrolledAt || 0);
    return age < 60e3 ? 10e3 : age < 600e3 ? 60e3 : 120e3;
  }

  const SrDevice = {
    // A new key pair. extractable = false: the private key cannot be exported.
    async newKey() {
      const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
      const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
      return { privateKey: pair.privateKey, publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
    },

    // Ask to become a browser for this player. This is everything it sends.
    enroll(identity, publicJwk) {
      return srFetch("/auth/device/enroll", {
        method: "POST",
        body: { statsId: String(identity.id), name: identity.name, publicKey: publicJwk, label: srBrowserLabel() }
      });
    },

    // Fetch a one-time challenge, sign "<prefix><challenge>.<deviceId>" with
    // the device key (ECDSA P-256, SHA-256, raw 64-byte signature) and post it.
    async signed(path, rec, prefix, extra) {
      const c = await srFetch("/auth/challenge");
      if (c.status !== 200 || !c.body.challenge) return c;
      const text = `${prefix}${c.body.challenge}.${String(rec.deviceId).toLowerCase()}`;
      const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, rec.privateKey, new TextEncoder().encode(text));
      return srFetch(path, {
        method: "POST",
        body: Object.assign({ deviceId: rec.deviceId, challenge: c.body.challenge, signature: srB64u(sig) }, extra || {})
      });
    },

    session(rec) { return this.signed("/auth/device/session", rec, ""); },

    mismatch(rec, pageStatsId) {
      return this.signed("/auth/device/mismatch", rec, `mismatch:${pageStatsId}:`, { pageStatsId: String(pageStatsId) });
    },

    list(token) { return srFetch("/auth/devices", { token }); },

    revoke(token, target) { return srFetch("/auth/device/revoke", { method: "POST", token, body: { deviceId: target } }); }
  };

  // ==================== AUTH MANAGER ====================
  //
  // Two logins live here:
  //   "device": the browser holds an approved key and trades a signature for
  //             a 15 minute token. This is the login that proves ownership.
  //   "legacy": the old POST /auth/koc {id, name}. Kept ONLY so nobody loses
  //             the script while their browser waits for approval, or before
  //             they have pressed Login.
  // The token is kept in memory and sessionStorage, never in localStorage.
  // Open tabs pass it to each other over a BroadcastChannel, so a new tab
  // does not have to ask the server for its own.
  //
  // auth.state.code is what the Command Center box shows:
  //   signed_out | legacy | pending | code_expired | active | mismatch |
  //   suspended | revoked | gone | not_allowed | outdated | offline
  class AuthManager {
    constructor() {
      this.token = null;
      this.authData = null;   // { token, id, name, role, expiry, kind, deviceId }
      this.device = null;     // this browser's record from SrDeviceStore
      this.state = { code: "signed_out" };
      this.initPromise = null;
      this.refreshPromise = null;
      this.listeners = new Map();
      this.channel = null;
      this.askWaiter = null;
      this.lastHeard = null;
      this.busy = false;
      this.openChannel();
    }

    // Decode a JWT payload (base64url). Returns null if it can't be read.
    static decodeJwt(token) {
      try {
        let b64 = String(token).split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        return JSON.parse(atob(b64));
      } catch (err) {
        return null;
      }
    }

    // When to treat the token as expired: the JWT's own exp, two minutes
    // early, so a token is renewed before a request can go out on one about
    // to lapse (#96, #92). Falls back to TOKEN_EXPIRY_MS only if exp can't be read.
    static expiryFor(token) {
      const payload = AuthManager.decodeJwt(token);
      if (payload && Number.isFinite(payload.exp)) {
        return Math.max(Date.now(), payload.exp * 1000 - TOKEN_EXPIRY_MARGIN_MS);
      }
      return Date.now() + TOKEN_EXPIRY_MS;
    }

    // ---- the token, in this tab and across tabs ----

    readSession() {
      try {
        const s = JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
        return s && s.token && s.expiry > Date.now() ? s : null;
      } catch (err) {
        return null;
      }
    }

    writeSession(s) {
      try {
        if (s) sessionStorage.setItem(SESSION_KEY, JSON.stringify(s));
        else sessionStorage.removeItem(SESSION_KEY);
      } catch (err) { /* private mode: the token then lives in memory only */ }
    }

    // Who this tab is logged in as, or null.
    getStoredAuth() {
      return this.authData || this.readSession();
    }

    makeSession(token, id, name, kind, deviceId) {
      const payload = AuthManager.decodeJwt(token);
      return {
        token,
        id: String(id),
        name,
        role: (payload && payload.role) || 'member',
        expiry: AuthManager.expiryFor(token),
        kind,
        deviceId: deviceId || null
      };
    }

    adopt(session, announce) {
      this.token = session.token;
      this.authData = session;
      this.writeSession(session);
      if (announce) this.post({ t: "token", session });
      this.emit('authChanged', session);
    }

    dropSession(announce) {
      this.token = null;
      this.authData = null;
      this.lastHeard = null;
      this.writeSession(null);
      if (announce) this.post({ t: "clear" });
    }

    // Does this token belong to the login this browser has right now?
    fits(s, rec) {
      if (!s || !s.token || !(s.expiry > Date.now())) return false;
      if (s.kind === "device") return !!rec && rec.status === "active" && rec.deviceId === s.deviceId;
      const legacy = SafeStorage.get(LEGACY_ID_KEY, null);
      return s.kind === "legacy" && !!legacy && String(legacy.id) === String(s.id) && (!rec || rec.status === "pending");
    }

    openChannel() {
      if (typeof BroadcastChannel === "undefined") return;
      try {
        this.channel = new BroadcastChannel(SESSION_CHANNEL);
        this.channel.onmessage = (ev) => {
          const m = ev.data || {};
          if (m.t === "ask") {
            if (this.authData && this.authData.expiry > Date.now()) this.post({ t: "token", session: this.authData });
          } else if (m.t === "token" && m.session) {
            if (m.session.kind === "device" || !this.lastHeard || this.lastHeard.kind !== "device") this.lastHeard = m.session;
            if (this.askWaiter) this.askWaiter(m.session);
            // An open tab moves on to the newer token of the same login.
            const mine = this.authData;
            if (mine && m.session.kind === mine.kind && m.session.id === mine.id &&
                m.session.deviceId === mine.deviceId && m.session.expiry > mine.expiry) {
              this.token = m.session.token;
              this.authData = m.session;
              this.writeSession(m.session);
            }
          } else if (m.t === "clear") {
            // Logged out, or a mismatch, in another tab.
            this.token = null;
            this.authData = null;
            this.lastHeard = null;
            this.writeSession(null);
            this.emit('authChanged', null);
          }
        };
      } catch (err) {
        this.channel = null;
      }
    }

    post(message) {
      try { if (this.channel) this.channel.postMessage(message); } catch (err) { /* channel closed */ }
    }

    // Ask the other open tabs for a token that `accept` takes; waits 150 ms
    // at most. (A tab still on the old login may answer first.)
    askOtherTabs(accept) {
      if (!this.channel) return Promise.resolve(null);
      return new Promise((resolve) => {
        const done = (s) => { this.askWaiter = null; clearTimeout(timer); resolve(s); };
        const timer = setTimeout(() => done(null), 150);
        this.askWaiter = (s) => { if (accept(s)) done(s); };
        this.post({ t: "ask" });
      });
    }

    async findSharedSession(rec) {
      const here = this.readSession();
      if (this.fits(here, rec)) return here;
      return this.askOtherTabs((s) => this.fits(s, rec));
    }

    // One tab at a time asks the server for a token (Web Locks, where the
    // browser has them); the others then take the token it announces.
    locked(fn) {
      const locks = typeof navigator !== "undefined" && navigator.locks;
      return locks && locks.request ? locks.request("KoC_SR_LOGIN", fn) : fn();
    }

    // ---- start-up ----

    // The old login keeps its token in localStorage "KoC_SRAUTH". Remember
    // only who it was for, and delete it.
    migrateOldLogin() {
      const old = SafeStorage.get(TOKEN_KEY, null);
      if (old === null) return;
      if (old && old.id && old.name && /^\d+$/.test(String(old.id)) && !SafeStorage.get(LEGACY_ID_KEY, null)) {
        SafeStorage.set(LEGACY_ID_KEY, { id: String(old.id), name: String(old.name) });
      }
      SafeStorage.remove(TOKEN_KEY);
    }

    setState(state) {
      this.state = state;
      this.emit('stateChanged', state);
    }

    async saveDevice(rec) {
      this.device = rec;
      try { await SrDeviceStore.save(rec); } catch (err) { console.warn("⚠️ Could not save this browser's login record:", err); }
    }

    // Forget this browser's key and both logins.
    async forgetDevice() {
      this.device = null;
      try { await SrDeviceStore.clear(); } catch (err) { /* nothing stored */ }
      SafeStorage.remove(LEGACY_ID_KEY);
      this.dropSession(true);
    }

    pendingCheckDue(rec, now = Date.now()) {
      if (!rec) return false;
      const since = now - (rec.lastCheckAt || 0);
      if (rec.status === "pending") return !rec.codeExpired && since >= srPendingCheckDelay(rec, now);
      if (rec.status === "suspended") return since >= 120e3;
      return false;
    }

    // Check stored login, renew it, or work out why there is none.
    // Resolves true when this tab has a token.
    initialize() {
      if (!this.initPromise) this.initPromise = this.start({});
      return this.initPromise;
    }

    start(opts) {
      return this.runInit(opts).catch((err) => {
        console.warn("⚠️ SR login check failed:", err);
        this.token = null;
        this.authData = null;
        this.state = { code: "offline" };
        return false;
      }).then((ok) => {
        this.emit('stateChanged', this.state);
        return ok;
      });
    }

    async runInit({ force = false, checkNow = false } = {}) {
      this.migrateOldLogin();
      let rec = null;
      try { rec = await SrDeviceStore.load(); } catch (err) { debugLog("Device store unavailable:", err); }
      this.device = rec;
      this.state = { code: "signed_out" };

      // Stats-ID check, Command Center only (the one page that names you).
      const page = srOnCommandCentre() ? findOwnIdentityOnPage() : null;
      let legacy = SafeStorage.get(LEGACY_ID_KEY, null);
      if (page && rec && String(rec.playerId) !== String(page.id)) {
        return this.handleMismatch(rec, page);
      }
      if (page && legacy && String(legacy.id) !== String(page.id)) {
        // The old login was for another account: never reuse it for this one.
        SafeStorage.remove(LEGACY_ID_KEY);
        this.dropSession(true);
        legacy = null;
      } else if (page && legacy && legacy.name !== page.name) {
        legacy = { id: String(page.id), name: page.name };   // renamed in the game
        SafeStorage.set(LEGACY_ID_KEY, legacy);
      }

      if (rec && rec.status === "active") {
        const shared = force ? null : await this.findSharedSession(rec);
        if (shared) {
          this.adopt(shared, false);
          this.state = { code: "active" };
          return true;
        }
        const ok = await this.locked(async () => {
          if (!force && this.fits(this.lastHeard, rec)) {   // another tab renewed while this one waited
            this.adopt(this.lastHeard, false);
            this.state = { code: "active" };
            return true;
          }
          return this.deviceLogin(rec);
        });
        if (ok) return true;
        rec = this.device;
      } else if (rec && (this.pendingCheckDue(rec) || (checkNow && !rec.codeExpired && Date.now() - (rec.lastCheckAt || 0) >= 10e3))) {
        if (await this.locked(() => this.deviceLogin(rec))) return true;
        rec = this.device;
      } else if (rec) {
        this.state = { code: rec.status === "suspended" ? "suspended" : rec.codeExpired ? "code_expired" : "pending" };
      }

      // The old login: only with no browser record yet, or while it waits.
      legacy = SafeStorage.get(LEGACY_ID_KEY, null);
      if (legacy && (!rec || rec.status === "pending")) {
        let session = force ? null : await this.findSharedSession(rec);
        if (!session) {
          session = await this.locked(async () => {
            if (!force && this.fits(this.lastHeard, rec)) return this.lastHeard;
            const made = await this.legacyLogin(legacy);
            if (made) this.post({ t: "token", session: made });
            return made;
          });
        }
        if (session) {
          this.adopt(session, false);
          if (!rec) this.state = { code: "legacy" };
          return true;
        }
      }

      this.token = null;
      this.authData = null;
      this.writeSession(null);
      return false;
    }

    // Trade a signature for a token. Sets this.state; true when logged in.
    async deviceLogin(rec) {
      let r = await SrDevice.session(rec);
      if (r.status === 401) r = await SrDevice.session(rec);   // a challenge can go stale: once more
      const err = r.body.error;
      rec.lastCheckAt = Date.now();

      if (r.status === 200 && r.body.accessToken) {
        rec.status = "active";
        delete rec.code; delete rec.codeExpiresAt; delete rec.codeExpired; delete rec.mismatch;
        if (r.body.player && r.body.player.name) rec.playerName = r.body.player.name;
        await this.saveDevice(rec);
        this.adopt(this.makeSession(r.body.accessToken, rec.playerId, rec.playerName, "device", rec.deviceId), true);
        this.state = { code: "active" };
        return true;
      }
      if (r.status === 202) {
        rec.status = "pending";
        if (r.body.expiresAt) rec.codeExpiresAt = r.body.expiresAt;
        await this.saveDevice(rec);
        this.state = { code: "pending" };
        return false;
      }
      if (r.status === 403 && err === "code_expired") {
        rec.codeExpired = true;
        await this.saveDevice(rec);
        this.state = { code: "code_expired" };
        return false;
      }
      if (r.status === 403 && err === "suspended") {
        rec.status = "suspended";
        await this.saveDevice(rec);
        this.dropSession(true);
        this.state = { code: "suspended" };
        return false;
      }
      if (r.status === 403 && err === "revoked") {
        // A revoked key never comes back; Login makes a new one.
        await this.forgetDevice();
        this.state = { code: "revoked" };
        return false;
      }
      if (r.status === 403) {
        await this.saveDevice(rec);
        this.dropSession(true);
        this.state = { code: "not_allowed", message: r.body.message };
        return false;
      }
      if (r.status === 401 && rec.status !== "active") {
        // The request is no longer on the server: rejected, or it ran out.
        await this.forgetDevice();
        this.state = { code: "gone" };
        return false;
      }
      if (r.status === 426) {
        this.state = { code: "outdated", message: r.body.message };
        return false;
      }
      // 429, a server error, or a 401 for an approved browser: keep the key.
      await this.saveDevice(rec);
      this.state = { code: rec.status === "pending" ? "pending" : "offline", message: r.body.message };
      return false;
    }

    // The page shows one player, this browser is registered to another.
    // Stop, tell the server once, explain.
    async handleMismatch(rec, page) {
      this.dropSession(true);
      SafeStorage.remove(LEGACY_ID_KEY);
      const told = rec.mismatch && rec.mismatch.told && String(rec.mismatch.pageId) === String(page.id);
      if (!told) {
        let settled = false;
        try {
          const r = await SrDevice.mismatch(rec, page.id);
          settled = r.status < 500 && r.status !== 429;   // anything else is retried on the next visit
        } catch (err) { /* offline: retried on the next visit */ }
        rec.mismatch = { pageId: String(page.id), pageName: page.name, at: Date.now(), told: settled };
        rec.status = "suspended";
        rec.lastCheckAt = Date.now();
        await this.saveDevice(rec);
      }
      this.state = { code: "mismatch", deviceName: rec.playerName, pageName: page.name, pageId: String(page.id) };
      return false;
    }

    // POST /auth/koc (the old login). Returns a session, or null. Forgets the
    // saved identity only when the server rejected it: a network blip, a
    // restart or a rate limit is no reason to make somebody log in again.
    async legacyLogin(identity) {
      try {
        const token = await this.requestToken(identity.id, identity.name);
        if (!token) return null;
        return this.makeSession(token, identity.id, identity.name, "legacy", null);
      } catch (err) {
        console.warn("⚠️ Old login failed:", err);
        if ([400, 401, 403, 404].includes(err.status)) SafeStorage.remove(LEGACY_ID_KEY);
        return null;
      }
    }

    // POST /auth/koc and return the token. Throws an Error with .status on a
    // non-2xx response. Used only by the old login.
    async requestToken(id, name) {
      const resp = await netFetch('login', `${API_URL}/auth/koc`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Script-Name": SCRIPT_NAME,
          "X-Script-Version": SCRIPT_VERSION
        },
        body: JSON.stringify({ id, name })
      });
      if (!resp.ok) {
        const err = new Error("Auth failed " + resp.status);
        err.status = resp.status;
        throw err;
      }
      const data = await resp.json();
      return data.token || data.accessToken;
    }

    // ---- tokens for API calls ----

    // Run the login check again, once, however many callers ask at the same time.
    renew(opts) {
      if (!this.refreshPromise) {
        this.refreshPromise = this.start(opts || {}).finally(() => { this.refreshPromise = null; });
        this.initPromise = this.refreshPromise;
      }
      return this.refreshPromise;
    }

    // Get current token (waits for init if needed). A page left open past the
    // token's expiry renews here instead of sending a dead token.
    async getToken() {
      await this.initialize();
      if (this.token && this.authData && Date.now() >= this.authData.expiry) {
        await this.renew({});
      }
      return this.token;
    }

    // The server refused `rejectedToken` (401). Renew once, shared by every
    // call that hit the same 401; if another call already replaced the token,
    // just use the new one. Returns true when there is a fresh token.
    async refreshAfter401(rejectedToken) {
      if (this.token && this.token !== rejectedToken) return true;
      if (!this.refreshPromise) this.dropSession(false);
      return this.renew({ force: true });
    }

    // ---- the Login and Log out buttons ----

    // Login, pressed in the Command Center box. Makes this browser's key,
    // asks the server for a code, and leaves the old login running until an
    // admin has approved the code.
    async login() {
      if (this.busy) return;
      this.busy = true;
      try {
        const page = srOnCommandCentre() ? findOwnIdentityOnPage() : null;
        if (!page) {
          this.setState({ code: this.state.code, message: "Could not read your Stats ID and name. Open your Command Center and press Login there." });
          return;
        }
        let rec = this.device;
        const sameKey = !!rec && rec.status === "pending" && String(rec.playerId) === String(page.id) && !!rec.privateKey;
        let keys = sameKey ? { privateKey: rec.privateKey, publicJwk: rec.publicJwk } : await SrDevice.newKey();
        let r = await SrDevice.enroll(page, keys.publicJwk);
        if (r.status === 403 && r.body.error === "revoked") {
          keys = await SrDevice.newKey();
          r = await SrDevice.enroll(page, keys.publicJwk);
        }
        debugLog("🔐 Login request answered:", r.status, r.body.error || r.body.status || "");

        if (r.status === 426) {
          this.setState({ code: "outdated", message: r.body.message });
          return;
        }
        if (r.status === 403 && r.body.error === "suspended") {
          this.setState({ code: "suspended" });
          return;
        }
        if (r.status >= 500 || r.status === 400) {
          this.setState({ code: this.state.code, message: r.body.message || "The Sweet Revenge server could not take the login. Try again shortly." });
          return;
        }

        const enrolled = (r.status === 202 || r.status === 200) && !!r.body.deviceId;
        if (enrolled) {
          rec = {
            v: 1,
            deviceId: r.body.deviceId,
            playerId: String(page.id),
            playerName: page.name,
            privateKey: keys.privateKey,
            publicJwk: keys.publicJwk,
            label: srBrowserLabel(),
            status: r.status === 200 ? "active" : "pending",
            code: r.body.code,
            codeExpiresAt: r.body.expiresAt,
            enrolledAt: Date.now(),
            lastCheckAt: Date.now()
          };
          await this.saveDevice(rec);
        }

        // The old login keeps the script working until the device is approved.
        SafeStorage.set(LEGACY_ID_KEY, { id: String(page.id), name: page.name });

        const wasRunning = !!this.token;
        if (enrolled && rec.status === "active") {
          await this.deviceLogin(rec);
        } else if (enrolled) {
          this.state = { code: "pending" };
        } else {
          // 403 not_allowed, 429 too many requests.
          const message = r.body.message || "The login was refused. Ask an admin.";
          this.state = { code: r.status === 403 ? "not_allowed" : this.state.code, message };
          if (!wasRunning) { try { sessionStorage.setItem(NOTICE_KEY, message); } catch (err) { /* no notice */ } }
        }
        if (wasRunning) this.emit('stateChanged', this.state);
        else location.reload();   // reload so the features start
      } catch (err) {
        ErrorHandler.log(ErrorHandler.LOG_LEVELS.ERROR, 'Login failed', err);
        this.setState({ code: this.state.code, message: "Could not reach the Sweet Revenge server. Try again shortly." });
      } finally {
        this.busy = false;
      }
    }

    // Log out this browser: tell the server to end it, then delete the key.
    async logout() {
      if (this.busy) return;
      this.busy = true;
      try {
        const rec = this.device;
        if (rec && rec.status === "active") {
          try {
            const token = await this.getToken();
            if (token && this.authData && this.authData.kind === "device") await SrDevice.revoke(token, "self");
          } catch (err) { /* offline: the key is deleted below either way */ }
        }
        await this.forgetDevice();
        this.emit('authChanged', null);
        location.reload();
      } finally {
        this.busy = false;
      }
    }

    // This player's browsers (needs the device login).
    async listDevices() {
      const token = await this.getToken();
      if (!token || !this.authData || this.authData.kind !== "device") return { status: 403, body: {} };
      return SrDevice.list(token);
    }

    // Sign out one other browser by id, or "all" for every browser.
    async revokeDevice(target) {
      const token = await this.getToken();
      if (!token || !this.authData || this.authData.kind !== "device") return { status: 403, body: {} };
      const r = await SrDevice.revoke(token, target);
      if (r.status === 200 && target === "all") {
        await this.forgetDevice();
        this.emit('authChanged', null);
        location.reload();
      }
      return r;
    }

    // Authenticated API call with retry. `kind` is 'read' or a SYNCS id (see
    // NETWORK GATE); a call whose kind is switched off is not made at all.
    async apiCall(kind, endpoint, data, retries = RETRY_ATTEMPTS) {
      if (!netAllowed(kind)) {
        debugLog(`⛔ Not sent (${kind} is switched off): ${endpoint.split('?')[0]}`);
        return null;
      }
      let token = await this.getToken();

      if (!token) {
        console.warn("⚠️ No valid token for API call");
        return null;
      }

      // Determine method: GET if no data provided, POST otherwise
      const method = data ? "POST" : "GET";

      // Log API call (only show data for POST requests)
      if (data) {
        debugLog(`🌐 API ${method} → ${endpoint}`, data);
      } else {
        debugLog(`🌐 API ${method} → ${endpoint}`);
      }

      for (let attempt = 1; attempt <= retries; attempt++) {
        token = this.token || token; // pick up a token refreshed by this or another call
        try {
          const fetchOptions = {
            method,
            headers: {
              "Authorization": "Bearer " + token,
              "X-Script-Name": SCRIPT_NAME,
              "X-Script-Version": SCRIPT_VERSION,
              "X-KoC-Clock": "utc" // KoC times in this request are UTC
            }
          };

          // Only add Content-Type and body for POST requests
          if (method === "POST") {
            fetchOptions.headers["Content-Type"] = "application/json";
            fetchOptions.body = JSON.stringify(data);
          }

          const resp = await netFetch(kind, `${API_URL}/${endpoint}`, fetchOptions);

          // Handle 401 - token expired
          if (resp.status === 401 && attempt === 1) {
            debugLog("🔄 Token expired (401), refreshing...");
            const refreshed = await this.refreshAfter401(token);
            if (refreshed) {
              continue; // Retry with new token
            } else {
              throw new Error("Token refresh failed");
            }
          }

          const json = await resp.json().catch(() => ({ error: "Invalid JSON" }));
          debugLog(`🌐 API response from ${endpoint}:`, json);
          return json;

        } catch (err) {
          if (attempt === retries) {
            console.error(`❌ API call failed → ${endpoint} after ${retries} attempts`, err);
            return null;
          }
          const delay = RETRY_DELAY_BASE_MS * attempt;
          console.warn(`⚠️ Retry ${attempt}/${retries} in ${delay}ms...`);
          await new Promise(r => setTimeout(r, delay));
        }
      }
    }

    // Event system
    on(event, callback) {
      if (!this.listeners.has(event)) {
        this.listeners.set(event, []);
      }
      this.listeners.get(event).push(callback);
      return () => this.off(event, callback);
    }

    off(event, callback) {
      const callbacks = this.listeners.get(event);
      if (callbacks) {
        const index = callbacks.indexOf(callback);
        if (index > -1) callbacks.splice(index, 1);
      }
    }

    emit(event, data) {
      const callbacks = this.listeners.get(event) || [];
      callbacks.forEach(cb => cb(data));
    }

  }

  // Create global auth instance
  const auth = new AuthManager();

  // ==================== SR LOGIN: Command Center box ====================
  // The login box under the native User Info table on base.php. It is
  // drawn from auth.state and redrawn when that changes. Every piece of text
  // goes in with textContent. Nothing in it links out of the game, and nothing
  // in it sends the in-game message: the member does that by hand.

  // Plain sentence for the ⚙ panel and the box: what pressing Login sends.
  const SR_LOGIN_SENDS = 'Login sends your Stats ID, your name, a public key made in this browser and a browser label ("' +
    srBrowserLabel() + '") to the Sweet Revenge server. The private half of the key never leaves this browser. Nothing is sent to the game.';

  function srLoginStatusText() {
    const s = auth.state || {};
    const who = (auth.authData && auth.authData.name) || (auth.device && auth.device.playerName) || "";
    switch (s.code) {
      case "active": return `Logged in as ${who}.`;
      case "legacy": return `Logged in as ${who} with the old login. This browser is not registered yet.`;
      case "pending": return `Waiting for an admin to approve this browser for ${who}.`;
      case "code_expired": return "The login code ran out before it was approved.";
      case "mismatch": return "Stopped: this browser is registered to another account.";
      case "suspended": return "This browser's login is suspended.";
      case "revoked": return "This browser was signed out.";
      case "gone": return "The login request is no longer waiting.";
      case "not_allowed": return "This account is not approved to use the scripts.";
      case "outdated": return "The script is too old to log in.";
      case "offline": return "Could not reach the Sweet Revenge server.";
      default: return "Not logged in.";
    }
  }

  function srEl(tag, css, text) {
    const e = document.createElement(tag);
    if (css) e.style.cssText = css;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  function srBtn(label, onClick, primary) {
    const b = srEl("button", "margin:4px 6px 0 0;padding:4px 10px;cursor:pointer;font:bold 12px Arial,sans-serif;border-radius:4px;border:1px solid " +
      (primary ? "#4a7a3a;background:#2f5d22;color:#fff;" : "#555;background:#222;color:#ddd;"), label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  // Looks like a link, is a button: it changes the box, it does not navigate.
  function srLinkBtn(label, onClick) {
    const b = srEl("button", "background:none;border:none;padding:0;margin:0;color:#8ab4f8;cursor:pointer;font:12px Arial,sans-serif;text-decoration:underline;", label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  let srLoginPollTimer = null;
  let srDevicesOpen = false;

  function renderSrLoginBox() {
    if (!onPage("base.php") || READ_ONLY_PAGE) return;
    let box = document.getElementById("sr-login-box");
    if (!box) {
      box = srEl("div", "margin:6px 0;padding:8px 10px;background:#111;color:#ddd;border:1px solid #555;font:12px Arial,sans-serif;text-align:left;line-height:1.5;");
      box.id = "sr-login-box";
      box.setAttribute("data-koc-injected", "1");
      const own = findOwnIdentityRow();
      const table = own && own.row.closest("table");
      if (table) table.insertAdjacentElement("afterend", box);
      else document.body.prepend(box);
    }
    box.textContent = "";

    const s = auth.state || { code: "signed_out" };
    const rec = auth.device;
    const page = findOwnIdentityOnPage();
    const add = (node) => { box.appendChild(node); return node; };
    const line = (text, css) => add(srEl("div", css || "", text));
    const small = "color:#9aa3b2;font-size:11px;";
    const warn = "color:#ffb74d;";
    const loginBtn = (label) => add(srBtn(label, () => auth.login(), true));
    const who = page ? `${page.name} (Stats ID ${page.id})` : "";

    // A message carried over a reload (a refused Login), shown once.
    let notice = s.message || null;
    try {
      const kept = sessionStorage.getItem(NOTICE_KEY);
      if (kept) { notice = notice || kept; sessionStorage.removeItem(NOTICE_KEY); }
    } catch (err) { /* no notice */ }

    if (s.code === "active") {
      // One status line.
      const row = add(srEl("div"));
      row.appendChild(srEl("span", "", `🔓 Sweet Revenge: logged in as ${(auth.authData && auth.authData.name) || (rec && rec.playerName) || ""} · `));
      row.appendChild(srLinkBtn("devices", () => { srDevicesOpen = !srDevicesOpen; renderSrLoginBox(); }));
      row.appendChild(srEl("span", "", " · "));
      row.appendChild(srLinkBtn("log out", () => srConfirmLogout()));
      if (srDevicesOpen) renderSrDevices(add(srEl("div", "margin-top:6px;")));
    } else if (s.code === "pending" && rec) {
      line("🔐 Sweet Revenge script login", "font-weight:bold;");
      const p = add(srEl("div"));
      p.appendChild(srEl("span", "", "Send this code in an in-game message to "));
      SR_APPROVER_NAMES.forEach((name, i) => {
        if (i) p.appendChild(srEl("span", "", " or "));
        p.appendChild(srEl("b", "", name));
      });
      p.appendChild(srEl("span", "", ": "));
      const code = srEl("span", "font:bold 15px Consolas,monospace;color:#fff;background:#000;border:1px solid #777;padding:1px 6px;letter-spacing:1px;user-select:all;white-space:nowrap;display:inline-block;", rec.code || "(code not saved)");
      code.id = "sr-login-code";
      p.appendChild(code);
      line("This box logs you in once an admin has approved it. You only do this once for each browser.");
      line("⚠ Only send a code that this box showed you. Never send a code that somebody else gave you.", warn);
      if (rec.codeExpiresAt) line(`The code runs out ${new Date(rec.codeExpiresAt).toLocaleString()}.`, small);
      if (auth.token) line("The script keeps working with the old login while you wait.", small);
      const checked = rec.lastCheckAt ? `Last checked ${new Date(rec.lastCheckAt).toLocaleTimeString()}: still waiting.` : "Not checked yet.";
      line(checked, small).id = "sr-login-checked";
      add(srBtn("Check now", () => auth.renew({ checkNow: true })));
      add(srBtn("Cancel", () => srConfirmLogout()));
    } else if (s.code === "mismatch") {
      line("⛔ Sweet Revenge script stopped", "font-weight:bold;color:#ff8a80;");
      line(`This browser is registered to ${s.deviceName || "another player"}, but you are logged into ${s.pageName} in KoC. This has been recorded for the admins.`);
      line("Two people who share a computer should each use their own browser profile.", small);
      line(`If ${s.pageName} is now the only account played in this browser, you can register it again. It needs a new code and an admin's approval.`, small);
      loginBtn(`Login as ${s.pageName}`);
    } else if (s.code === "suspended") {
      line("⛔ Sweet Revenge script login suspended", "font-weight:bold;color:#ff8a80;");
      line("This browser's login was suspended, most likely because it was used with another account. Ask an admin to re-activate it.");
    } else if (s.code === "outdated") {
      line("⚠ Userscript is outdated. Please update.", "font-weight:bold;" + warn);
      line("Update KoC Data Centre from your userscript manager, then reload this page.", small);
    } else {
      // signed_out, legacy, code_expired, revoked, gone, not_allowed, offline
      line("🔐 Sweet Revenge script login", "font-weight:bold;");
      if (s.code === "legacy") {
        line(`Logged in as ${(auth.authData && auth.authData.name) || who} with the old login, which is being switched off.`);
        line("Press Login to register this browser. You will get a code to send in an in-game message; the script keeps working while you wait.");
      } else if (s.code === "code_expired") {
        line("That code ran out before it was approved. Press Login for a new one.");
      } else if (s.code === "revoked") {
        line("This browser was signed out, from another of your browsers or by an admin. Press Login to register it again.");
      } else if (s.code === "gone") {
        line("That login request is no longer waiting: it was not approved, or it ran out. Press Login to ask again.");
      } else if (s.code === "not_allowed") {
        line("This account is not approved to use the scripts with the new login. Ask an admin.");
        if (auth.token) line("The old login keeps working for now.", small);
      } else if (s.code === "offline") {
        line("Could not reach the Sweet Revenge server. Reload the page to try again.");
      } else {
        line(who ? `${who}: not logged in.` : "Not logged in.");
      }
      if (notice) { line(notice, warn); notice = null; }
      if (s.code !== "offline" || !rec) {
        if (page) loginBtn(s.code === "code_expired" ? "Login (new code)" : "Login");
        else line("Could not read your Stats ID and name from this page.", warn);
        line(SR_LOGIN_SENDS, small + "margin-top:4px;");
      }
      if (s.code === "legacy") add(srBtn("Log out", () => srConfirmLogout()));
    }
    if (notice) line(notice, warn);

    // While a code waits for approval, look again now and then (see
    // srPendingCheckDelay). Only this page does it, and only while it is open.
    const waiting = !!rec && rec.status === "pending" && !rec.codeExpired;
    if (waiting && !srLoginPollTimer) {
      srLoginPollTimer = setInterval(() => {
        if (document.hidden) return;
        if (auth.pendingCheckDue(auth.device)) auth.renew({});
      }, 5000);
    } else if (!waiting && srLoginPollTimer) {
      clearInterval(srLoginPollTimer);
      srLoginPollTimer = null;
    }
  }

  function srConfirmLogout() {
    const rec = auth.device;
    const msg = rec && rec.status === "active"
      ? "Log out this browser?\n\nLogging in again needs a new code, sent in an in-game message and approved by an admin."
      : rec ? "Cancel this login request and log out?" : "Log out?";
    if (confirm(msg)) auth.logout();
  }

  // The member's own browsers: which ones are approved, when each was last
  // used, and a way to sign one out.
  async function renderSrDevices(holder) {
    holder.textContent = "Loading your browsers…";
    let r;
    try { r = await auth.listDevices(); } catch (err) { r = { status: 0, body: {} }; }
    holder.textContent = "";
    if (r.status !== 200 || !Array.isArray(r.body.devices)) {
      holder.appendChild(srEl("div", "color:#ffb74d;", "Could not load your browsers. Try again shortly."));
      return;
    }
    holder.appendChild(srEl("div", "color:#9aa3b2;font-size:11px;", "Browsers registered to your account. Sign out any you do not recognise, and tell an admin."));
    for (const d of r.body.devices) {
      const row = srEl("div", "padding:3px 0;border-top:1px solid #333;");
      const used = d.lastUsedAt ? `last used ${new Date(d.lastUsedAt).toLocaleString()}` : "never used";
      const state = d.status === "active" ? "" : d.status === "pending" ? " · waiting for approval" : ` · ${d.status}`;
      row.appendChild(srEl("span", "", `${d.label || "Browser"}${d.current ? " (this browser)" : ""} · ${used}${state} `));
      if (!d.current) {
        row.appendChild(srLinkBtn("sign out", async () => {
          if (!confirm(`Sign out "${d.label || "Browser"}"? It will need a new code to log in again.`)) return;
          await auth.revokeDevice(d.id);
          renderSrLoginBox();
        }));
      }
      holder.appendChild(row);
    }
    holder.appendChild(srBtn("Sign out of every browser", async () => {
      if (!confirm("Sign out of every browser, this one included?\n\nEach will need a new code, approved by an admin, to log in again.")) return;
      await auth.revokeDevice("all");
    }));
  }

  // ==================== STORAGE HELPERS ====================

  function getNameMap() {
    return SafeStorage.get(MAP_KEY, {});
  }

  function saveNameMap(map) {
    return SafeStorage.set(MAP_KEY, map);
  }

  /**
   * Clean up old players from localStorage to prevent unbounded growth
   * Removes players not seen in the last 30 days
   */
  function cleanupOldPlayers() {
    const PLAYER_MAX_AGE_DAYS = 30;
    const cutoffTime = Date.now() - (PLAYER_MAX_AGE_DAYS * 24 * 60 * 60 * 1000);

    const map = getNameMap();
    const originalCount = Object.keys(map).length;
    let removedCount = 0;

    for (const [playerId, playerData] of Object.entries(map)) {
      const lastSeen = playerData.lastSeen;

      // Remove if no lastSeen timestamp or if older than cutoff
      if (!lastSeen || Date.parse(lastSeen) < cutoffTime) {
        delete map[playerId];
        removedCount++;
      }
    }

    if (removedCount > 0) {
      saveNameMap(map);
      console.log(`🧹 Cleaned up ${removedCount} old players from localStorage (${originalCount} → ${originalCount - removedCount})`);
    } else {
      debugLog(`✅ No old players to clean up (${originalCount} players in cache)`);
    }

    return removedCount;
  }

  /**
   * Run periodic localStorage maintenance
   * Cleanup runs once every 7 days
   */
  // Storage keys earlier versions kept that nothing reads now.
  const UNUSED_KEYS = [
    "KoC_DataCentre",            // a local TIV log
    "KoC_WeaponMultipliers",     // gold per point learned from purchases
    "KoC_SabLogReset",           // a one-time Sab Tracker reset
    ...['enabled', 'settings', 'attack_events', 'last_bank', 'pending_action', 'last_notify_ts',
      'notify_state', 'bank_events', 'last_attacklog_visit'].map(k => "KoC_Banking_" + k)   // Banking Mode
  ];

  function runPeriodicMaintenance() {
    UNUSED_KEYS.forEach(k => SafeStorage.remove(k));
    const CLEANUP_INTERVAL_DAYS = 7;
    const LAST_CLEANUP_KEY = "KoC_LastCleanup";

    const lastCleanup = SafeStorage.get(LAST_CLEANUP_KEY, 0);
    const daysSinceCleanup = (Date.now() - lastCleanup) / (24 * 60 * 60 * 1000);

    if (daysSinceCleanup >= CLEANUP_INTERVAL_DAYS) {
      console.log(`🧹 Running periodic localStorage maintenance (last cleanup: ${Math.floor(daysSinceCleanup)} days ago)`);

      // Clean old players
      cleanupOldPlayers();

      // Show storage usage
      const usage = SafeStorage.getUsage();
      console.log(`💾 localStorage usage: ${usage.usedKB} KB (${usage.percentUsed}% of estimated 5MB limit)`);

      // Update last cleanup timestamp
      SafeStorage.set(LAST_CLEANUP_KEY, Date.now());
    } else {
      debugLog(`✅ Maintenance not needed yet (last cleanup: ${Math.floor(daysSinceCleanup)} days ago, next in ${Math.ceil(CLEANUP_INTERVAL_DAYS - daysSinceCleanup)} days)`);
    }
  }

  // ==================== INITIALIZATION & GATEKEEPER ====================

  async function initializeScript() {
    // Initialize authentication
    const isAuthenticated = await auth.initialize();

    // The login box lives on the Command Center, logged in or not.
    if (onPage("base.php") && !READ_ONLY_PAGE) {
      try {
        renderSrLoginBox();
        auth.on('stateChanged', () => renderSrLoginBox());
      } catch (err) {
        console.warn("⚠️ Could not draw the SR login box:", err);
      }
    }

    if (!isAuthenticated) {
      console.warn("🔒 Data Centre disabled — not logged in (" + auth.state.code + ").");
      return false; // Stop initialization
    }

    debugLog("✅ Authenticated with SR, initializing features...");

    // Run periodic localStorage maintenance
    runPeriodicMaintenance();

    return true;
  }

  // ==================== PLAYER DATA MANAGEMENT ====================

  // `kind` is the SYNCS id the caller shares under (see NETWORK GATE).
  function updatePlayerInfo(id, patch, kind) {
    if (!id) return;

    const map = getNameMap();
    const prev = map[id] || {};

    // Sanitize patch data first
    const sanitizedPatch = sanitizePlayerData(patch);

    // Clean patch - remove Unknown, empty, or null values
    const cleanPatch = {};
    for (const [k, v] of Object.entries(sanitizedPatch)) {
      if (v !== "Unknown" && v !== "" && v != null) {
        cleanPatch[k] = v;
      }
    }

    // Merge and save to localStorage cache
    const updated = { ...prev, ...cleanPatch, lastSeen: getKoCServerTimeUTC() };
    map[id] = updated;
    saveNameMap(map);

    // Send to API if changed - ONLY send newly scraped fields, not re-send cached data
    if (JSON.stringify(prev) !== JSON.stringify(updated)) {
      const apiPayload = {};
      // Only include fields that were actually scraped on this page (cleanPatch)
      for (const [k, v] of Object.entries(cleanPatch)) {
        if (v !== "Unknown" && v !== "" && v != null) {
          apiPayload[k] = v;
        }
      }
      // Include lastSeen since it was just updated
      apiPayload.lastSeen = updated.lastSeen;
      auth.apiCall(kind, "players", { id, ...apiPayload });
    }
  }

  // ==================== XP TO ATTACKS CALCULATOR ====================

  function calculateXPTradeAttacks(xp, turns) {
    const XP_PER_TRADE = 1425;

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

  // Attacks you can make if you allow at most `maxTrades` XP→turn trades.
  // Same order as calculateXPTradeAttacks: spend turns first (each attack
  // refunds XP), and trade only when you are out of turns for a hit.
  function attacksWithTrades(xp, turns, maxTrades) {
    const XP_PER_TRADE = 1425;
    let attacks = 0, trades = 0;
    for (;;) {
      while (turns >= TURNS_PER_ATTACK) {
        turns -= TURNS_PER_ATTACK;
        attacks++;
        xp += XP_REFUND_PER_ATTACK;
      }
      if (trades >= maxTrades || xp < XP_PER_TRADE) break;
      xp -= XP_PER_TRADE;
      turns += TURNS_PER_TRADE;
      trades++;
    }
    return { attacks, trades };
  }

  // Gold goal maths for the sidebar calculator. Returns null when no goal is set.
  //   remaining        goal − gold on hand (when counted)
  //   noTrade          hits from turns on hand, and the gold each must bring in
  //   hitFor           the hit size you plan on (Avg Gold/Atk unless set)
  //   hitsNeeded       hits at that size; trades = the fewest XP trades that
  //                    give that many hits (0 = none), null if even trading all
  //                    your XP falls short (maxAttacks says how far it gets)
  function goldGoalSummary({ goal, onHand = 0, countOnHand = true, hitFor = 0, xp = 0, turns = 0 }) {
    goal = Number(goal) || 0;
    if (goal <= 0) return null;
    onHand = countOnHand ? Math.max(0, Number(onHand) || 0) : 0;
    hitFor = Number(hitFor) || 0;
    const remaining = Math.max(0, goal - onHand);
    const noTradeHits = Math.floor((Number(turns) || 0) / TURNS_PER_ATTACK);
    const all = attacksWithTrades(xp, turns, Infinity);
    const out = {
      goal, onHand, remaining, hitFor,
      noTradeHits,
      noTradePerHit: remaining <= 0 ? 0 : (noTradeHits > 0 ? Math.ceil(remaining / noTradeHits) : null),
      maxAttacks: all.attacks,
      maxTrades: all.trades,
      maxPerHit: remaining <= 0 ? 0 : (all.attacks > 0 ? Math.ceil(remaining / all.attacks) : null),
      hitsNeeded: null,
      trades: null,
      xpTraded: 0
    };
    if (remaining <= 0) { out.hitsNeeded = 0; out.trades = 0; return out; }
    if (hitFor <= 0) return out;
    out.hitsNeeded = Math.ceil(remaining / hitFor);
    for (let k = 0; k <= all.trades; k++) {
      if (attacksWithTrades(xp, turns, k).attacks >= out.hitsNeeded) {
        out.trades = k;
        out.xpTraded = k * 1425;
        break;
      }
    }
    return out;
  }

  // ==================== BANKING HISTORY (TREND GRAPH) ====================

  // Send a banked-% snapshot from the sidebar box, at most every 30 minutes.
  // The server also throttles.
  let bankingSnapshotInFlight = false;
  async function maybeSubmitBankingSnapshot(data) {
    try {
      if (bankingSnapshotInFlight) return;
      if (!auth.getStoredAuth()) return;            // not logged in
      if (!data || !isFinite(data.bankedPct)) return;

      const SUBMIT_KEY = "KoC_BankingSnapshot_last";
      const last = SafeStorage.get(SUBMIT_KEY, 0);
      const now = Date.now();
      if (now - last < 30 * 60 * 1000) return;       // client throttle: once / 30 min

      bankingSnapshotInFlight = true;
      const result = await auth.apiCall("banking-snapshots", "banking/snapshot", data);  // data present → POST
      if (result) {
        SafeStorage.set(SUBMIT_KEY, now);
        debugLog("[Banking] Snapshot submitted:", data.bankedPct + "%");
      }
    } catch (err) {
      debugLog("[Banking] Snapshot submit failed:", err);
    } finally {
      bankingSnapshotInFlight = false;
    }
  }

  // Fetch banking history and show a banked-% line chart (hand-rolled SVG, no libs).
  async function showBankingTrend() {
    if (!auth.getStoredAuth()) {
      alert("Open your Command Center and press Login to track your banking trend.");
      return;
    }

    const history = await auth.apiCall("read", "banking/history?days=30");  // no data → GET
    const points = (history || [])
      .map(r => ({ t: new Date(r.recorded_at).getTime(), pct: Number(r.banked_pct) }))
      .filter(p => isFinite(p.t) && isFinite(p.pct))
      .sort((a, b) => a.t - b.t);

    if (points.length === 0) {
      alert("No banking history yet.\n\nA snapshot is sent from the sidebar box at most every 30 minutes on any page with the sidebar — the banked % trend will build up here over the coming days.");
      return;
    }

    const W = 580, H = 320, padL = 44, padR = 16, padT = 40, padB = 40;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const tMin = points[0].t, tMax = points[points.length - 1].t;
    const tSpan = Math.max(1, tMax - tMin);
    const xOf = t => padL + ((t - tMin) / tSpan) * plotW;
    const yOf = v => padT + (1 - v / 100) * plotH;   // y axis fixed 0–100%

    const fmtDate = ms => { const d = new Date(ms); return `${d.getDate()}/${d.getMonth() + 1}`; };

    let grid = "";
    [0, 25, 50, 75, 100].forEach(v => {
      const y = yOf(v);
      grid += `<line x1="${padL}" y1="${y}" x2="${padL + plotW}" y2="${y}" stroke="#333" stroke-width="1"/>`;
      grid += `<text x="${padL - 6}" y="${y + 4}" fill="#999" font-size="10" text-anchor="end">${v}%</text>`;
    });

    let xlabels = "";
    [tMin, tMin + tSpan / 2, tMax].forEach(t => {
      xlabels += `<text x="${xOf(t)}" y="${padT + plotH + 16}" fill="#999" font-size="10" text-anchor="middle">${fmtDate(t)}</text>`;
    });

    const poly = points.map(p => `${xOf(p.t).toFixed(1)},${yOf(p.pct).toFixed(1)}`).join(" ");
    const dots = points.map(p =>
      `<circle cx="${xOf(p.t).toFixed(1)}" cy="${yOf(p.pct).toFixed(1)}" r="2.5" fill="#a67c00"><title>${fmtDate(p.t)}: ${p.pct.toFixed(1)}%</title></circle>`
    ).join("");

    const latest = points[points.length - 1].pct;
    const avg = points.reduce((s, p) => s + p.pct, 0) / points.length;

    const chartHTML = `
      <svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="max-width:100%; background:#111; border-radius:6px;">
        <polyline points="${padL},${padT} ${padL},${padT + plotH} ${padL + plotW},${padT + plotH}" fill="none" stroke="#444" stroke-width="1"/>
        ${grid}
        ${xlabels}
        <polyline points="${poly}" fill="none" stroke="#a67c00" stroke-width="2"/>
        ${dots}
      </svg>
      <div style="text-align:center; color:#ccc; font-size:12px; margin-top:8px;">
        Latest: <strong style="color:#fff;">${latest.toFixed(1)}%</strong> &nbsp;•&nbsp; Average: <strong style="color:#fff;">${avg.toFixed(1)}%</strong> &nbsp;•&nbsp; ${points.length} point${points.length !== 1 ? "s" : ""}
      </div>
      <div style="text-align:center; color:#777; font-size:10px; margin-top:6px;">
        Each point is your banked % as computed on the command centre — refresh it by visiting the attack log, then the command centre.
      </div>`;

    const overlay = document.createElement('div');
    overlay.id = 'koc-banking-overlay';
    Object.assign(overlay.style, {
      position: 'fixed', top: '0', left: '0', width: '100%', height: '100%',
      backgroundColor: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center',
      justifyContent: 'center', zIndex: '9999'
    });
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

    const modal = document.createElement('div');
    Object.assign(modal.style, {
      background: '#1a1a1a', color: '#fff', padding: '20px', border: '2px solid #666',
      borderRadius: '8px', maxWidth: '95%', position: 'relative'
    });

    const closeBtn = document.createElement('span');
    closeBtn.textContent = '×';
    Object.assign(closeBtn.style, { position: 'absolute', top: '6px', right: '12px', cursor: 'pointer', fontSize: '26px', color: '#999' });
    closeBtn.onclick = () => overlay.remove();

    const title = document.createElement('h2');
    title.textContent = '💰 Banking Trend';
    title.style.cssText = 'margin:0 0 12px 0; color:gold; text-align:center; font-size:16px;';

    const body = document.createElement('div');
    body.innerHTML = chartHTML;

    modal.appendChild(closeBtn);
    modal.appendChild(title);
    modal.appendChild(body);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  }

  // ==================== SIDEBAR CALCULATOR ====================

  function initSidebarCalculator() {
    const BOX_ID = "koc-xp-box";
    if (document.getElementById(BOX_ID)) return; // Prevent duplicates

    if (!document.getElementById("koc-logo-style")) {
      const style = document.createElement("style");
      style.id = "koc-logo-style";
      style.textContent = "a.koc-button img { transition: transform 0.2s ease, filter 0.2s ease; }" +
        " a.koc-button img:hover { transform: scale(1.05); filter: drop-shadow(0 0 6px gold); }";
      document.head.appendChild(style);
    }

    const xpBox = document.createElement("table");
    xpBox.id = BOX_ID;
    xpBox.className = "table_lines";
    xpBox.style.marginTop = "5px";
    xpBox.innerHTML = `
      <tbody>
        <tr><th align="center">⚔️ Turn Trading Calculator</th></tr>
        <tr><td align="center" style="color:black;">Attacks Left <span id="xp-attacks">0</span></td></tr>
        <tr><td align="center" style="color:black;">XP Trade Attacks <span id="xp-trade">0</span></td></tr>
        <tr><td align="center" style="color:black;">Avg Gold/Atk <a href="attacklog.php" id="xp-gold-link" style="color:black;"><span id="xp-gold">0</span></a> <span id="xp-gold-edit" title="Set manually (overrides auto-calibration from the attack log)" style="cursor:pointer;">✏️</span><span id="xp-gold-manual-tag" style="display:none; color:#b45309; font-weight:bold; font-size:9px;"> manual</span></td></tr>
        <tr><td align="center" style="color:black;">Total Potential Gold <span id="xp-total">0</span></td></tr>
        <tr><td align="center" style="color:black;">🎯 Goal <span id="xp-goal">—</span> <span id="xp-goal-edit" title="Goal settings — the gold you are working towards (an XP upgrade, say) and the hit size you plan on" style="cursor:pointer;">✏️</span></td></tr>
        <tr id="xp-goal-detail" style="display:none;"><td align="center" style="color:black; font-size:11px; line-height:1.3; padding:0 2px;"></td></tr>
        <tr id="xp-goal-settings" style="display:none;"><td style="color:black; font-size:11px; text-align:left;">
          <label style="display:block;">Goal <input id="xp-goal-in" type="text" placeholder="e.g. 1.2b" style="width:70px; font-size:11px;"></label>
          <label style="display:block; margin-top:3px;" title="The gold you expect each hit to bring in. Leave blank to use your Avg Gold/Atk.">Hit for <input id="xp-goal-hit-in" type="text" placeholder="avg" style="width:62px; font-size:11px;"></label>
          <label style="display:block; margin-top:3px;"><input id="xp-goal-onhand-in" type="checkbox"> Count gold, Safe &amp; Vault</label>
          <div style="margin-top:4px; text-align:center;">
            <button type="button" id="xp-goal-save" style="font-size:11px;">Save</button>
            <button type="button" id="xp-goal-clear" style="font-size:11px;">Clear</button>
          </div>
        </td></tr>
        <tr><td align="center" style="color:black;">Banked <span id="xp-banked">—</span> <span id="xp-banked-graph" title="Banking % trend over time" style="cursor:pointer;">📈</span></td></tr>
        <tr id="xp-update-row" style="display:none;"><td align="center" style="padding:5px 2px;"></td></tr>
        <tr>
          <td align="center">
            <a href="#" id="sr-logo-link" class="koc-button" title="Data Centre feature settings">
              <img src="${srLogoSrc()}"
                   alt="Sweet Revenge"
                   style="max-width:110px; height:auto; margin-top:6px; display:block; margin-left:auto; margin-right:auto;">
            </a>
            <button id="sr-auth-btn" style="
              margin-top: 8px;
              padding: 6px 12px;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              color: white;
              border: none;
              border-radius: 4px;
              cursor: pointer;
              font-weight: bold;
              font-size: 12px;
              width: 100%;
              max-width: 110px;
              transition: all 0.2s;
            ">Loading...</button>
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
      // Fallback: inject into sidebar cell
      const firstSidebar = document.querySelector("td.menu_cell");
      if (firstSidebar) firstSidebar.appendChild(xpBox);
    }

    // "Update available" pill when the public release is newer.
    // The link opens the raw .user.js; the member's userscript manager shows
    // its own Update prompt. Hidden when current or when the API didn't say.
    if (scriptUpdate && !scriptUpdate.isLatest) {
      const row = document.getElementById("xp-update-row");
      const a = document.createElement("a");
      a.href = scriptUpdate.updateUrl;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = `⬆ Update v${scriptUpdate.latestVersion}`;
      a.title = `Data Centre v${scriptUpdate.latestVersion} is out (you have v${SCRIPT_VERSION}). Opens the script in your userscript manager, which will ask you to confirm the update.`;
      // Block, not nowrap: the sidebar cell is ~117px, so a long version wraps rather than overflows.
      a.style.cssText = "display:block; max-width:100%; box-sizing:border-box; font-size:10px; line-height:1.4; font-weight:bold; color:#2a2008; background:#f0c674; border:1px solid #b45309; border-radius:4px; padding:2px 5px; text-decoration:none;";
      row.firstElementChild.appendChild(a);
      row.style.display = "";
    }

    // Helper functions
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
      return parseKocNumber(parts[1]) || 0;
    }

    function updateXPBox() {
      const xpVal = getSidebarValue("Experience");
      const turnsVal = getSidebarValue("Turns");

      const attacksLeft = Math.floor(turnsVal / TURNS_PER_ATTACK);
      const xpTradeAttacks = calculateXPTradeAttacks(xpVal, turnsVal);

      const avgGold = SafeStorage.get("xpTool_avgGold", 0);
      const totalPotential = xpTradeAttacks * avgGold;

      document.getElementById("xp-attacks").innerText = attacksLeft;
      document.getElementById("xp-trade").innerText = xpTradeAttacks;
      document.getElementById("xp-gold").innerText = formatGold(avgGold);
      document.getElementById("xp-total").innerText = formatGold(totalPotential);

      // Gold goal: what each hit must bring in without trading, and how many
      // XP trades it takes at the hit size you plan on.
      const goalEl = document.getElementById("xp-goal");
      const goalDetailRow = document.getElementById("xp-goal-detail");
      if (goalEl && goalDetailRow) {
        const goalHitFor = SafeStorage.get("xpTool_goalHitFor", 0);
        // Everything you hold counts: gold on hand + Safe + Vault, from the
        // sidebar on every page — so each hit you land shrinks what's left.
        const side = readOwnSidebar() || {};
        const held = { gold: side.goldN || 0, safe: side.safeN || 0, vault: side.vaultN || 0 };
        const g = goldGoalSummary({
          goal: SafeStorage.get("xpTool_goldGoal", 0),
          onHand: held.gold + held.safe + held.vault,
          countOnHand: SafeStorage.get("xpTool_goalCountOnHand", true),
          hitFor: goalHitFor > 0 ? goalHitFor : avgGold,
          xp: xpVal,
          turns: turnsVal
        });
        if (!g) {
          goalEl.innerText = "— set one";
          goalDetailRow.style.display = "none";
        } else {
          goalEl.innerText = formatGold(g.goal);
          goalEl.title = g.onHand > 0
            ? `Held ${formatGold(g.onHand)} = gold ${formatGold(held.gold)} + Safe ${formatGold(held.safe)} + Vault ${formatGold(held.vault)}`
            : "";
          // Short label | value rows so it fits the narrow sidebar (≈120px) without
          // wrapping. The game styles every td directly (10pt, white, and a
          // border-bottom inside table.table_lines), which beats anything set on
          // the inner table — so size, colour and border go on each cell.
          // Values hold together with × and &nbsp;, so a value only ever wraps
          // between the hit count and its status ("17 / 2 trades") when it must.
          const cellCss = "font-size:10px; line-height:1.4; border:0; padding:0; background:none;";
          const row = (label, value, tip = "") =>
            `<tr${tip ? ` title="${tip}"` : ""}><td style="${cellCss} width:1%; white-space:nowrap; text-align:left; padding-right:3px; color:#333;">${label}</td>` +
            `<td style="${cellCss} text-align:right; color:#000;">${value}</td></tr>`;
          let html;
          if (g.remaining <= 0) {
            html = "✅ <b>Reached</b>";
          } else {
            const hits = (n, perHit) => `${n}×<b>${formatGold(perHit)}</b>`;
            let rows = row("Need", `<b>${formatGold(g.remaining)}</b>`,
              `Goal ${formatGold(g.goal)} minus what you hold (gold + Safe + Vault)`);
            rows += row("No trade", g.noTradePerHit == null ? "—" : hits(g.noTradeHits, g.noTradePerHit),
              "Hits from the turns on hand × the gold each must bring in");
            if (g.maxTrades > 0) {
              rows += row("All XP", g.maxPerHit == null ? "—" : hits(g.maxAttacks, g.maxPerHit),
                `Hits if you trade all your XP (${g.maxTrades} trades) × the gold each must bring in`);
            }
            const hitLabel = "At " + formatGold(g.hitFor);
            let atVal;
            if (g.hitsNeeded == null) atVal = "set ✏️";
            else if (g.trades === 0) atVal = `${g.hitsNeeded} <b style="color:#006400;">no&nbsp;trade</b>`;
            else if (g.trades != null) atVal = `${g.hitsNeeded} <b style="color:#b45309;">${g.trades}&nbsp;trade${g.trades === 1 ? "" : "s"}</b>`;
            else atVal = `${g.hitsNeeded} <b style="color:#8b0000;">short</b>`;
            rows += row(hitLabel, atVal, `Hits needed at ${formatGold(g.hitFor)}${goalHitFor > 0 ? "" : " (your Avg Gold/Atk)"}, and the fewest XP trades that give them`);
            html = `<table style="width:100%; border-collapse:collapse; margin:0; font-size:10px;">${rows}</table>`;
          }
          const cell = goalDetailRow.firstElementChild;
          cell.innerHTML = html;
          cell.title = g.remaining <= 0 ? "" :
            `Goal ${g.goal.toLocaleString()}` + (g.onHand > 0 ? ` − ${g.onHand.toLocaleString()} held (gold + Safe + Vault)` : "") +
            ` = ${g.remaining.toLocaleString()} to find.\n` +
            `Without trading you have ${g.noTradeHits} hits (turns on hand).\n` +
            (g.trades > 0 ? `${g.trades} trade${g.trades === 1 ? "" : "s"} costs ${g.xpTraded.toLocaleString()} XP.\n` : "") +
            `Trading all your XP gives ${g.maxAttacks} hits (${g.maxTrades} trades).`;
          goalDetailRow.style.display = "";
        }
      }

      // Show a "manual" tag when Avg Gold/Atk is a manual override
      const xpGoldManualTag = document.getElementById("xp-gold-manual-tag");
      if (xpGoldManualTag) {
        xpGoldManualTag.style.display = SafeStorage.get("xpTool_avgGold_isManual", false) ? "inline" : "none";
      }

      // Banking Efficiency
      const goldLost = SafeStorage.get("KoC_GoldLost24h", 0);
      const myId = SafeStorage.get("KoC_MyId", null);
      const map = getNameMap();

      let projectedIncome = 0;
      if (map[myId]?.projectedIncome !== undefined) {
        projectedIncome = Number(map[myId].projectedIncome) || 0;
      }

      const dailyTbg = projectedIncome * MINUTES_PER_DAY;
      let bankedPctText = "—";

      if (dailyTbg > 0) {
        const bankedGold = Math.max(0, dailyTbg - goldLost);
        const pct = (bankedGold / dailyTbg * 100).toFixed(1);

        // Send a banked-% snapshot (at most every 30 min).
        maybeSubmitBankingSnapshot({
          bankedPct: parseFloat(pct),
          dailyTbg: Math.round(dailyTbg),
          goldLost24h: Math.round(goldLost),
          projectedIncome: Math.round(projectedIncome),
          goldOnHand: getSidebarValue("Gold")
        });

        // Pick pill background color
        let bg = "#8b0000";   // Dark red
        if (pct >= 25) bg = "#b45309";   // Amber
        if (pct >= 50) bg = "#a67c00";   // Goldenrod
        if (pct >= 75) bg = "#006400";   // Dark green

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
            border:1px solid rgba(0,0,0,0.2);
            vertical-align:middle;
          ">
            ${pct}%
          </span>`;
      }

      document.getElementById("xp-banked").innerHTML = bankedPctText;
    }

    updateXPBox();

    // Setup auth button
    const authBtn = document.getElementById("sr-auth-btn");
    if (authBtn) {
      // Update button text based on auth status
      function updateAuthButton() {
        const isAuthed = auth.getStoredAuth() !== null;
        authBtn.textContent = isAuthed ? "🔓 Logout" : "🔐 Login";
        authBtn.style.background = isAuthed
          ? "linear-gradient(135deg, #dc2626 0%, #991b1b 100%)"
          : "linear-gradient(135deg, #667eea 0%, #764ba2 100%)";
      }

      // Initial state
      updateAuthButton();

      // Click handler
      authBtn.addEventListener("click", async () => {
        const isAuthed = auth.getStoredAuth() !== null;
        if (isAuthed) {
          srConfirmLogout();
        } else if (onPage("base.php")) {
          await auth.login();
        } else {
          alert("Open your Command Center to log in.");
        }
      });

      // Listen for auth changes
      auth.on('authChanged', updateAuthButton);
    }

    // SR logo opens the Data Centre settings popup (same as the ⚙ sidebar link)
    const logoLink = document.getElementById("sr-logo-link");
    if (logoLink) {
      logoLink.addEventListener("click", (e) => {
        e.preventDefault();
        openFeatureSettings();
      });
    }

    // Manual override for Avg Gold/Atk — lets you set the value yourself instead of
    // relying on the auto-calibration from the attack log. Stored as a manual flag +
    // value; the effective value (xpTool_avgGold) is what every consumer reads.
    const goldEditBtn = document.getElementById("xp-gold-edit");
    if (goldEditBtn) {
      goldEditBtn.addEventListener("click", (e) => {
        e.preventDefault();
        const current = SafeStorage.get("xpTool_avgGold", 0);
        const isManual = SafeStorage.get("xpTool_avgGold_isManual", false);
        const prefill = current ? String(current) : "";
        const input = prompt(
          "Set Avg Gold/Atk manually (overrides the auto-calibration from the attack log).\n\n" +
          "Currently: " + (isManual ? "manual override" : "auto-calibrated from the attack log") + ".\n\n" +
          "Enter a number — suffixes ok, e.g. 1.5b, 750m, 250000000.\n" +
          "Type 'auto' (or leave blank) to go back to the calculated value.",
          prefill
        );
        if (input === null) return; // cancelled
        // OK without editing must not silently convert an auto-calibrated value
        // into a locked manual override — keep whichever mode is active.
        if (input === prefill) return;

        const trimmed = input.trim().toLowerCase();
        if (trimmed === "" || trimmed === "auto") {
          // Revert to the auto-calibrated value
          SafeStorage.set("xpTool_avgGold_isManual", false);
          const auto = SafeStorage.get("xpTool_avgGold_auto", SafeStorage.get("xpTool_avgGold", 0));
          SafeStorage.set("xpTool_avgGold", auto);
          debugLog("[Sidebar] Avg Gold/Atk reverted to auto:", auto);
        } else {
          let raw = trimmed.replace(/[,\s]/g, "");
          let mult = 1;
          if (raw.endsWith("b")) { mult = 1e9; raw = raw.slice(0, -1); }
          else if (raw.endsWith("m")) { mult = 1e6; raw = raw.slice(0, -1); }
          else if (raw.endsWith("k")) { mult = 1e3; raw = raw.slice(0, -1); }
          const val = parseFloat(raw) * mult;
          if (!isFinite(val) || val <= 0) {
            alert("Please enter a valid positive number (e.g. 1.5b, 750m, 250000000), or 'auto'.");
            return;
          }
          SafeStorage.set("xpTool_avgGold_manual", val);
          SafeStorage.set("xpTool_avgGold_isManual", true);
          SafeStorage.set("xpTool_avgGold", val);
          debugLog("[Sidebar] Avg Gold/Atk manual override set:", val);
        }
        updateXPBox();
      });
    }

    // Gold goal settings — ✏️ opens a small panel under the Goal rows.
    const goalEditBtn = document.getElementById("xp-goal-edit");
    const goalSettings = document.getElementById("xp-goal-settings");
    if (goalEditBtn && goalSettings) {
      const goalIn = document.getElementById("xp-goal-in");
      const hitIn = document.getElementById("xp-goal-hit-in");
      const onHandIn = document.getElementById("xp-goal-onhand-in");
      const readAmount = (el, label) => {
        const t = el.value.trim();
        if (t === "") return 0;
        const v = parseKocNumber(t);
        if (!v || v <= 0) { alert(`${label}: enter an amount like 1.2b, 750m or 33,000,000 — or leave it blank.`); return null; }
        return v;
      };
      goalEditBtn.addEventListener("click", (e) => {
        e.preventDefault();
        if (goalSettings.style.display === "none") {
          const goal = SafeStorage.get("xpTool_goldGoal", 0);
          const hitFor = SafeStorage.get("xpTool_goalHitFor", 0);
          goalIn.value = goal ? formatGold(goal) : "";
          hitIn.value = hitFor ? formatGold(hitFor) : "";
          onHandIn.checked = SafeStorage.get("xpTool_goalCountOnHand", true);
          goalSettings.style.display = "";
          goalIn.focus();
        } else {
          goalSettings.style.display = "none";
        }
      });
      const saveGoal = () => {
        const goal = readAmount(goalIn, "Goal");
        const hitFor = readAmount(hitIn, "Hit for");
        if (goal === null || hitFor === null) return;
        SafeStorage.set("xpTool_goldGoal", goal);
        SafeStorage.set("xpTool_goalHitFor", hitFor);
        SafeStorage.set("xpTool_goalCountOnHand", onHandIn.checked);
        goalSettings.style.display = "none";
        updateXPBox();
      };
      document.getElementById("xp-goal-save").addEventListener("click", (e) => {
        e.preventDefault();
        saveGoal();
      });
      document.getElementById("xp-goal-clear").addEventListener("click", (e) => {
        e.preventDefault();
        SafeStorage.set("xpTool_goldGoal", 0);
        SafeStorage.set("xpTool_goalHitFor", 0);
        goalSettings.style.display = "none";
        updateXPBox();
      });
      [goalIn, hitIn].forEach(el => el.addEventListener("keydown", (e) => {
        // Call the save directly. Never .click() the button: a script-made click
        // is an action the player didn't make, which this script must not do.
        if (e.key === "Enter") { e.preventDefault(); saveGoal(); }
      }));
    }

    // Banking trend graph button (opens the banked-% timeline modal)
    const bankingGraphBtn = document.getElementById("xp-banked-graph");
    if (bankingGraphBtn) {
      bankingGraphBtn.addEventListener("click", (e) => {
        e.preventDefault();
        showBankingTrend();
      });
    }

    debugLog("[Sidebar] Sidebar box inserted into page");
  }

  // ==================== POPUP CALCULATOR ====================

  function createAttackPopup() {
    const overlay = document.createElement('div');
    overlay.id = 'koc-popup-overlay';
    Object.assign(overlay.style, {
      position: 'fixed',
      top: '0',
      left: '0',
      width: '100%',
      height: '100%',
      backgroundColor: 'rgba(0,0,0,0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
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
      top: '5px',
      right: '10px',
      cursor: 'pointer',
      fontSize: '20px'
    });
    closeBtn.onclick = () => overlay.remove();

    const title = document.createElement('h3');
    title.textContent = '⚔️ Turn Trading Calculator';
    title.style.marginTop = '0';
    title.style.textAlign = 'center';

    // Input fields with validation constraints
    const turnsInput = document.createElement('input');
    turnsInput.type = 'number';
    turnsInput.placeholder = 'Turns';
    turnsInput.min = '0';
    turnsInput.max = '1000000';
    turnsInput.step = '1';
    turnsInput.style.width = '100%';
    turnsInput.style.marginBottom = '5px';

    const expInput = document.createElement('input');
    expInput.type = 'number';
    expInput.placeholder = 'Experience';
    expInput.min = '0';
    expInput.max = '100000000';
    expInput.step = '1';
    expInput.style.width = '100%';
    expInput.style.marginBottom = '5px';

    const avgInput = document.createElement('input');
    avgInput.type = 'number';
    avgInput.placeholder = 'Avg Gold/Atk';
    avgInput.min = '0';
    avgInput.max = '1000000000000';
    avgInput.step = 'any';
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
      // Validate and sanitize inputs
      const validation = validateCalculatorInput(
        turnsInput.value,
        expInput.value,
        avgInput.value
      );

      if (!validation.valid) {
        alert('⚠️ Invalid input:\n\n' + validation.errors.join('\n'));
        return;
      }

      const { turns, exp, avgGold } = validation.values;

      const maxAttacks = calculateXPTradeAttacks(exp, turns);
      const potGold = maxAttacks * avgGold;

      results.querySelector('#koc-max-attacks').textContent = maxAttacks.toLocaleString();
      results.querySelector('#koc-pot-gold').textContent = potGold.toLocaleString();

      debugLog('[Calculator] Validated input:', validation.values, '→ Output:', { maxAttacks, potGold });
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

  function hookSidebarPopup() {
    const th = [...document.querySelectorAll("th")]
      .find(el => el.innerText.includes("Turn Trading Calculator"));

    if (th) {
      th.style.cursor = 'pointer';
      th.title = 'Click to open Turn Trading Calculator';
      th.onclick = createAttackPopup;
    }
  }

  // ==================== ATTACK LOG ENHANCER ====================

  function enhanceAttackLog() {
    debugLog("[Sidebar] enhanceAttackLog called");

    const tables = document.querySelectorAll('table');
    for (let i = 0; i < tables.length; i++) {
      const tbl = tables[i];
      const txt = tbl.innerText.trim();

      // Look for summary headers
      if (txt.startsWith('Total By You Last 24 Hours') || txt.startsWith('Total On You Last 24 Hours')) {
        const dataTable = tables[i + 1];
        if (dataTable) {
          const rows = dataTable.querySelectorAll('tr');
          rows.forEach(r => {
            const cells = r.querySelectorAll('td');
            if (cells.length >= 3) {
              const label = cells[0].innerText.trim().toLowerCase();

              // Average Gold per Attack (By You)
              if (label.startsWith('attacks')) {
                const numAttacks = parseInt(cells[1].innerText.replace(/,/g, ''), 10);
                const gold = parseInt(cells[2].innerText.replace(/,/g, ''), 10);

                if (numAttacks > 0) {
                  const avg = gold / numAttacks;
                  const labelTxt = (avg >= 1e9)
                    ? (avg / 1e9).toFixed(1) + 'B AV'
                    : (avg / 1e6).toFixed(1) + 'M AV';

                  const th = tbl.querySelector('th');
                  if (th && !th.innerHTML.includes('AV')) {
                    const div = document.createElement('div');
                    div.style.textAlign = 'center';
                    div.textContent = `${th.innerText} (${labelTxt})`;
                    th.replaceChildren(div);
                  }

                  // Save avg gold for Sidebar + Popup.
                  // Keep the auto-calibrated value separately (xpTool_avgGold_auto) so a
                  // manual override set via the sidebar ✏️ survives attack-log recalcs.
                  // Only update the effective value when no manual override is active.
                  if (txt.startsWith('Total By You Last 24 Hours')) {
                    SafeStorage.set('xpTool_avgGold_auto', avg);
                    SafeStorage.set('xpTool_avgGold_time', Date.now());
                    if (!SafeStorage.get('xpTool_avgGold_isManual', false)) {
                      SafeStorage.set('xpTool_avgGold', avg);
                      debugLog("[Sidebar] Avg Gold/Atk auto-calibrated:", avg);
                    } else {
                      debugLog("[Sidebar] Avg Gold/Atk auto value updated, but manual override active — keeping manual.");
                    }
                  }
                }
              }

              // Gold Lost (On You) for Banking Efficiency
              if (txt.startsWith('Total On You Last 24 Hours') && label === 'total') {
                const goldLost = parseInt(cells[2].innerText.replace(/,/g, ''), 10) || 0;
                SafeStorage.set("KoC_GoldLost24h", goldLost);
                SafeStorage.set("KoC_GoldLost24h_time", new Date().toISOString());
                debugLog("📊 Banking: Gold lost (24h) saved:", goldLost);
              }
            }
          });
        }
      }
    }
  }

  // ==================== RECON PAGE: MAX ATTACKS ====================

  function addMaxAttacksRecon() {
    const ROW_ID = "koc-max-attacks-row";
    if (document.getElementById(ROW_ID)) return; // Avoid duplicates

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
    let turns = 0;
    let exp = 0;

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

    debugLog("[Sidebar] Recon Max Attacks row added:", maxAttacks);
  }

  // ==================== BATTLEFIELD COLLECTOR ====================

  let battlefieldTimeout = null;
  let collectedPlayers = new Set();

  async function collectFromBattlefield() {
    if (battlefieldTimeout) {
      clearTimeout(battlefieldTimeout);
    }

    battlefieldTimeout = setTimeout(async () => {
      const rows = document.querySelectorAll("tr[user_id]");
      let newCount = 0;

      // Map column indexes from the table header — the battlefield sometimes
      // renders rows without the Alliance column (mid-AJAX states drop cells),
      // so fixed indexes would corrupt data: name would get the army size and
      // alliance the player name.
      const headerCells = rows[0]
        ? [...(rows[0].closest("table")?.querySelectorAll("th") || [])]
        : [];
      const colIndex = {};
      headerCells.forEach((th, i) => {
        const label = th.innerText.trim().toLowerCase();
        if (label === "alliance") colIndex.alliance = i;
        else if (label === "rank") colIndex.rank = i;
      });

      rows.forEach(row => {
        const id = row.getAttribute("user_id");
        if (collectedPlayers.has(id)) return;

        const cells = row.querySelectorAll("td");
        // Positional columns are only trustworthy when the row actually has
        // one cell per header column
        const aligned = headerCells.length > 0 && cells.length === headerCells.length;

        // Name: only trust the stats link that points at this row's own id
        const nameLink = [...row.querySelectorAll("a[href*='stats.php?id=']")]
          .find(a => a.href.match(/id=(\d+)/)?.[1] === id);
        const name = nameLink?.textContent.trim() || "";

        // Alliance: the alliances.php link in the alliance column (empty for
        // unallied players — leave existing DB value untouched)
        let alliance = "";
        if (aligned && colIndex.alliance != null) {
          alliance = cells[colIndex.alliance]?.querySelector("a[href*='alliances.php']")?.textContent.trim() || "";
        }

        const rank = (aligned && colIndex.rank != null) ? (cells[colIndex.rank]?.innerText.trim() || "") : "";

        // Build player object - ONLY alliance, name, id, rank (no timestamps - DB doesn't have those columns)
        const patch = { id };
        if (name) patch.name = name;
        if (alliance) patch.alliance = alliance;
        if (rank) patch.rank = rank;
        if (Object.keys(patch).length === 1) return; // nothing trustworthy scraped

        const player = sanitizePlayerData(patch);

        updatePlayerInfo(player.id, player, 'battlefield');
        collectedPlayers.add(id);
        newCount++;
      });

      if (newCount > 0) {
        debugLog(`[DataCentre] Captured ${newCount} new players from battlefield (alliance, name, rank only)`);
      }

      battlefieldTimeout = null;
    }, BATTLEFIELD_COLLECT_DELAY_MS);
  }

  // ==================== WAR LIST COLLECTOR ====================
  /**
   * warlist.php?view=Alliance is the only page that shows, for every player on
   * the list at once: their sentry WITH the age of the game's own reading, the
   * weapon the game recommends sabbing them with, and the AAT — how many of
   * that weapon they actually hold, plus the gold one full sab would destroy.
   *
   * AAT reads like an inventory count but it is per-sab capacity: what ONE
   * successful sab destroys. Measured across 102 players, aat x unit price is
   * 0.0012 of TIV every time, and the daily cap divided by it is 128 — the
   * number of successful sabs it takes to max somebody out.
   *
   * Verified against the live page (110 rows): every row has 11 cells, the
   * player id is always in the row's own links even when the game hides the
   * name, sentry of 0 is common and real, and the gold per weapon is NOT
   * always 1,000,000 (Chariot and Ebony Platemail are 450,000) — so the
   * game's own "damage per sab" figure is taken rather than assumed.
   */
  function parseWarListPage() {
    const table = [...document.querySelectorAll('table')].filter(t => {
      const ths = [...t.querySelectorAll('th')].map(th => th.textContent.trim().toLowerCase());
      return ths.includes('aat') && ths.some(h => h.startsWith('recommended'));
    }).pop();
    if (!table) return [];

    // Columns by header name, never by fixed position: a dropped cell would
    // shift every value one place left.
    const heads = [...table.querySelectorAll('th')].map(th => th.textContent.trim().toLowerCase());
    const col = {};
    heads.forEach((h, i) => {
      // The membership columns are compared with spaces and punctuation
      // stripped: "My 24hr Sabs" and "Time Added / Reason" are the kind of
      // header a <br> gets put into, and textContent flattens a <br> to nothing.
      const k = h.replace(/[^a-z0-9]/g, '');
      if (h === 'name') col.name = i;
      else if (h === 'sentry') col.sentry = i;
      else if (h.startsWith('recommended')) col.weapon = i;
      else if (h === 'aat') col.aat = i;
      else if (h.startsWith('last sab')) col.lastSab = i;
      else if (k.startsWith('my24hr') && k.includes('sab')) col.mySab = i;
      else if (k.startsWith('my24hr') && k.includes('poison')) col.myPoison = i;
      else if (k.startsWith('my24hr') && k.includes('theft')) col.myTheft = i;
      else if (k.startsWith('timeadded')) col.added = i;
    });
    if (col.sentry == null && col.aat == null) return [];

    const firstNum = (s) => {
      const m = String(s).replace(/,/g, '').match(/\d+/);
      return m ? parseInt(m[0], 10) : null;   // 0 is a real sentry, never null
    };
    // These cells hold two numbers with only a <br> between them:
    //   AAT     "488" <br> <span>488,000,000 damage per sab</span>
    //   Sentry  "309,747,148"   <span>(2min)</span>
    // Flattened to text they run together as "488488,000,000" — and a 488 that
    // reads as 488 billion is the worst possible error in a targeting tool. So
    // read the lead number from the cell's own text nodes and the rest from its
    // child elements, which is unambiguous however the text gets flattened.
    const leadNum = (el) => {
      if (!el) return null;
      for (const n of el.childNodes) {
        if (n.nodeType !== 3) continue;
        const m = (n.textContent || '').replace(/,/g, '').match(/\d+/);
        if (m) return parseInt(m[0], 10);
      }
      return null;
    };
    const tailText = (el) => !el ? '' :
      [...el.childNodes].filter((n) => n.nodeType === 1).map((n) => n.textContent || '').join(' ');
    const ageMs = (s) => {
      const m = String(s).match(/\((\d+)\s*(min|mins|h|hr|hrs|d|day|days)\)/i);
      if (!m) return null;
      const n = parseInt(m[1], 10), u = m[2].toLowerCase();
      return u.startsWith('min') ? n * 60000 : u.startsWith('d') ? n * 86400000 : n * 3600000;
    };
    // A "My 24hr" cell exactly as shown — "None", "6/9", or a <span>MAXED</span>.
    // It goes to the server raw and is parsed there, in one place.
    const cellText = (el) => {
      const t = el ? (el.textContent || '').replace(/\s+/g, ' ').trim() : '';
      return t || null;
    };

    const out = [];
    for (const tr of [...table.querySelectorAll('tr')].slice(1)) {
      const tds = tr.querySelectorAll('td');
      if (tds.length !== heads.length) continue;  // only trust rows that line up
      const link = [...tr.querySelectorAll('a[href*="id="]')]
        .find(a => /stats\.php|attack\.php|warlist_player\.php/.test(a.getAttribute('href') || ''));
      const id = link && (link.getAttribute('href').match(/id=(\d+)/) || [])[1];
      if (!id) continue;

      const sentryCell = tds[col.sentry], aatCell = tds[col.aat];
      const sentryText = (sentryCell || {}).innerText || '';
      const aatText = ((aatCell || {}).innerText || '').replace(/,/g, '');
      // Structural read first, flattened text only as a fallback if the page
      // ever stops using the <br> + <span> shape.
      const sentry = leadNum(sentryCell) ?? firstNum(sentryText);
      const aat = leadNum(aatCell) ?? firstNum(aatText);
      const goldText = tailText(aatCell) || aatText;
      const gold = parseInt(String((goldText.match(/([\d,]+)\s*damage per sab/i) || [])[1] || '').replace(/,/g, ''), 10);
      const nameCell = tds[col.name];
      const nameLink = nameCell && nameCell.querySelector('a');
      const allianceSpan = nameCell && nameCell.querySelector('span');
      const added = parseWarListAdded(tds[col.added] ? tds[col.added].textContent : '');

      out.push({
        id,
        // The game hides the name on some rows; the id still identifies them,
        // so never write an empty name over a good one.
        name: nameLink && nameLink.textContent.trim() ? nameLink.textContent.trim() : null,
        alliance: allianceSpan && allianceSpan.textContent.trim() ? allianceSpan.textContent.trim() : null,
        sentry,
        sentryAgeMs: ageMs(tailText(sentryCell) || sentryText),
        weapon: ((tds[col.weapon] || {}).textContent || '').trim() || null,
        aat,
        sabGold: Number.isFinite(gold) ? gold : null,
        lastSab: parseLastSab(tds[col.lastSab], leadNum, tailText, ageMs),
        // War List membership: when they were put on the list (KoC server
        // time, converted on the server) and why, and the viewer's OWN "My
        // 24hr" counters on them. "MAXED" there means the viewer's 10 attempts
        // are used — it says nothing about the target's damage cap.
        addedAt: added.addedAt,
        reason: added.reason,
        my24h: {
          sab: cellText(tds[col.mySab]),
          poison: cellText(tds[col.myPoison]),
          theft: cellText(tds[col.myTheft])
        }
      });
    }

    // The page is its own price list: every row with both an AAT and a gold
    // figure states that weapon's unit price, and they vary (Chariot and Ebony
    // Platemail are 450k where most are 1M). Use it to value the last sab,
    // whose weapon is not always the one recommended now.
    const unitPrice = {};
    for (const r of out) {
      if (r.weapon && r.aat > 0 && r.sabGold > 0) unitPrice[r.weapon] = r.sabGold / r.aat;
    }
    for (const r of out) {
      if (r.lastSab && r.lastSab.weapon && unitPrice[r.lastSab.weapon]) {
        r.lastSab.gold = Math.round(r.lastSab.weapons * unitPrice[r.lastSab.weapon]);
      }
    }
    return out;
  }

  /**
   * "5,148 Lookout Tower by Spook-SR (1d)" — amount, weapon, who, how long ago.
   * "0 Nunchaku by Cranz-SR (1d)" is a sab that took nothing, and "None" means
   * nobody has sabbed them at all.
   */
  function parseLastSab(cell, leadNum, tailText, ageMs) {
    if (!cell) return null;
    const weapons = leadNum(cell);
    if (weapons === null) return null;           // "None"
    const lead = [...cell.childNodes].find((n) => n.nodeType === 3 && /\d/.test(n.textContent || ''));
    const weapon = lead
      ? (lead.textContent || '').replace(/,/g, '').replace(/^\s*\d+\s*/, '').replace(/\s*by\s*$/i, '').trim()
      : '';
    const who = cell.querySelector('a');
    return {
      weapons,
      weapon: weapon || null,
      by: who && who.textContent.trim() ? who.textContent.trim() : null,
      agoMs: ageMs(tailText(cell)),
      gold: null
    };
  }

  /**
   * "2026-09-11 16:55:41 Reason:" — the Time Added / Reason cell. The stamp is
   * KoC server time and is sent as printed (the server converts it, with the
   * same helper the Inactive Accounts sync uses). The reason is whatever
   * follows "Reason:", usually nothing.
   */
  function parseWarListAdded(text) {
    const t = String(text || '').replace(/\s+/g, ' ').trim();
    const stamp = t.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
    const why = t.match(/Reason:\s*(.*)$/i);
    return {
      addedAt: stamp ? stamp[1] : null,
      reason: why && why[1].trim() ? why[1].trim() : null
    };
  }

  async function collectFromWarList() {
    // A War List brought back with Back / Forward is the page as it was then:
    // its "My 24hr" cells are old, and sending them would stamp them as seen
    // now. Nothing is sent from it (the roster refuses one anyway).
    if (pageNavType() === 'back_forward') { debugLog('⚔️ War list: page restored with Back/Forward — not sent'); return; }
    const rows = parseWarListPage();
    if (!rows.length) { debugLog('⚔️ War list: no parseable rows'); return; }

    // Who is on the War List, sent first and as ONE request, so it lands even
    // if the member moves on before the per-player loop below finishes: each
    // row's id, when and why it was added, and this member's own "My 24hr"
    // cells. The server keeps the list itself (first/last seen) and each
    // member's latest counters per target. Reading only — the game allows no
    // changes on this page, and nothing here makes any. `page` says how the
    // page was reached and the Server Time it was drawn with (pageInfo).
    const view = new URLSearchParams(location.search).get('view') || 'Alliance';
    try {
      const res = await auth.apiCall('war-list', 'api/war-room/warlist', {
        view,
        rows: rows.map((r) => ({ id: r.id, addedAt: r.addedAt, reason: r.reason, my24h: r.my24h })),
        page: pageInfo()
      });
      debugLog(`⚔️ War list membership (${view}): ${rows.length} rows sent`, res);
    } catch (e) { /* the war room may not be configured; never break the page */ }

    const now = Date.now();
    let sentryCount = 0, aatCount = 0;
    for (const r of rows) {
      const payload = {
        id: r.id,
        // The War List keeps listing players who have gone into vacation mode,
        // so seeing somebody here is NOT evidence they are playing again.
        noReactivate: true
      };
      if (r.sentry !== null) {
        payload.sentryRating = r.sentry;
        // Stamp the game's own reading age, not "now" — the server only
        // accepts a value whose timestamp beats what it already holds, so an
        // honest age also protects a fresher recon from being overwritten.
        payload.sentryRatingTime = new Date(now - (r.sentryAgeMs || 0)).toISOString();
        sentryCount++;
      }
      if (r.aat !== null && r.weapon) {
        payload.sabWeapon = { weapon: r.weapon, aat: r.aat, gold: r.sabGold };
        payload.sabWeaponTime = new Date(now).toISOString();
        aatCount++;
      }
      if (r.lastSab) {
        payload.lastSab = r.lastSab;
        payload.lastSabTime = new Date(now).toISOString();
      }
      if (r.name) payload.name = r.name;
      if (r.alliance) payload.alliance = r.alliance;
      if (Object.keys(payload).length <= 2) continue;  // id + noReactivate only

      try { await auth.apiCall('war-list', 'players', payload); } catch (e) { /* keep going */ }
    }

    // The same sabs, logged once for the war's own record: a running account of
    // what the alliance has actually destroyed, and the damage side of the
    // calibration loop. One request for the page; the server dedupes, so
    // revisiting the list does not count anything twice.
    const observed = rows.filter((r) => r.lastSab).map((r) => ({
      targetId: r.id,
      weapons: r.lastSab.weapons,
      weapon: r.lastSab.weapon,
      by: r.lastSab.by,
      gold: r.lastSab.gold,
      agoMs: r.lastSab.agoMs
    }));
    if (observed.length) {
      try {
        const res = await auth.apiCall("war-list", "api/war-room/sab-results/bulk", { results: observed });
        debugLog(`⚔️ War list sab log: ${observed.length} seen, ${res && res.inserted} new`);
      } catch (e) { /* the war room may not be configured; never break the page */ }
    }
    debugLog(`⚔️ War list collected ${rows.length} rows (${sentryCount} sentry, ${aatCount} AAT, ${observed.length} sabs)`);
  }

  // ==================== INACTIVE ACCOUNTS COLLECTOR ====================
  /**
   * inactives.php lists every inactive account in the game: the exact server
   * time each one went inactive, whether it was Vacation Mode or a deletion,
   * and their alliance. The game drops a player from it the moment their
   * vacation ends, so the whole list goes to the roster as one snapshot and
   * the server works out who is new, who is still away and who is back. That
   * is what keeps the dashboard's Vacation Watch countdowns exact.
   *
   * Reads only the page you opened — nothing here fetches or reloads it. The
   * cells are sent exactly as shown; parsing and the KoC-time conversion
   * happen on the server, so a change to the page is fixed in one place.
   */
  function readInactivesTable() {
    // Work from the header row itself, using direct cells only: KoC nests its
    // tables inside layout tables, and a title row above the column headers
    // would otherwise shift every column by one.
    const cellsOf = (tr, tag) => [...tr.children].filter(c => c.tagName === tag);
    const headerRow = [...document.querySelectorAll('tr')].find(tr => {
      const heads = cellsOf(tr, 'TH').map(th => th.textContent.trim().toLowerCase());
      return heads.includes('statsid') && heads.includes('inactive reason');
    });
    if (!headerRow) return null;
    const table = headerRow.closest('table');
    const headers = cellsOf(headerRow, 'TH').map(th => th.textContent.trim());
    const rows = [...table.querySelectorAll('tr')]
      .filter(tr => tr.closest('table') === table && cellsOf(tr, 'TH').length === 0)
      .map(tr => cellsOf(tr, 'TD').map(td => td.textContent.trim()))
      .filter(cells => cells.length > 0);
    return { headers, rows };
  }

  async function collectFromInactives() {
    const read = readInactivesTable();
    if (!read) { debugLog('🏖️ Inactive Accounts: table not found'); return; }

    const res = await auth.apiCall('inactives', 'api/war-room/inactives', read);
    if (!res || !res.ok) {
      debugLog('🏖️ Inactive Accounts: not recorded', res);
      return;
    }
    debugLog(`🏖️ Inactive Accounts: ${res.seen} rows, ${res.vacation} on vacation, ${res.updated} updated, back: ${res.returned.map(p => p.name).join(', ') || 'nobody'}`);

    if (!res.returnsApplied) {
      ErrorHandler.showNotification(`Vacation Watch: this list looked incomplete (${res.withheldReason}), so nobody was marked back. Reload the page to try again.`, 'warn');
    } else if (res.returned.length) {
      ErrorHandler.showNotification(`Vacation Watch updated — back from vacation: ${res.returned.map(p => p.name).join(', ')}`, 'info');
    } else {
      ErrorHandler.showNotification(`Vacation Watch updated — ${res.vacation} on vacation`, 'info');
    }
  }

  // ==================== ATTACK TIV COLLECTOR ====================

  /**
   * The target of the attack page. Usually it is in the address
   * (attack.php?id=…), but when the game answers a mission form itself — most
   * importantly when it refuses a sab because the target is maxed — it redraws
   * attack.php with no query string at all. Every mission form on the page
   * carries the target in a hidden defender_id field, so fall back to that.
   * That redrawn page is the one that says for certain the target is maxed.
   */
  function attackPageTargetId() {
    const m = location.search.match(/[?&]id=(\d+)/);
    if (m) return m[1];
    const el = document.querySelector('input[name="defender_id"]');
    return el && /^\d+$/.test(el.value || '') ? el.value : null;
  }

  async function collectTIVFromAttackPage() {
    const targetId = attackPageTargetId();

    // Check for Invalid User ID error
    if (document.body.textContent.includes("Invalid User ID")) {
      if (targetId) {
        const id = targetId;
        console.warn(`⚠️ Invalid User ID detected for player ${id} - marking as deleted`);
        await auth.apiCall('attack-pages', `players/${id}/mark-inactive`, {
          status: "deleted",
          error: "Invalid User ID"
        });
      }
      return;
    }

    // A target sabbed flat renders "Total Invested Value: ()" — empty parens,
    // not "(0)". The regex allows empty digits and records that as TIV 0.
    const tivMatch = document.body.textContent.match(/Total Invested Value:\s*\(([\d,]*)\)/i);
    if (!targetId || !tivMatch) return;

    const id = targetId;
    const tivDigits = tivMatch[1].replace(/,/g, "");
    const tiv = tivDigits === "" ? 0 : parseInt(tivDigits, 10);
    if (!Number.isFinite(tiv)) return;
    const now = getKoCServerTimeUTC();

    updatePlayerInfo(id, { tiv, tivTime: now }, 'attack-pages');

    debugLog("📊 Attack TIV saved", { id, tiv });

    // Push to API
    await auth.apiCall("attack-pages", "tiv", { playerId: id, tiv, time: now });
  }

  // ==================== ATTACK LOG COLLECTOR ====================

  /**
   * The defender on a battle report (detail.php?attack_id=): the first player
   * link on the page that is not the member's own. The report links them in
   * its "You stole … camp" line and in the battle text ("<name>'s forces
   * counter-attack"). Shared by collectAttackLog and the mission history, so
   * both file the battle against the same player. null when there is none.
   */
  function battleReportTargetId(myId) {
    for (const link of document.querySelectorAll('a[href*="stats.php?id="]')) {
      try {
        const id = new URL(link.href, location.origin).searchParams.get('id');
        if (id && /^\d+$/.test(id) && id !== myId) return id;
      } catch (error) {
        // Skip invalid links
      }
    }
    return null;
  }

  /**
   * The first line of a WON battle report, matched as [line, gold, the
   * defender's name], or null. An attack and a raid word it differently:
   * "You stole N gold while attacking <name>'s camp and made off with H
   * hostages (…)" / "… while raiding <name>'s camp …". Takes the report's
   * own lines (battleReportLines), and only a line that STARTS with those
   * words counts: the defender's own message sits above the report
   * ("<name> said …") and can name any camp it likes.
   *
   * A message broken over lines could still start one with those very
   * words, so the line must also agree with the battle text below it, which
   * no player writes into: a battle that ends "<name>'s forces overpowered
   * your army!" was lost and stole nothing; the name must be the one in
   * "<name>'s forces counter-attack"; and when the spoils line "You stole N
   * gold from <name>'s" is there, the line with that same N is the one. Any
   * of those missing (a wording the game changed) is simply not checked.
   */
  function battleReportStoleLine(lines) {
    const list = (lines || []).filter((l) => typeof l === 'string');
    const first = (re) => list.map((l) => l.match(re)).find(Boolean) || null;
    if (first(/^\s*\S+?'s forces overpowered your army\b/i)) return null;
    const named = first(/^\s*(\S+?)'s forces counter-attack\b/i);
    const spoils = first(/^\s*You stole ([\d,]+) gold from\b/i);
    const found = list.map((l) => l.match(/^\s*You stole ([\d,]+) gold while (?:attacking|raiding) (.+?)'s camp/i))
      .filter((m) => m && (!named || m[2].trim().toLowerCase() === named[1].toLowerCase()));
    return (spoils && found.find((m) => m[1] === spoils[1])) || found[0] || null;
  }

  /**
   * Whether a battle report's lines hold the WHOLE battle yet. Its own
   * closing lines come last: a loss's "<name>'s forces overpowered your
   * army!", or a win's spoils line "You stole N gold from <name>'s" with the
   * first line's N. A read that has them has everything above them too. A
   * win's first line (and so its outcome) is drawn BEFORE the battle, so
   * having the outcome is not enough. A win worded any other way is never
   * taken as whole. Shared by collectAttackLog and the mission history, so
   * both wait for the same thing — the server keeps the first copy of a
   * report's text it gets, so a half-drawn one would stick.
   */
  function battleReportWhole(lines) {
    const list = (lines || []).filter((l) => typeof l === 'string');
    if (list.some((l) => /^\s*\S+?'s forces overpowered your army\b/i.test(l))) return true;
    const stole = battleReportStoleLine(list);
    const spoils = list.map((l) => l.match(/^\s*You stole ([\d,]+) gold from\b/i)).find(Boolean);
    return !!stole && !!spoils && spoils[1] === stole[1];
  }

  /**
   * The defender's name from a battle report's own lines, or null. A win
   * names them in its first line (battleReportStoleLine). A lost battle has
   * no such line, but its battle text has a line that starts "<name>'s
   * forces counter-attack …" and, at the end, "<name>'s forces overpowered
   * your army!". Held to the start of a line, with no space in the name, so
   * a defender's message ("<name> said <name>'s forces overpowered your
   * army") can never be the one read. A string is taken as its lines.
   */
  function battleReportTargetName(lines) {
    const list = Array.isArray(lines) ? lines : String(lines || '').split('\n');
    const stole = battleReportStoleLine(list);
    if (stole && stole[2].trim()) return stole[2].trim();
    for (const l of list) {
      const m = typeof l === 'string' ? l.match(/^\s*(\S+?)'s forces (?:counter-attack|overpowered your army)\b/i) : null;
      if (m) return m[1];
    }
    return null;
  }

  /**
   * Whether a battle report (detail.php?attack_id=) is the member's OWN
   * attack or raid, told from the attacker's side. Both sides of a battle
   * get a report, and both open with "Your soldiers march onto the
   * battlefield" — that line says nothing about whose attack it was. What
   * does:
   *   attacker's side only — a "… Again!" button (battleReportAgainButton);
   *     "N of your soldiers are trained attack specialists"; "<name>'s
   *     forces counter-attack and inflict …"; "You stole N gold while
   *     attacking / raiding <name>'s camp …"
   *   defender's side only — "N of your soldiers are trained defense
   *     specialists"; "<name>'s forces attack and inflict …"; on a lost
   *     defence, a first line "<name> took ya N gold while attacking you and
   *     ran off with …"
   * Ours = at least one attacker mark and no defender mark. A report with
   * neither (a wording the game has changed, a page not fully drawn yet) is
   * not ours to record. Every mark is held to the start of a line of the
   * report's own lines (battleReportLines), so a message a player wrote
   * above the report cannot pass for one. The "took ya" line is among those
   * lines only when the battle itself has that player attacking the member
   * (battleReportLines), so on a page it never vetoes alone: a message line
   * starting "<word> took ya" over the member's own lost raid is not one of
   * the report's lines, and the raid is still recorded. Shared by
   * collectAttackLog and the mission history: an enemy's hit on the member,
   * filed as the member's own attack, would stay wrong for good (the server
   * keeps the first attacker it is told).
   */
  function battleReportIsOwnAttack(lines) {
    const list = (lines || []).filter((l) => typeof l === 'string').map((l) => l.trim());
    const has = (re) => list.some((l) => re.test(l));
    // "you" as the one attacked, not the start of a name ("… attacking you-2's camp")
    const defender = has(/^[\d,]+ of your soldiers are trained defense specialists\b/i) ||
      has(/^\S+?'s forces attack and inflict\b/i) ||
      has(/^\S+ took ya\b/i) ||
      has(/^(?:\S+ ){1,3}[\d,]+ gold while (?:attacking|raiding) you\b(?!\S*'s camp)/i);
    if (defender) return false;
    return !!battleReportAgainButton() ||
      has(/^[\d,]+ of your soldiers are trained attack specialists\b/i) ||
      has(/^\S+?'s forces counter-attack and inflict\b/i) ||
      !!battleReportStoleLine(list);
  }

  /**
   * detail.php?attack_id= — the member's own attack or raid, as one
   * attack_logs row (POST battlefield/attack-log). Read twice per page view:
   * at once, and ATTACK_LOG_DELAY_MS later in case the report was not all
   * on the page yet. Resolves true when this read sent the WHOLE report and
   * the server took it ({ ok: true }); false otherwise.
   *
   * after: the first read's promise, on the delayed read. When it resolves
   * true there is nothing to add and nothing is sent. A first read that found
   * only part of the report, or whose post failed, leaves the delayed read to
   * send (the server fills a repeat's missing fields and takes the late
   * gold).
   */
  async function collectAttackLog({ after = null } = {}) {
    debugLog("📊 Attack log collector triggered");

    if (after && await Promise.resolve(after).catch(() => false)) {
      debugLog("📊 Attack log: the first read sent the whole report — not sent again");
      return true;
    }

    // Extract attack ID from URL
    const urlParams = new URLSearchParams(location.search);
    const attackId = urlParams.get('attack_id');
    if (!attackId) {
      debugLog("⚠️ No attack_id found in URL");
      return false;
    }

    // Everything is read from the report's own lines (battleReportLines, the
    // same reader the mission history uses), never from the whole page: the
    // defender's message above the report ("<name> said …") is on the page
    // too and must never supply the target's name.
    const lines = battleReportLines();
    if (!lines.length) {
      debugLog("⚠️ No battle report on this page (yet)");
      return false;
    }
    // Both sides of a battle get a report; only the member's own attack or
    // raid is recorded here.
    if (!battleReportIsOwnAttack(lines)) {
      debugLog("📊 Attack log: not a report of your own attack or raid (another player's attack on you, or not drawn yet) — not sent");
      return false;
    }
    const reportText = lines.join('\n');
    const myId = SafeStorage.get("KoC_MyId", null);

    // Gold, target and hostages are on a win's first line: "You stole N gold
    // while attacking <name>'s camp and made off with H hostages (Attack: …)".
    // A raid reads "while RAIDING"; both wordings match. A lost battle has no
    // such line: 0 stolen is then the truth,
    // and the name comes from its battle text (battleReportTargetName).
    const stole = battleReportStoleLine(lines);
    const stoleLine = stole ? stole.input : '';
    const goldStolen = stole ? parseInt(stole[1].replace(/,/g, ''), 10) : 0;
    const targetName = battleReportTargetName(lines) || 'Unknown';

    const hostagesMatch = stoleLine.match(/made\s+off\s+with\s+([\d,]+)\s+hostages/i);
    const hostages = hostagesMatch ? parseInt(hostagesMatch[1].replace(/,/g, ''), 10) : 0;

    // The hostages by unit type, same line. Thousands separators allowed: a
    // big hit can take more than 999 of one kind ("1,203").
    const casualtiesMatch = stoleLine.match(/\(Attack:\s*([\d,]+),\s*Defense:\s*([\d,]+),\s*Untrained:\s*([\d,]+),\s*Spies:\s*([\d,]+),\s*Sentries:\s*([\d,]+)\)/i);
    const count = (s) => parseInt(String(s).replace(/,/g, ''), 10) || 0;
    const casualties = casualtiesMatch ? {
      attack: count(casualtiesMatch[1]),
      defense: count(casualtiesMatch[2]),
      untrained: count(casualtiesMatch[3]),
      spies: count(casualtiesMatch[4]),
      sentries: count(casualtiesMatch[5])
    } : null;

    // Extract your army stats
    const yourTrainedMatch = reportText.match(/([\d,]+)\s+of your soldiers are trained attack specialists/i);
    const yourUntrainedMatch = reportText.match(/([\d,]+)\s+of your army consists of untrained soldiers/i);
    const yourArmy = {
      trained: yourTrainedMatch ? parseInt(yourTrainedMatch[1].replace(/,/g, ''), 10) : null,
      untrained: yourUntrainedMatch ? parseInt(yourUntrainedMatch[1].replace(/,/g, ''), 10) : null
    };

    // Extract enemy army stats
    const enemyTrainedMatch = reportText.match(/enemy has\s+([\d,]+)\s+trained soldiers with weapons/i);
    const enemyUntrainedMatch = reportText.match(/enemy's\s+([\d,]+)\s+untrained soldiers/i);
    const enemyArmy = {
      trained: enemyTrainedMatch ? parseInt(enemyTrainedMatch[1].replace(/,/g, ''), 10) : null,
      untrained: enemyUntrainedMatch ? parseInt(enemyUntrainedMatch[1].replace(/,/g, ''), 10) : null
    };

    // Extract damage dealt
    const damageMatch = reportText.match(/inflict\s+([\d,]+)\s+damage/i);
    const damageDealt = damageMatch ? parseInt(damageMatch[1].replace(/,/g, ''), 10) : 0;

    // Extract enemy casualties
    const enemyCasualtiesMatch = reportText.match(/enemy sustains\s+([\d,]+)\s+casualties/i);
    const enemyCasualties = enemyCasualtiesMatch ? parseInt(enemyCasualtiesMatch[1].replace(/,/g, ''), 10) : 0;

    // Find target ID
    const targetId = battleReportTargetId(myId);

    if (!targetId) {
      debugLog("⚠️ Could not find target ID");
      return false;
    }

    // Build attack log payload: what the report itself shows. (Up to v3.0.0
    // this also sent `fresh`, so the server could take the stolen gold off
    // the target's gold estimate once; that estimate is gone, #138.)
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

    debugLog("📊 Attack log collected:", attackLog);

    // Only a read of the whole report (battleReportWhole) stops the delayed
    // read; a win worded any other way is never taken as whole, so the
    // delayed read posts it again.
    const whole = battleReportWhole(lines);

    // Send to API
    const res = await auth.apiCall("attack-pages", "battlefield/attack-log", attackLog);
    return whole && !!(res && res.ok);
  }

  // ==================== MILITARY STATS PARSER ====================

  function collectMilitaryStats() {
    const header = document.evaluate(
      `.//th[contains(., "Military Effectiveness")]`,
      document,
      null,
      XPathResult.FIRST_ORDERED_NODE_TYPE,
      null
    ).singleNodeValue;

    if (!header) return {};

    const table = header.closest("table");
    const stats = {};
    const ranks = {}; // ranks tracked separately
    const now = getKoCServerTimeUTC();

    table.querySelectorAll("tr").forEach(row => {
      const cells = row.querySelectorAll("td");
      if (cells.length < 2) return;

      const label = cells[0].innerText.trim().toLowerCase();
      const value = cells[1].innerText.trim();
      const rankText = cells[2]?.innerText.trim(); // rank from the 3rd column

      // Extract rank number from "#117" or "#1,234" format (handle commas for ranks over 1000)
      const rankMatch = rankText?.match(/#([\d,]+)/);
      const rank = rankMatch ? parseInt(rankMatch[1].replace(/,/g, ''), 10) : null;

      if (label.startsWith("strike")) {
        stats.strikeAction = value;
        stats.strikeActionTime = now;
        if (rank) ranks.strike = rank;
      }
      if (label.startsWith("defense")) {
        stats.defensiveAction = value;
        stats.defensiveActionTime = now;
        if (rank) ranks.defense = rank;
      }
      if (label.startsWith("spy")) {
        stats.spyRating = value;
        stats.spyRatingTime = now;
        if (rank) ranks.spy = rank;
      }
      if (label.startsWith("sentry")) {
        stats.sentryRating = value;
        stats.sentryRatingTime = now;
        if (rank) ranks.sentry = rank;
      }
      if (label.startsWith("poison")) {
        stats.poisonRating = value;
        stats.poisonRatingTime = now;
        if (rank) ranks.poison = rank;
      }
      if (label.startsWith("antidote")) {
        stats.antidoteRating = value;
        stats.antidoteRatingTime = now;
        if (rank) ranks.antidote = rank;
      }
      if (label.startsWith("theft")) {
        stats.theftRating = value;
        stats.theftRatingTime = now;
        if (rank) ranks.theft = rank;
      }
      if (label.startsWith("vigilance")) {
        stats.vigilanceRating = value;
        stats.vigilanceRatingTime = now;
        if (rank) ranks.vigilance = rank;
      }
    });

    // Store ranks separately: your stat ranks
    stats._realRanks = ranks;

    return stats;
  }

  // ==================== STATS PAGE COLLECTOR ====================

  async function collectFromStatsPage() {
    // Get player ID from URL
    const playerId = new URLSearchParams(location.search).get('id');
    if (!playerId || !/^\d+$/.test(playerId)) {
      debugLog("⚠️ Stats page: No valid player ID in URL");
      return;
    }

    // Check for deleted/vacation player error
    const bodyText = document.body.textContent;
    if (bodyText.includes("Stats Page that does not exist") ||
        bodyText.includes("Invalid User ID")) {
      console.warn(`⚠️ Player ${playerId} does not exist - marking as deleted`);
      await auth.apiCall('recon', `players/${playerId}/mark-inactive`, {
        status: "deleted",
        error: "Stats page does not exist"
      });
      return;
    }

    // Find the "Shared Recon Info" table
    const tables = document.querySelectorAll('table.table_lines');
    let sharedReconTable = null;

    for (const table of tables) {
      const header = table.querySelector('th');
      if (header && header.textContent.includes('Shared Recon Info')) {
        sharedReconTable = table;
        break;
      }
    }

    // No shared recon on this player is not a reason to leave: the Information
    // table below still tells us their race, rank and alliance.
    if (!sharedReconTable) debugLog("ℹ️ Stats page: no Shared Recon Info table — collecting Information table only");

    const stats = {};

    // Stat name mapping (exact match -> field name)
    const statMapping = {
      'Strike Action': 'strikeAction',
      'Defensive Action': 'defensiveAction',
      'Spy Rating': 'spyRating',
      'Sentry Rating': 'sentryRating',
      'Poison Rating': 'poisonRating',
      'Antidote Rating': 'antidoteRating',
      'Theft Rating': 'theftRating',
      'Vigilance Rating': 'vigilanceRating'
    };

    // Parse timestamp from page (format: "2026-01-24 01:57:14")
    // KoC server time: convertKoCServerTimeToUTC handles UTC and the older US Eastern dates
    // May also be "time ago" format if table was already enhanced - fall back to current time
    function parseTimestamp(text) {
      if (!text) return null;
      const match = text.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
      if (match) {
        // Convert KoC server time to UTC using the shared function
        return convertKoCServerTimeToUTC(match[1]);
      }
      // If it's "time ago" format or unparseable, return null (caller will use current time)
      return null;
    }

    const now = getKoCServerTimeUTC();

    // The Information table is on this same page and carries Race and Rank.
    // Reading it here refreshes race and rank on every stats-page visit,
    // without needing a full recon.
    const info = readStatsInfoTable();
    if (info.race) { stats.race = info.race; stats.raceTime = now; }
    if (info.rank) { stats.rank = info.rank; stats.rankTime = now; }
    // Alt Watch: commander chain, signup time, previous-era rank
    let infoRead = false;
    for (const k of ['commanderId', 'commanderName', 'supremeCommanderId', 'supremeCommanderName', 'signupAt', 'previousEraRank']) {
      if (info[k] !== undefined && info[k] !== null) { stats[k] = info[k]; infoRead = true; }
    }
    if (infoRead) stats.infoSeenAt = now;

    if (sharedReconTable) sharedReconTable.querySelectorAll("tr").forEach(row => {
      const cells = row.querySelectorAll("td");
      if (cells.length < 3) return;

      // Column 0: Stat label, Column 1: Value, Column 2: Timestamp
      const label = cells[0].innerText.trim();
      const valueText = cells[1].innerText.trim();
      const timestampText = cells[2].innerText.trim();

      // Skip ??? or ?? values - we don't want to overwrite real data with unknowns
      // But 0 is a valid value (e.g., poison/antidote/theft/vigilance can be 0 or low)
      if (valueText === '???' || valueText === '??' || valueText === '') return;

      // Find matching stat
      const fieldName = statMapping[label];
      if (fieldName) {
        // Parse numeric value (remove commas)
        const value = parseInt(valueText.replace(/,/g, ''), 10);
        if (!isNaN(value)) {
          stats[fieldName] = value;
          // Use the timestamp from the page (when recon was done)
          // Fall back to current time if timestamp is in "time ago" format
          const timestamp = parseTimestamp(timestampText);
          stats[`${fieldName}Time`] = timestamp || now;
        }
      }
    });

    // Count collected fields (exclude time fields)
    const fields = Object.keys(stats).filter(key => !key.endsWith('Time'));
    const statCount = fields.filter(key => key !== 'race' && key !== 'rank').length;

    if (!fields.length) {
      debugLog(`ℹ️ Stats page: nothing to collect for player ${playerId} (all ??? and no Information table)`);
      return;
    }

    // Save to localStorage and send to API
    updatePlayerInfo(playerId, stats, 'recon');
    debugLog(`📊 Stats page collected ${statCount}/8 stats for player ${playerId}`, {
      race: stats.race || null, rank: stats.rank || null
    });
  }

  /**
   * Read the Information table that KoC renders on stats.php:
   *
   *   Name: … | Alliance: … | Race: Dwarves | Nobody tosses a Dwarf! | Rank: 121
   *
   * Only race and rank are taken. Name and alliance are deliberately left
   * alone — those have their own trusted collectors, and a bad scrape of the
   * name field would overwrite the roster's name.
   */
  function readStatsInfoTable() {
    const out = {};
    const table = getTableByHeader("Information");
    if (!table) return out;
    for (const row of table.querySelectorAll("tr")) {
      const cells = row.querySelectorAll("td");
      if (cells.length < 2) continue;
      const label = (cells[0].innerText || '').trim().toLowerCase();
      const value = (cells[1].innerText || '').trim();
      if (!value) continue;
      // "Dwarves | Nobody tosses a Dwarf!" — keep the race, drop the flavour text
      if (label === 'race:') {
        const race = value.split('|')[0].trim();
        if (race) out.race = race;
      } else if (label === 'rank:') {
        // "Rank:" exactly — never "Previous Era Rank:" or "Highest Rank:".
        // Digits only: KoC comma-formats ranks over 999 and parseInt("1,039")
        // is 1.
        const digits = value.replace(/[^0-9]/g, '');
        if (digits) out.rank = digits;
      } else if (label === 'commander:' || /^supreme commander:?$/.test(label)) {
        // Alt Watch: a stats.php?id= link, or "None". "none" is
        // sent for None because empty values are never sent.
        const pre = label === 'commander:' ? 'commander' : 'supremeCommander';
        const link = cells[1].querySelector("a[href*='stats.php?id=']");
        const cid = link && (link.getAttribute('href') || '').match(/id=(\d+)/);
        if (cid) {
          out[pre + 'Id'] = cid[1];
          out[pre + 'Name'] = (link.textContent || '').trim();
        } else if (/^none$/i.test(value)) {
          out[pre + 'Id'] = 'none';
          out[pre + 'Name'] = 'none';
        }
      } else if (label === 'signup time:') {
        // The account's creation, shown on TODAY's server clock (UTC) even for
        // old accounts, so it is read as UTC directly (convertKoCServerTimeToUTC
        // would add 4-5h to dates before 3 Nov 2026)
        const m = value.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
        if (m) out.signupAt = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])).toISOString();
      } else if (label.startsWith('previous era rank:')) {
        // "Previous Era Rank: 150" sits in the label cell; its partner cell is Highest Rank
        const digits = label.slice('previous era rank:'.length).replace(/[^0-9]/g, '');
        if (digits) out.previousEraRank = parseInt(digits, 10);
      }
    }
    // The Supreme Commander row only shows when there is one
    if (out.commanderId && out.commanderId !== 'none' && out.supremeCommanderId === undefined) {
      out.supremeCommanderId = 'none';
      out.supremeCommanderName = 'none';
    }
    return out;
  }

  // ==================== BASE PAGE COLLECTOR ====================

  function collectFromBasePage() {
    // Your id and name come from the game's own User Info table on this page.
    // A name saved with an older login is never preferred over it.
    let myId = SafeStorage.get("KoC_MyId", null);
    let myName = SafeStorage.get("KoC_MyName", null);
    const nativeIdentity = findOwnIdentityOnPage();
    if (nativeIdentity) {
      myId = nativeIdentity.id;
      myName = nativeIdentity.name;
      SafeStorage.set("KoC_MyId", myId);
      SafeStorage.set("KoC_MyName", myName);
    }
    if (!myId) return;

    // Projected Income (gold per turn)
    let projectedIncome;
    for (const tr of document.querySelectorAll("tr")) {
      const txt = tr.innerText.trim();
      if (txt.includes("Projected Income")) {
        const match = txt.match(/([\d,]+)\s+Gold/);
        if (match) projectedIncome = parseInt(match[1].replace(/,/g, ""), 10);
      }
    }

    // Military Effectiveness ratings and your rank in each stat
    const stats = collectMilitaryStats();
    const realRanks = stats._realRanks || {};
    delete stats._realRanks;
    const now = getKoCServerTimeUTC();

    // Kept on this device for the sidebar calculator (projected income) and
    // the Stat Reshuffler (race).
    const map = getNameMap();
    map[myId] = { ...map[myId], ...sanitizePlayerData({ name: myName, projectedIncome, ...stats, lastSeen: now }) };
    saveNameMap(map);

    // Shared under "Your Command Centre stats". Not awaited: nothing waits on it.
    auth.apiCall("own-stats", "players", { id: myId, name: myName, projectedIncome, lastSeen: now });
    if (Object.keys(realRanks).length > 0) {
      auth.apiCall("own-stats", `rankings/real-ranks/${myId}`, { ranks: realRanks });
    }
  }

  // ==================== REWARDS PAGE COLLECTOR (RECONS) ====================

  // POST our current/max recon count to the API so alliance members can see it.
  // current may run past max: the game keeps counting once the goal is done.
  // No-ops cleanly if not logged in. Errors are swallowed by the caller.
  // missions: your own "Recon Missions" count, or null when the page
  // had no such row — the server then keeps the last one it stored.
  async function publishReconCount(current, max, completed, claimed, missions) {
    const token = await auth.getToken();
    if (!token) return;
    const resp = await netFetch('recon', `${API_URL}/player-recons`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
        "X-Script-Name": SCRIPT_NAME,
        "X-Script-Version": SCRIPT_VERSION,
        "X-KoC-Clock": "utc" // KoC times in this request are UTC
      },
      body: JSON.stringify({ current, max, completed, claimed, missions })
    });
    if (!resp) return;   // switched off
    if (resp.status === 404) {
      // The roster has no player for the id this login carries (an era reset
      // drops every player; a login made before it, or for another account,
      // keeps that id for up to 12 h). The count never lands and the Recons
      // column keeps the last one that did.
      console.warn(`[DataCentre] Your Recons count (${current}/${max}) was not shared: the roster does not know the player this Data Centre login is for. Log out and back in from the sidebar.`);
    }
    if (!resp.ok) {
      throw new Error(`publishReconCount HTTP ${resp.status}`);
    }
  }

  // The "Unsuccessful Recons" /1000 goal as the Rewards page draws it, or null.
  // Each goal is a <td>: "Unsuccessful Recons<br><font color=goldenrod>N/1000</font>"
  // (the /100 and /1000 goals share one <tr>), then a cell with its button.
  // The game keeps counting past the goal and marks it done:
  //   …<font …>1278/1000</font> &#9989; Completed</td> … class="reward_claimed" value="CLAIMED"
  // LOCKED (reward_notel) = not reached, CLAIM = reached but not claimed.
  // `label` picks the row: Unsuccessful Recons (Actions against you) by
  // default, or /Recon Missions/ (Your Actions) — same markup, same states.
  function readReconReward(doc = document, label = /Unsuccessful Recons/i) {
    for (const cell of doc.querySelectorAll("td")) {
      // The goal's own cell only, not a layout cell wrapping the whole page
      if (cell.querySelector("td")) continue;
      if (!label.test(cell.textContent)) continue;
      const count = (cell.querySelector("font") || cell).textContent;
      const m = count.replace(/,/g, "").match(/(\d+)\s*\/\s*(\d+)/);
      if (!m) continue;
      const current = parseInt(m[1], 10);
      const max = parseInt(m[2], 10);
      if (max !== 1000) continue; // only the /1000 goal (skip /100)

      // The button follows in the same row: the next cell holding an input
      let button = null;
      for (let c = cell.nextElementSibling; c && !button; c = c.nextElementSibling) {
        button = c.querySelector("input[name$='_bonus']");
      }
      const state = button ? String(button.value || "").trim().toUpperCase() : "";
      const claimed = state === "CLAIMED" || !!(button && button.classList.contains("reward_claimed"));
      const completed = current >= max || claimed || state === "CLAIM" || cell.textContent.includes("✅");
      return { current, max, completed, claimed };
    }
    return null;
  }

  function collectFromRewardsPage() {
    const reward = readReconReward();
    if (!reward) return;
    const { current, max, completed, claimed } = reward;
    // Your own Recon Missions count (Your Actions row). It keeps climbing past
    // its goal, so the Recons column shows it once your 1,000 above is done.
    const missionsRow = readReconReward(document, /Recon Missions/i);
    const missions = missionsRow ? missionsRow.current : null;
    const myId = SafeStorage.get("KoC_MyId", null);
    const myName = SafeStorage.get("KoC_MyName", null);
    if (!myId) return;

    // Kept once done too, so the panel's offline fallback shows ✅ Done
    const reconData = {
      id: myId,
      name: myName,
      reconsRemaining: completed ? 0 : Math.max(0, max - current),
      current,
      max,
      completed,
      claimed,
      missions,
      lastUpdate: getKoCServerTimeUTC()
    };
    SafeStorage.set(`reconTrack_${myId}`, JSON.stringify(reconData));
    debugLog(completed ? "✅ Recons goal done:" : "📊 Recons to clear captured:", reconData);

    // Publish to API for alliance-wide visibility (best-effort, non-blocking)
    publishReconCount(current, max, completed, claimed, missions).catch(err =>
      debugLog("⚠️ Recon publish failed (ignored):", err)
    );
  }

  // ==================== OWN-ACCOUNT TRACKING ====================
  // The member's OWN account as their own pages show it — the sidebar
  // balances on any page, the tables the game drew on Base / Armory /
  // Upgrades / Safe / Training / Trade / Rewards / Conquest / Game Logs, and
  // each conquest result. Only the page in front of the member is read:
  // nothing is fetched or clicked, and the page is left exactly as drawn.
  // The War List and Farm List never get here (READ_ONLY_PAGE).

  // Page file → snapshot key. Any other page sends the sidebar alone.
  const OWN_TRACK_PAGES = {
    "base.php": "base", "armory.php": "armory", "upgrades.php": "upgrades", "safe.php": "safe",
    "training.php": "training", "trade.php": "trade", "rewards.php": "rewards", "conquestv2.php": "conquest",
    // Game Logs: daily login bonus, vault tax, purchases, repairs, safe, hostages,
    // poison, weapons lost to sabs and thefts — all your own
    "logs.php": "logs"
  };
  // Tables left out, by the header of the table or of any table around it:
  // other players' numbers (Officers lists their army; Recent Attacks On You
  // is the attack log's), logins, notices, settings, the ticking era
  // countdown, and price lists that are the same for everyone (the Armory's
  // buy lists are dropped by their header row below).
  const OWN_TRACK_SKIP = /^(officers|previous logins|notice from commander|(style |armory )?preferences|armory collapsing|safe upgrade list|recent attacks on you|beta feedback|era \d+ ends in)/i;
  const OWN_TRACK_PAGE_GAP_MS = 5 * 60 * 1000;       // one snapshot per page per 5 min
  const OWN_TRACK_SIDEBAR_GAP_MS = 15 * 60 * 1000;   // sidebar-only pages: per 15 min
  const OWN_TRACK_UNCHANGED_MS = 6 * 60 * 60 * 1000; // an unchanged page is resent after 6 h
  const OWN_TRACK_LAST_KEY = "KoC_OwnTrackLast";
  const CONQUEST_QUEUE_KEY = "KoC_ConquestQueue";

  function ownTrackPageKey(path = location.pathname) {
    return OWN_TRACK_PAGES[(path.split("/").pop() || "").toLowerCase()] || null;
  }

  // An element's text as the member sees it: textContent, minus the inline
  // scripts the sidebar carries ("checksize();" ran into Recent Logs) and
  // hidden page plumbing (Base hides a 32-hex token in a display:none span;
  // a collapsed table row is real data and stays). Given a table, only the
  // text that belongs to that table itself: not a table nested in it, not
  // the sidebar, not anything this script drew.
  const OWN_TRACK_HIDDEN = 'script, style, noscript, [hidden], span[style*="display:none"], span[style*="display: none"], div[style*="display:none"], div[style*="display: none"]';
  function ownTrackText(el, table = null) {
    let s = "";
    const walker = (el.ownerDocument || document).createTreeWalker(el, 4 /* NodeFilter.SHOW_TEXT */);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const p = n.parentElement;
      if (p && p.closest(OWN_TRACK_HIDDEN)) continue;
      if (table && p && (p.closest("table") !== table || p.closest("td.menu_cell") || isInjectedContent(p))) continue;
      s += n.nodeValue;
    }
    return s.replace(/\s+/g, " ").trim();
  }

  // The sidebar's balances as printed ("2,560M" stays "2,560M") plus the
  // numbers they mean, the Recent Logs line, and the era countdown: its text
  // and the exact end the game counts to (data-end, unix seconds).
  function readOwnSidebar(doc = document) {
    const side = doc.querySelector("td.menu_cell");
    if (!side) return null;
    const text = ownTrackText(side);
    const out = {};
    const fields = { gold: "Gold", safe: "Safe", vault: "Vault", experience: "Experience", experienceBank: "Experience Bank", turns: "Turns", rank: "Rank" };
    for (const [key, label] of Object.entries(fields)) {
      const m = text.match(new RegExp(`(?:^|\\s)${label}:\\s*(-?[\\d,.]+\\s*[KMBT]?)(?![\\w])`));
      if (!m) continue;
      out[key] = m[1].trim();
      const n = parseKocNumber(m[1]);
      if (n !== null) out[key + "N"] = n;
    }
    const logs = text.match(/Recent Logs:\s*(.*?)\s*(?:Era \d+ ends in|$)/);
    if (logs && logs[1]) out.recentLogs = logs[1].slice(0, 600);
    const countdown = doc.querySelector("[data-age-countdown]");
    let eraLine = countdown ? ownTrackText(countdown) : (text.match(/Era \d+ ends in[^.]*\./) || [""])[0];
    // A countdown that does not name its era ("82d 23h 59m") still carries data-label="Era N"
    const label = countdown && countdown.getAttribute("data-label");
    if (eraLine && label && !/\bEra \d+/.test(eraLine)) eraLine = `${label}: ${eraLine}`;
    if (eraLine) out.eraText = eraLine.slice(0, 200);
    const end = countdown && parseInt(countdown.getAttribute("data-end"), 10);
    if (end) out.eraEnd = end;
    return Object.keys(out).length ? out : null;
  }

  // The page's own tables as rows of cell texts, by header. Every table gives
  // only its own text (ownTrackText with the table), so a layout table does
  // not repeat the tables inside it and a row with a form table nested in a
  // cell (the Armory inventory's Repair / Scrap / Sell) keeps its own cells.
  // Nothing from the sidebar or from anything this script drew. A table's
  // header is its own first <th> (minus the "+" of a collapsible section);
  // the title of a header-only table drawn just before it (Base draws
  // "Officers" that way, its rows in the next table) and the headers of the
  // tables around it count for the skip list too.
  function readOwnTables(doc = document) {
    const clean = (th) => ownTrackText(th).replace(/^[^A-Za-z0-9]+/, "").slice(0, 160);
    const ownHeader = (table) => {
      const th = [...table.querySelectorAll("th")].find(h => h.closest("table") === table);
      return th ? clean(th) : "";
    };
    const titleBefore = (table) => {
      let p = table.previousElementSibling;
      while (p && /^(BR|P|SCRIPT)$/.test(p.tagName)) p = p.previousElementSibling;
      const only = p && p.tagName === "TABLE" && p.rows.length === 1 && p.rows[0].cells.length === 1 ? p.rows[0].cells[0] : null;
      return only && only.tagName === "TH" ? clean(only) : "";
    };
    const out = [];
    for (const table of doc.querySelectorAll("table")) {
      if (table.closest("td.menu_cell") || isInjectedContent(table)) continue;
      const heads = [ownHeader(table), titleBefore(table)];
      for (let t = table.parentElement && table.parentElement.closest("table"); t; t = t.parentElement ? t.parentElement.closest("table") : null) heads.push(ownHeader(t));
      if (heads.some(h => OWN_TRACK_SKIP.test(h))) continue;
      const rows = [];
      let skipping = false; // a section inside the table (Safe's "SAFE Upgrade List")
      for (const tr of table.rows) {
        if (tr.cells.length === 1 && tr.cells[0].tagName === "TH") skipping = OWN_TRACK_SKIP.test(clean(tr.cells[0]));
        if (skipping) continue;
        const cells = [...tr.cells].slice(0, 24).map(c => ownTrackText(c, table).slice(0, 300))
          .map(c => (/^[0-9a-f]{24,}$/i.test(c) ? "" : c)); // a token, never a reading
        if (cells.some(Boolean)) rows.push(cells);
        if (rows.length >= 250) break;
      }
      if (!rows.length) continue;
      // An Armory buy list (Strength | Price | Buy | Max Buy) — not the merc market
      if (rows.some(r => r.includes("Max Buy") && r.includes("Strength") && r.includes("Price"))) continue;
      out.push({ h: heads.find(Boolean) || "", rows });
      if (out.length >= 80) break;
    }
    return out;
  }

  // A short fingerprint, so an unchanged page is not sent again.
  function ownTrackDigest(value) {
    const s = JSON.stringify(value);
    let h = 5381;
    for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
    return h.toString(36) + "." + s.length.toString(36);
  }

  function ownTrackShouldSend(key, digest, gapMs) {
    const last = (SafeStorage.get(OWN_TRACK_LAST_KEY, {}) || {})[key];
    if (!last) return true;
    const age = Date.now() - last.t;
    if (last.d === digest && age < OWN_TRACK_UNCHANGED_MS) return false;
    return age >= gapMs;
  }

  function ownTrackMarkSent(key, digest) {
    const last = SafeStorage.get(OWN_TRACK_LAST_KEY, {}) || {};
    last[key] = { d: digest, t: Date.now() };
    SafeStorage.set(OWN_TRACK_LAST_KEY, last);
  }

  // The payload for this page, read now — before any other step draws on it.
  function readOwnSnapshot(doc = document, path = location.pathname) {
    const page = ownTrackPageKey(path) || "sidebar";
    const sidebar = readOwnSidebar(doc);
    const tables = page === "sidebar" ? [] : readOwnTables(doc);
    if (!sidebar && !tables.length) return null;
    // The countdown ticks and Recent Logs may age; the balances and tables decide "changed".
    const numbers = sidebar ? Object.fromEntries(Object.entries(sidebar).filter(([k]) => k.endsWith("N"))) : null;
    return { page, at: PAGE_KOC_TIME, sidebar, tables, digest: ownTrackDigest(page === "sidebar" ? numbers : tables) };
  }

  // Reads synchronously (the first await is the token), so call it before the
  // steps that draw on the page and do not await it.
  async function sendOwnSnapshot() {
    const snap = readOwnSnapshot();
    if (!snap) return;
    const gap = snap.page === "sidebar" ? OWN_TRACK_SIDEBAR_GAP_MS : OWN_TRACK_PAGE_GAP_MS;
    if (!ownTrackShouldSend(snap.page, snap.digest, gap)) return;
    const { digest, ...body } = snap;
    const resp = await auth.apiCall("own-history", "own-tracking/snapshot", body);
    if (resp && resp.ok) ownTrackMarkSent(snap.page, digest);
    else debugLog("⚠️ Own snapshot not stored:", resp);
  }

  // conquestv2.php's summary cells (Strike, Repair Cost, Turns, Experience,
  // Exp Bank, Gold, Vault), by the game's own data-conquest-stat names.
  function readConquestCells(doc = document) {
    const out = {};
    for (const td of doc.querySelectorAll("td[data-conquest-stat]")) {
      const n = parseKocNumber(ownTrackText(td));
      if (n !== null) out[td.getAttribute("data-conquest-stat")] = n;
    }
    return out;
  }

  function queueConquestAttempt(attempt) {
    const queue = SafeStorage.get(CONQUEST_QUEUE_KEY, []) || [];
    queue.push(attempt);
    while (queue.length > 500) queue.shift();
    SafeStorage.set(CONQUEST_QUEUE_KEY, queue);
    flushConquestQueueSoon();
  }

  // One POST for a run of attempts; what the server took leaves the queue,
  // the rest waits for the next page (the server skips a key it already has).
  let conquestFlushing = false;
  async function flushConquestQueue() {
    if (conquestFlushing) return;
    const queue = SafeStorage.get(CONQUEST_QUEUE_KEY, []) || [];
    if (!queue.length) return;
    conquestFlushing = true;
    try {
      const batch = queue.slice(0, 200);
      const resp = await auth.apiCall("own-history", "own-tracking/conquest", { eraText: (readOwnSidebar() || {}).eraText || null, attempts: batch });
      if (resp && resp.ok) {
        const sent = new Set(batch.map(a => a.key));
        SafeStorage.set(CONQUEST_QUEUE_KEY, (SafeStorage.get(CONQUEST_QUEUE_KEY, []) || []).filter(a => !sent.has(a.key)));
      } else {
        debugLog("⚠️ Conquest attempts not stored yet:", resp);
      }
    } finally {
      conquestFlushing = false;
    }
  }
  const flushConquestQueueSoon = debounce(() => { flushConquestQueue(); }, 4000);

  // conquestv2.php sends each attempt itself and writes the result into
  // #conquest-result without reloading. Watch that box (the member's own
  // click filled it) and record each new result with the summary cells
  // before and after — the game's own numbers for turns and EXP per attempt.
  // Read a moment after the box changes, so the cells have caught up; a burst
  // of attempts inside that moment is one record whose turns spent say how
  // many it was. A box that adds to its old text gives only the new part.
  function watchConquestResults(doc = document) {
    const box = doc.getElementById("conquest-result");
    if (!box) return null;
    const loadedAt = Date.now();
    let before = readConquestCells(doc);
    let prevText = ownTrackText(box);
    let lastKey = null;
    const capture = () => {
      const text = ownTrackText(box);
      if (!text || text === prevText) return;
      let fresh = text;
      if (prevText && text.startsWith(prevText)) fresh = text.slice(prevText.length).trim();
      else if (prevText && text.endsWith(prevText)) fresh = text.slice(0, text.length - prevText.length).trim();
      prevText = text;
      if (!fresh) return;
      const after = readConquestCells(doc);
      const key = [PAGE_KOC_TIME || "", fresh, after.attack_turns, after.experience].join("|");
      if (key === lastKey) return;
      lastKey = key;
      const moved = Object.keys(after).some(k => after[k] !== before[k]);
      const target = doc.querySelector("#anotherconquest input[name='conquest_target']");
      queueConquestAttempt({
        at: PAGE_KOC_TIME,
        offsetMs: Date.now() - loadedAt,
        target: target ? target.value : null,
        text: fresh.slice(0, 1500),
        before,
        after: moved ? after : null, // cells that did not move say nothing
        key: ownTrackDigest(key) + "." + (Date.now() - loadedAt).toString(36)
      });
      if (moved) before = after;
    };
    const observer = new MutationObserver(debounce(capture, 1200));
    observer.observe(box, { childList: true, subtree: true, characterData: true });
    return observer;
  }

  // ==================== SWEET REVENGE STATS PANEL ====================

  async function insertTopStatsPanel() {
    const infoRow = document.querySelector("a[href='info.php']")?.closest("tr");
    if (!infoRow) return;

    // The alliance's players, only the fields the panel shows. Without an
    // answer (Read switched off, logged out, server down) the members this
    // device has seen are used.
    const fields = 'id,name,alliance,tiv,strikeAction,defensiveAction,spyRating,sentryRating,poisonRating,antidoteRating,theftRating,vigilanceRating,rank,projectedIncome,projectedIncomeTime';
    let players = await auth.apiCall('read', `players?alliance=Sweet+Revenge&fields=${fields}`);
    if (!Array.isArray(players)) {
      players = Object.values(getNameMap()).filter(p => p.alliance === "Sweet Revenge");
    }

    // Format numbers
    function formatNumber(n) {
      const num = Number(n) || 0;
      if (num >= 1e12) return (num / 1e12).toFixed(2) + "T";
      if (num >= 1e9) return (num / 1e9).toFixed(2) + "B";
      if (num >= 1e6) return (num / 1e6).toFixed(2) + "M";
      return num.toLocaleString();
    }

    // Income per minute, short: 3688534 -> "3.7M/m"
    function formatIncome(n) {
      const num = Number(n) || 0;
      if (num >= 1e9) return (num / 1e9).toFixed(2) + "B/m";
      if (num >= 1e6) return (num / 1e6).toFixed(1) + "M/m";
      if (num >= 1e3) return (num / 1e3).toFixed(0) + "K/m";
      return num.toLocaleString() + "/m";
    }

    // Income box: projected gold per minute from each member's own-stats sync.
    // Values older than a day are dimmed; the tooltip gives the exact figure and age.
    function incomeRows() {
      const DAY_MS = 24 * 60 * 60 * 1000;
      return [...players]
        .filter(p => Number(p.projectedIncome) > 0)
        .sort((a, b) => Number(b.projectedIncome) - Number(a.projectedIncome))
        .map((p, i) => {
          const income = Number(p.projectedIncome);
          const t = p.projectedIncomeTime ? new Date(p.projectedIncomeTime).getTime() : NaN;
          const ageMs = Number.isFinite(t) ? Date.now() - t : NaN;
          let ageText = "age unknown";
          if (Number.isFinite(ageMs)) {
            const h = Math.max(0, Math.floor(ageMs / 3600000));
            ageText = h < 1 ? "under 1h ago" : h < 48 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
          }
          return {
            id: p.id,
            rank: i + 1,
            name: p.name || "Unknown",
            value: formatIncome(income),
            title: `${income.toLocaleString()} gold per minute (synced ${ageText})`,
            stale: !Number.isFinite(ageMs) || ageMs > DAY_MS
          };
        });
    }

    // Sort helper
    function sortedBy(field, asc = false) {
      return [...players]
        .filter(p => p[field] !== undefined && p[field] !== null)
        .sort((a, b) => {
          // Remove commas before converting to number
          const cleanA = typeof a[field] === 'string' ? a[field].replace(/,/g, '') : a[field];
          const cleanB = typeof b[field] === 'string' ? b[field].replace(/,/g, '') : b[field];
          const av = Number(cleanA) || 0;
          const bv = Number(cleanB) || 0;
          return asc ? (av - bv) : (bv - av);
        })
        .map((p, i) => ({
          id: p.id,
          rank: i + 1,
          name: p.name || "Unknown",
          value: formatNumber(p[field])
        }));
    }

    // The Recons column's value: the count, or ✅ Done once the goal is met
    // (the game keeps counting past it — 1278/1000 — so the raw count goes
    // in the tooltip). Each row is only as fresh as that member's last
    // Rewards visit that reached the server, so the tooltip gives its age and
    // a row older than a day is dimmed.
    //
    // Once the goal is done the row switches to the member's own Recon
    // Missions count — 🎯 1,278 in goldenrod, like the game draws it —
    // which keeps climbing, so the done rows read as a friendly "most recons
    // this era" table. A done member with no count yet still shows ✅ Done.
    function reconAge(updatedAt) {
      const t = Date.parse(updatedAt || "");
      const ageH = Number.isFinite(t) ? Math.max(0, (Date.now() - t) / 3600000) : null;
      const age = ageH === null ? "" : ` — updated ${ageH < 1 ? Math.round(ageH * 60) + " min" : ageH < 48 ? Math.round(ageH) + " h" : Math.round(ageH / 24) + " days"} ago`;
      return { age, stale: ageH !== null && ageH > 24 };
    }
    function reconCell(count, max, completed, claimed, updatedAt, missions, missionsUpdatedAt) {
      const { age, stale } = reconAge(updatedAt);
      if ((completed || count >= max) && Number.isInteger(missions)) {
        const m = reconAge(missionsUpdatedAt || updatedAt);
        return {
          value: `🎯 ${missions.toLocaleString("en-US")}`,
          color: "goldenrod",
          title: `Recon Missions this era${m.age.replace(" — updated", ", as of")} (unsuccessful recons goal done: ${count}/${max}, ${claimed ? "reward claimed" : "reward not claimed yet"})`,
          stale: m.stale,
          missions
        };
      }
      if (completed || count >= max) {
        return { value: "✅ Done", title: `${count}/${max} unsuccessful recons — ${claimed ? "reward claimed" : "reward not claimed yet"}${age}`, stale };
      }
      return { value: `${count}/${max}`, title: age ? `${count}/${max}${age}` : "", stale };
    }

    // Fetch alliance-wide recon counts from the API, with localStorage as fallback.
    // Returns rows in the shape expected by makeRBTable: { id, rank, name, value, rawValue }
    async function getReconTracking() {
      // 1) The alliance-wide list (the server sorts it: most remaining first, done last)
      const list = await auth.apiCall('read', `player-recons?alliance=${encodeURIComponent("Sweet Revenge")}`);
      if (Array.isArray(list)) {
        return list.map((p, i) => ({
          id: p.id,
          rank: i + 1,
          name: p.name,
          ...reconCell(p.count ?? p.current, p.max, p.completed, p.claimed, p.updatedAt, p.missions, p.missionsUpdatedAt),
          rawValue: p.remaining
        }));
      }

      // 2) Without it: this device's own capture
      const reconPlayers = [];
      for (const key of Object.keys(localStorage)) {
        if (key.startsWith("reconTrack_")) {
          try {
            const data = JSON.parse(localStorage.getItem(key));
            reconPlayers.push({
              id: data.id,
              rank: 0,
              name: data.name,
              ...reconCell(data.current, data.max, data.completed, data.claimed, data.lastUpdate, data.missions, data.lastUpdate),
              rawValue: data.reconsRemaining
            });
          } catch (err) {
            console.warn("Failed to parse recon data:", key, err);
          }
        }
      }
      // Same order as the server: still swapping first (most to go), then
      // done members by Recon Missions count, highest first
      reconPlayers.sort((a, b) => b.rawValue - a.rawValue || (b.missions ?? -1) - (a.missions ?? -1));
      reconPlayers.forEach((p, i) => { p.rank = i + 1; });
      return reconPlayers;
    }

    // Stat definitions
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
      { key: "vigilanceRating", label: "🔎 Vigilance", id: "vigilance" },
      { key: "recons", label: "🔍 Recons", id: "recons", custom: true },
      { key: "income", label: "💵 Income", id: "income", custom: true }
    ];

    // Build mini table
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
            <tr><th colspan="2" style="text-align:center; padding:4px;">${escapeHtml(def.label)}</th></tr>
          </thead>
          <tbody>
            ${rows.map(r => `
              <tr>
                <td style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:90px; padding:2px 4px; line-height:1.2;">
                  ${r.rank}. <a href="stats.php?id=${escapeHtml(r.id)}" style="color:#9cf; text-decoration:none;">${escapeHtml(r.name)}</a>
                </td>
                <td align="right" style="white-space:nowrap; padding:2px 4px; line-height:1.2;${r.color ? ` color:${r.color};` : ""}${r.stale ? " opacity:0.5;" : ""}"${r.title ? ` title="${escapeHtml(r.title)}"` : ""}>${escapeHtml(r.value)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;

      return wrap;
    }

    // Container row
    const container = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 2;
    container.appendChild(cell);

    // Header with column toggles
    const header = document.createElement("div");
    header.style.cssText = "margin-bottom:8px; color:gold; font-size:12px; font-weight:bold;";

    header.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <span>Sweet Revenge Stats</span>
      </div>
    `;

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
      const savedState = SafeStorage.get(`srStat_${def.id}`, "visible");
      checkbox.checked = savedState !== "hidden";

      label.appendChild(checkbox);
      label.appendChild(document.createTextNode(def.label));
      toggleContainer.appendChild(label);
    });

    header.appendChild(toggleContainer);

    // Two-row container
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

    // Pre-fetch the recon rows once (forEach callback below is sync).
    // getReconTracking() hits the API; we await it here so the table can render
    // with alliance-wide data in the same pass.
    const reconRows = await getReconTracking();

    // Generate all tables
    const allTables = [];
    statDefs.forEach(def => {
      // Custom data sources for recons and income
      const rows = def.key === "recons" ? reconRows
        : def.key === "income" ? incomeRows()
        : sortedBy(def.key, def.asc);

      const table = makeRBTable(def, rows);
      table.dataset.statId = def.id;

      // Set initial visibility
      const savedState = SafeStorage.get(`srStat_${def.id}`, "visible");
      if (savedState === "hidden") {
        table.style.display = "none";
      }

      allTables.push(table);
    });

    // Redistribute tables between rows
    function redistributeTables() {
      row1.innerHTML = "";
      row2.innerHTML = "";

      const visibleTables = allTables.filter(t => t.style.display !== "none");
      const midpoint = Math.ceil(visibleTables.length / 2);

      visibleTables.forEach((table, i) => {
        if (i < midpoint) {
          row1.appendChild(table);
        } else {
          row2.appendChild(table);
        }
      });

      row2.style.display = visibleTables.length <= midpoint ? "none" : "flex";
    }

    redistributeTables();

    // Add toggle event listeners
    statDefs.forEach(def => {
      const checkbox = toggleContainer.querySelector(`#sr-toggle-${def.id}`);
      checkbox.addEventListener("change", e => {
        const table = allTables.find(t => t.dataset.statId === def.id);
        if (e.target.checked) {
          table.style.display = "block";
          SafeStorage.set(`srStat_${def.id}`, "visible");
        } else {
          table.style.display = "none";
          SafeStorage.set(`srStat_${def.id}`, "hidden");
        }
        redistributeTables();
      });
    });

    // Build cell
    cell.appendChild(header);
    cell.appendChild(tablesContainer);

    infoRow.parentNode.insertBefore(container, infoRow.nextSibling);
  }

  // ==================== RANK-UP COST DISPLAY ====================

  // Find the game's "Rating For Previous/Next Rank Gain" table (armory/safe/etc.)
  function findRankGainTable() {
    const tables = [...document.querySelectorAll('table')];
    return tables.find(table => {
      const header = table.querySelector('th');
      if (!header) return false;

      const headerText = header.textContent.trim();
      // Try multiple variations of the header text
      return headerText.includes('Rating For Previous/Next Rank Gain') ||
             headerText.includes('Rating For') ||
             headerText.includes('Previous/Next Rank') ||
             headerText.includes('Next Rank Gain');
    });
  }

  // Store rank-up costs for auto-fill functionality
  let armoryRankCosts = {
    costs: {},        // { 'attack': 1234567, 'defense': 987654, ... }
    stats: {},        // Current stat values
    efficiency: {},   // Gold-per-point efficiency values
    nextRanks: {},    // Next rank threshold for each stat
    lastCalculated: null
  };

  const RANKUP_ACTION_CAT = { Strike: 'attack', Defense: 'defense', Spy: 'spy', Sentry: 'sentry', Poison: 'poison', Antidote: 'antidote', Theft: 'theft', Vigilance: 'vigilance' };

  function rankupShort(n) {
    if (n >= 1e12) return (n / 1e12).toFixed(1) + 'T';
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return Math.round(n).toLocaleString();
  }

  // Armory: rank-up costs in the Rank Gain table, then the gold/pt panel under
  // it — each behind its own feature switch. Re-run whenever a pin or the
  // Plan-as-held toggle changes.
  function renderRankUpAndGpp() {
    const armory = gppReadArmory();
    const resolved = gppResolve(armory);
    if (featureEnabled('rank-up-costs')) displayRankUpCosts(armory.stats, gppEfficiencyMap(resolved), resolved);
    if (featureEnabled('gpp-panel')) renderGppPanel(resolved);
  }

  function displayRankUpCosts(stats, efficiency, resolved) {
    // Validate inputs
    if (!stats || Object.keys(stats).length === 0) {
      debugLog('⚠️ displayRankUpCosts: No stats provided');
      return;
    }
    efficiency = efficiency || {};
    resolved = resolved || {};
    const planHeld = gppPlanAsHeld();

    // Store stats and efficiency for auto-fill
    armoryRankCosts.stats = stats;
    armoryRankCosts.efficiency = efficiency;
    armoryRankCosts.costs = {}; // Reset costs

    // Find the rank progression table
    const rankTable = findRankGainTable();

    if (!rankTable) {
      debugLog('⚠️ displayRankUpCosts: Could not find rank progression table');
      debugLog('Available table headers:', [...document.querySelectorAll('table')].map(t => t.querySelector('th')?.textContent.trim()).filter(Boolean));
      return;
    }

    debugLog('✅ Found rank progression table');
    rankTable.querySelectorAll('.kdc-rankcost').forEach(el => el.remove()); // re-render

    // Map action names to stat keys and efficiency keys
    const actionMap = {
      'Strike': { stat: 'strikeAction', efficiency: 'goldPerAttackPoint' },
      'Defense': { stat: 'defensiveAction', efficiency: 'goldPerDefensePoint' },
      'Spy': { stat: 'spyRating', efficiency: 'goldPerSpyPoint' },
      'Sentry': { stat: 'sentryRating', efficiency: 'goldPerSentryPoint' },
      'Poison': { stat: 'poisonRating', efficiency: 'goldPerPoisonPoint' },
      'Antidote': { stat: 'antidoteRating', efficiency: 'goldPerAntidotePoint' },
      'Theft': { stat: 'theftRating', efficiency: 'goldPerTheftPoint' },
      'Vigilance': { stat: 'vigilanceRating', efficiency: 'goldPerVigilancePoint' }
    };

    // Parse current stat values
    const parseStatValue = (val) => {
      if (!val) return 0;
      return parseInt(String(val).replace(/,/g, ''), 10) || 0;
    };

    const addSpan = (cell, text, color, title) => {
      const span = document.createElement('span');
      span.className = 'kdc-rankcost';
      span.style.color = color;
      span.style.marginLeft = '8px';
      if (title) { span.style.cursor = 'help'; span.title = title; }
      span.textContent = text;
      cell.appendChild(span);
      return span;
    };

    // Unheld is often on purpose, so it reads as information, never a warning.
    const unheldText = (r) => {
      if (!r || !(r.unheldQty > 0)) return '';
      const extra = (r.mult > 0 && r.unheldStrength > 0) ? ' · +' + rankupShort(r.mult * r.unheldStrength) + ' if held' : '';
      return rankupShort(r.unheldQty) + ' unheld' + extra;
    };

    // Process each row
    const rows = rankTable.querySelectorAll('tr');
    let processedCount = 0;

    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      if (cells.length < 3) return;

      const actionText = cells[0]?.textContent.trim();
      const nextRatingText = cells[2]?.textContent.trim();

      const mapping = actionMap[actionText];
      if (!mapping) {
        debugLog(`⚠️ No mapping for action: "${actionText}"`);
        return;
      }

      const r = resolved[RANKUP_ACTION_CAT[actionText]];
      const shownStat = parseStatValue(stats[mapping.stat]);
      const heldStat = r ? gppHeldRating(r) : shownStat;
      const currentStat = planHeld ? heldStat : shownStat;
      const nextRating = parseInt(nextRatingText.replace(/,/g, ''), 10);
      const efficiencyValue = efficiency[mapping.efficiency];
      const unheld = unheldText(r);

      // Debug missing values
      if (!currentStat) {
        debugLog(`⚠️ ${actionText}: Missing current stat (${mapping.stat})`);
        return;
      }
      if (!nextRating || isNaN(nextRating)) {
        debugLog(`⚠️ ${actionText}: Missing/invalid next rating: "${nextRatingText}"`);
        return;
      }
      if (!efficiencyValue) {
        debugLog(`⚠️ ${actionText}: Missing efficiency (${mapping.efficiency})`);
        addSpan(cells[2], '(no gold/pt — pin one below)', '#8b94a7');
        if (unheld) addSpan(cells[2], unheld, '#8b94a7');
        return;
      }

      const gap = nextRating - currentStat;
      if (gap <= 0) {
        // Already past next rank — said only when it is holding that gets you there
        if (planHeld && heldStat > shownStat) addSpan(cells[2], '(✓ past it if held)', '#8b94a7');
        if (unheld) addSpan(cells[2], unheld, '#8b94a7');
        return;
      }

      const goldNeeded = gap * efficiencyValue;

      // Store cost data for auto-fill functionality
      const formFieldMap = {
        'Strike': 'attack',
        'Defense': 'defend',
        'Spy': 'spy',
        'Sentry': 'sentry',
        'Poison': 'poison',
        'Antidote': 'medicine',
        'Theft': 'theft',
        'Vigilance': 'vigilance'
      };

      const formField = formFieldMap[actionText];
      if (formField) {
        armoryRankCosts.costs[formField] = goldNeeded;
        armoryRankCosts.nextRanks[formField] = nextRating;
      }

      const goldFormatted = rankupShort(goldNeeded);

      // Calculate weapon count for Attack and Defense
      let weaponCountText = '';
      if (actionText === 'Strike' || actionText === 'Defense') {
        // Get best weapon for this category
        const bestWeaponMap = {
          'Strike': { name: 'Chariot', price: 450000, strength: 600 },
          'Defense': { name: 'Ebony Platemail', price: 450000, strength: 600 }
        };

        const weapon = bestWeaponMap[actionText];
        if (weapon) {
          const weaponCount = Math.ceil(goldNeeded / weapon.price);
          weaponCountText = ` (x${rankupShort(weaponCount)})`;
        }
      }

      // Create tooltip text
      const tooltipText = `Gold needed for next rank${planHeld ? ' (planning as if every weapon is held)' : ''}:\n` +
        `Gap: ${gap.toLocaleString()} points\n` +
        `Efficiency: ${efficiencyValue} gold/point — ${r ? gppSourceLabel(r) : 'unknown source'}\n` +
        `Cost: ${gap.toLocaleString()} × ${efficiencyValue} = ${Math.round(goldNeeded).toLocaleString()} gold`;

      // Add cost display to the cell
      const costSpan = addSpan(cells[2], `(${goldFormatted})${weaponCountText}`, '#4CAF50', tooltipText);
      costSpan.style.fontWeight = 'bold';
      if (unheld) addSpan(cells[2], unheld, '#8b94a7');
      processedCount++;
      debugLog(`✅ ${actionText}: Added cost display (${goldFormatted})`);
    });

    debugLog(`✅ displayRankUpCosts: Processed ${processedCount} rank cost displays`);
  }

  // The gold/pt panel under the Rank Gain table: each stat's figure, where it
  // came from, what is unheld, and a pin box. Collapsed to its header line
  // until opened (remembered); Plan as held stays usable from the header.
  // Display-only — pins, the toggle and open/closed are stored on this device.
  const GPP_PANEL_OPEN_KEY = 'KoC_GppPanelOpen';
  const GPP_SOURCE_SHORT = { live: 'Live', remembered: 'Remembered', paired: 'Paired', pinned: 'Pinned' };

  function renderGppPanel(resolved) {
    const rankTable = findRankGainTable();
    if (!rankTable) return;
    document.getElementById('kdc-gpp-panel')?.remove();

    const pins = SafeStorage.get(GPP_PINS_KEY, {});
    const planHeld = gppPlanAsHeld();
    const open = SafeStorage.get(GPP_PANEL_OPEN_KEY, false) === true;
    const headTh = rankTable.querySelector('th');
    const subTh = rankTable.querySelectorAll('tr')[1]?.querySelector('th');
    const fmtGpp = g => g > 0 ? String(Number(g.toPrecision(3))) : '—';
    const muted = 'color:#8b94a7;';
    const bodyRow = '<tr class="kdc-gpp-body"' + (open ? '' : ' style="display:none;"') + '>';

    // Header summary for the collapsed state: "8 Live", "6 Live · 1 Pinned · 1 none"
    const counts = {};
    for (const cat of RESHUF_CATS) {
      const s = GPP_SOURCE_SHORT[resolved[cat].source] || 'none';
      counts[s] = (counts[s] || 0) + 1;
    }
    const summary = Object.entries(counts).map(([s, n]) => n + ' ' + s).join(' · ');

    const table = document.createElement('table');
    table.id = 'kdc-gpp-panel';
    table.className = rankTable.className;
    table.style.cssText = 'width:100%;margin-top:4px;';
    let html =
      '<tr><th colspan="5" class="' + (headTh ? headTh.className : '') + '">' +
      '<span id="kdc-gpp-toggle" style="cursor:pointer;" title="Show or hide the gold per stat point table">' +
      '<span id="kdc-gpp-arrow">' + (open ? '▾' : '▸') + '</span> Gold per Stat Point ' +
      '<span style="font-weight:normal;' + muted + '">(' + summary + ')</span></span>' +
      '<label style="font-weight:normal;margin-left:10px;cursor:pointer;" title="Rank-up costs and the Optimizer start from your rating with every weapon you own held — for the end-of-era push.">' +
      '<input type="checkbox" id="kdc-gpp-held"' + (planHeld ? ' checked' : '') + ' style="vertical-align:middle;margin:0 3px 0 0;">Plan as held</label></th></tr>' +
      bodyRow + ['Action', 'Gold/pt', 'Source', 'Unheld', 'Pin gold/pt'].map(t => '<th class="' + (subTh ? subTh.className : '') + '">' + t + '</th>').join('') + '</tr>';
    for (const cat of RESHUF_CATS) {
      const r = resolved[cat];
      const label = cat === 'attack' ? 'Strike' : RESHUF_LABELS[cat];
      let unheld = '?';
      if (r.unheldQty === 0) unheld = '—';
      else if (r.unheldQty > 0) unheld = rankupShort(r.unheldQty) + ((r.mult > 0 && r.unheldStrength > 0) ? ' <span style="' + muted + '">(+' + rankupShort(r.mult * r.unheldStrength) + ' if held)</span>' : '');
      const srcColor = r.stale ? 'color:#e6b450;' : (r.source ? '' : muted);
      html += bodyRow +
        '<td>' + label + '</td>' +
        '<td align="right">' + fmtGpp(r.gpp) + '</td>' +
        '<td style="' + srcColor + '">' + escapeHtml(gppSourceLabel(r)) +
          (r.pinned && r.under && r.under.gpp > 0 ? ' <span style="' + muted + '">(' + escapeHtml(r.under.source) + ': ' + fmtGpp(r.under.gpp) + ')</span>' : '') + '</td>' +
        '<td align="right">' + unheld + '</td>' +
        '<td><input type="text" class="kdc-gpp-pin" data-cat="' + cat + '" size="7" value="' + (pins[cat] > 0 ? pins[cat] : '') + '"' +
          ' placeholder="' + (r.gpp > 0 && !r.pinned ? fmtGpp(r.gpp) : '') + '" style="width:70px;"></td>' +
        '</tr>';
    }
    html += bodyRow + '<td colspan="5" style="font-size:10px;' + muted + '">' +
      'Live = your rating ÷ the weapons the game says are held, read on every visit. A stat you keep unheld keeps its last reading (Remembered). ' +
      'Poison/Antidote and Theft/Vigilance borrow from each other only at equal skill levels (read on the Upgrades page). ' +
      'A pin wins until you clear it.' +
      (planHeld ? ' <b>Plan as held:</b> other players\' ratings are as last recorded — they may be hiding strength too.' : '') +
      '</td></tr>';
    table.innerHTML = html;
    rankTable.parentNode.insertBefore(table, rankTable.nextSibling);

    table.querySelector('#kdc-gpp-toggle').addEventListener('click', () => {
      const nowOpen = SafeStorage.get(GPP_PANEL_OPEN_KEY, false) !== true;
      SafeStorage.set(GPP_PANEL_OPEN_KEY, nowOpen);
      table.querySelectorAll('.kdc-gpp-body').forEach(tr => { tr.style.display = nowOpen ? '' : 'none'; });
      table.querySelector('#kdc-gpp-arrow').textContent = nowOpen ? '▾' : '▸';
    });
    table.querySelector('#kdc-gpp-held').addEventListener('change', e => {
      SafeStorage.set(GPP_HELD_KEY, e.target.checked);
      renderRankUpAndGpp();
    });
    table.querySelectorAll('.kdc-gpp-pin').forEach(inp => inp.addEventListener('change', () => {
      const v = parseFloat(String(inp.value).replace(/,/g, ''));
      const all = SafeStorage.get(GPP_PINS_KEY, {});
      if (v > 0 && isFinite(v)) all[inp.dataset.cat] = v; else delete all[inp.dataset.cat];
      SafeStorage.set(GPP_PINS_KEY, all);
      renderRankUpAndGpp();
    }));
  }

  // ==================== RANK NEIGHBOUR RECON LINKS ====================
  // Turns each Previous/Next rating threshold into a hyperlink to the player we
  // believe holds that rank. Candidates are matched by RATING VALUE (the
  // game's threshold is ground truth), never by the drift-prone DB rank
  // columns, so a wrong candidate rotates out on the next page load.
  // Clicking a link opens that player's stats page.

  const RANK_NEIGHBOR_ACTION_MAP = {
    'Strike': 'strikeAction',
    'Defense': 'defensiveAction',
    'Spy': 'spyRating',
    'Sentry': 'sentryRating',
    'Poison': 'poisonRating',
    'Antidote': 'antidoteRating',
    'Theft': 'theftRating',
    'Vigilance': 'vigilanceRating'
  };

  async function enhanceRankNeighborLinks() {
    const rankTable = findRankGainTable();
    if (!rankTable) return; // Page doesn't show the Previous/Next Rank Gain table

    const parseRating = (txt) => {
      const n = parseInt(String(txt || '').replace(/,/g, ''), 10);
      return Number.isFinite(n) && n > 0 ? n : null;
    };

    // Scrape the game's exact thresholds per stat row
    const thresholds = {};
    const cellsByStat = {};
    rankTable.querySelectorAll('tr').forEach(row => {
      const cells = row.querySelectorAll('td');
      if (cells.length < 3) return;

      const statKey = RANK_NEIGHBOR_ACTION_MAP[cells[0]?.textContent.trim()];
      if (!statKey) return;

      const prev = parseRating(cells[1]?.textContent);
      const next = parseRating(cells[2]?.textContent);
      if (!prev && !next) return;

      thresholds[statKey] = {};
      if (prev) thresholds[statKey].prev = prev;
      if (next) thresholds[statKey].next = next;
      cellsByStat[statKey] = cells;
    });

    if (Object.keys(thresholds).length === 0) {
      debugLog('⚠️ Rank neighbours: table found but no parseable thresholds');
      return;
    }

    const resp = await auth.apiCall('read', 'rankings/rank-neighbors', { thresholds });
    if (!resp || !resp.neighbors) {
      debugLog('⚠️ Rank neighbours: no API response');
      return;
    }

    let linked = 0;
    for (const [statKey, cells] of Object.entries(cellsByStat)) {
      const neighbor = resp.neighbors[statKey];
      if (!neighbor) continue;
      if (linkifyRankNeighborCell(cells[1], neighbor.prev, 'Previous rank')) linked++;
      if (linkifyRankNeighborCell(cells[2], neighbor.next, 'Next rank')) linked++;
    }
    debugLog(`🔗 Rank neighbours: linked ${linked} rating thresholds`);
  }

  function linkifyRankNeighborCell(cell, candidate, label) {
    if (!cell || !candidate || !candidate.playerId) return false;

    const container = cell.querySelector('font') || cell;
    // The threshold number is the first digit-bearing text node — wrap only
    // that, leaving other enhancers' additions (e.g. rank-up cost spans) alone
    const textNode = [...container.childNodes].find(
      node => node.nodeType === Node.TEXT_NODE && /\d/.test(node.textContent)
    );
    if (!textNode) return false;

    const link = document.createElement('a');
    link.href = `stats.php?id=${encodeURIComponent(candidate.playerId)}`;
    link.textContent = textNode.textContent.trim();
    // Blend in with the native table — the tooltip is the only visible hint
    link.style.color = 'inherit';
    link.style.textDecoration = 'none';

    const age = candidate.ratingTime ? reconTimeAgo(candidate.ratingTime) : 'never';
    const tooltip = [
      `${label}: ${candidate.name}`,
      `DB rating: ${Number(candidate.rating).toLocaleString()}`,
      `Last stat update: ${age}`
    ];
    if (candidate.gap) {
      tooltip.push('⚠️ Gap — nobody in DB at this rating. Recon upward!');
    } else if (candidate.staleSignal) {
      tooltip.push('🔴 DB rank and rating lookups disagree — recon me first!');
    } else if (candidate.matched) {
      tooltip.push('✅ DB rating matches the game exactly');
    }
    link.title = tooltip.join('\n');

    container.replaceChild(link, textNode);

    return true;
  }

  // ==================== ARMORY AUTO-FILL PREFERENCES ====================

  function scrapeAvailableGold() {
    const bodyText = document.body.innerText;

    let availableFunds = 0;
    let vaultGold = 0;

    // Scrape Available Funds
    const availableMatch = bodyText.match(/Available\s+Funds:\s*([\d,]+)\s+Gold/i);
    if (availableMatch) {
      availableFunds = parseInt(availableMatch[1].replace(/,/g, ''), 10);
      debugLog(`💰 Available Funds: ${availableFunds.toLocaleString()}`);
    }

    // Scrape Vault Gold
    const vaultMatch = bodyText.match(/Vault\s+Gold:\s*([\d,]+)\s+Gold/i);
    if (vaultMatch) {
      vaultGold = parseInt(vaultMatch[1].replace(/,/g, ''), 10);
      debugLog(`🏦 Vault Gold: ${vaultGold.toLocaleString()}`);
    }

    const totalGold = availableFunds + vaultGold;

    if (totalGold > 0) {
      debugLog(`💎 Total Gold (Available + Vault): ${totalGold.toLocaleString()}`);
      return totalGold;
    }

    debugLog('⚠️ Could not find available or vault gold on page');
    return 0;
  }

  function showAutoFillMessage(message, type = 'info') {
    const colors = {
      success: '#4CAF50',
      error: '#f44336',
      info: '#2196F3'
    };

    const messageDiv = document.createElement('div');
    messageDiv.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 15px 20px;
      background: ${colors[type]};
      color: white;
      border-radius: 4px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
      z-index: 10000;
      max-width: 400px;
      font-family: Arial, sans-serif;
      font-size: 14px;
      white-space: pre-line;
    `;

    messageDiv.textContent = message;
    document.body.appendChild(messageDiv);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      messageDiv.style.opacity = '0';
      messageDiv.style.transition = 'opacity 0.3s ease';
      setTimeout(() => messageDiv.remove(), 300);
    }, 5000);

    debugLog(`📢 ${type.toUpperCase()}: ${message}`);
  }

  function autoFillArmoryPreferences() {
    debugLog('🎯 Starting auto-fill for armory preferences...');

    // Add 3% buffer to ensure we actually reach the rank (accounts for calculation drift)
    const OVERSPEND_BUFFER = 1.03; // 3% extra

    // 1. Scrape available gold
    const availableGold = scrapeAvailableGold();

    if (availableGold <= 0) {
      showAutoFillMessage('❌ No gold available. Cannot auto-fill preferences.', 'error');
      return;
    }

    // 2. Validate cost data
    if (!armoryRankCosts.costs || Object.keys(armoryRankCosts.costs).length === 0) {
      showAutoFillMessage('❌ Cost data not available: turn on Rank-up cost display and reload.', 'error');
      return;
    }

    debugLog(`💰 Available gold: ${availableGold.toLocaleString()}`);
    debugLog(`📊 Rank costs (raw):`, armoryRankCosts.costs);

    // Apply overspend buffer to each stat's cost
    const statsWithCosts = Object.entries(armoryRankCosts.costs).map(([stat, cost]) => ({
      stat,
      cost: Math.ceil(cost * OVERSPEND_BUFFER), // Add 3% buffer
      rawCost: cost, // Keep original for reference
      percentage: 0
    }));

    // 4. Sort by cost (cheapest first)
    statsWithCosts.sort((a, b) => a.cost - b.cost);

    debugLog(`📈 Sorted stats by cost:`, statsWithCosts.map(s => `${s.stat}: ${s.cost.toLocaleString()}`));

    // 5. Allocate gold using cheapest-first algorithm
    let remainingGold = availableGold;
    const goldAllocations = {}; // Gold amount per stat
    const allocations = {}; // Percentage per stat (must total 100%)

    // First pass: determine gold allocation for each stat
    for (const statInfo of statsWithCosts) {
      const { stat, cost } = statInfo;

      if (remainingGold <= 0) {
        goldAllocations[stat] = 0;
        debugLog(`⏭️ ${stat}: No gold remaining, skipping`);
        continue;
      }

      if (cost <= remainingGold) {
        // Can afford full rank
        goldAllocations[stat] = cost;
        remainingGold -= cost;
        debugLog(`✅ ${stat}: Allocated ${cost.toLocaleString()} gold (remaining: ${remainingGold.toLocaleString()})`);
      } else {
        // Partial rank - allocate remaining gold
        goldAllocations[stat] = remainingGold;
        debugLog(`⚠️ ${stat}: Allocated ${remainingGold.toLocaleString()} gold (partial rank)`);
        remainingGold = 0;
      }
    }

    // Second pass: convert gold amounts to percentages (must total 100%)
    const totalGoldAllocated = Object.values(goldAllocations).reduce((sum, gold) => sum + gold, 0);

    if (totalGoldAllocated > 0) {
      for (const [stat, goldAmount] of Object.entries(goldAllocations)) {
        if (goldAmount > 0) {
          const percentage = Math.round((goldAmount / totalGoldAllocated) * 100);
          allocations[stat] = percentage;
          debugLog(`📊 ${stat}: ${goldAmount.toLocaleString()} gold = ${percentage}%`);
        } else {
          allocations[stat] = 0;
        }
      }

      // Ensure percentages add up to exactly 100% (fix rounding errors)
      const totalPercentage = Object.values(allocations).reduce((sum, pct) => sum + pct, 0);
      if (totalPercentage !== 100 && totalPercentage > 0) {
        // Find the stat with the largest allocation and adjust it
        const largestStat = Object.entries(allocations)
          .filter(([_, pct]) => pct > 0)
          .sort((a, b) => b[1] - a[1])[0];

        if (largestStat) {
          const adjustment = 100 - totalPercentage;
          allocations[largestStat[0]] += adjustment;
          debugLog(`🔧 Adjusted ${largestStat[0]} by ${adjustment}% to reach 100% total`);
        }
      }
    }

    // 6. Fill form inputs
    const formFieldNames = {
      'attack': 'prefs[attack]',
      'defend': 'prefs[defend]',
      'spy': 'prefs[spy]',
      'sentry': 'prefs[sentry]',
      'poison': 'prefs[poison]',
      'medicine': 'prefs[medicine]',
      'theft': 'prefs[theft]',
      'vigilance': 'prefs[vigilance]'
    };

    let filledCount = 0;
    const summary = [];

    for (const [stat, percentage] of Object.entries(allocations)) {
      const fieldName = formFieldNames[stat];
      if (!fieldName) {
        debugLog(`⚠️ No form field mapping for stat: ${stat}`);
        continue;
      }

      const input = document.querySelector(`input[name="${fieldName}"]`);
      if (input) {
        input.value = percentage;
        filledCount++;
        if (percentage > 0) {
          summary.push(`${stat}: ${percentage}%`);
        }
        debugLog(`✅ Filled ${fieldName} with ${percentage}%`);
      } else {
        debugLog(`⚠️ Could not find input field: ${fieldName}`);
      }
    }

    // 7. Show success message
    if (filledCount > 0) {
      const goldUsed = availableGold - remainingGold;
      const totalPct = Object.values(allocations).reduce((sum, pct) => sum + pct, 0);
      const message = `✅ Auto-filled ${filledCount} preferences (Total: ${totalPct}%)\n` +
                     `💰 Gold allocated: ${goldUsed.toLocaleString()} / ${availableGold.toLocaleString()}\n` +
                     `📊 ${summary.join(', ')}\n` +
                     `🎯 +3% buffer included to ensure rank completion`;
      showAutoFillMessage(message, 'success');
    } else {
      showAutoFillMessage('❌ Could not find any form fields to fill', 'error');
    }
  }

  // ==================== OPTIMIZER AUTO-FILL ====================

  async function autoFillArmoryWithOptimizer() {
    debugLog('🚀 Starting optimizer auto-fill...');

    // 1. Get Total Potential Gold from calculator
    const xpTradeElem = document.getElementById("xp-trade");
    const xpTradeAttacks = parseInt(xpTradeElem?.innerText || "0");
    const avgGold = SafeStorage.get("xpTool_avgGold", 0);
    const totalPotentialGold = xpTradeAttacks * avgGold;

    debugLog(`💰 Total Potential Gold: ${totalPotentialGold.toLocaleString()} (${xpTradeAttacks} attacks × ${avgGold.toLocaleString()})`);

    // Validate gold available
    if (totalPotentialGold <= 0) {
      showAutoFillMessage('❌ No gold available. Please configure XP calculator first.', 'error');
      return;
    }

    // 2. Get authentication token
    const token = await auth.getToken();
    if (!token) {
      showAutoFillMessage('❌ Please log in first. Open your Command Center and press Login.', 'error');
      return;
    }

    // 3. Get player ID
    const playerId = SafeStorage.get("KoC_MyId", null);
    if (!playerId) {
      showAutoFillMessage('❌ Player ID not found. Open your Command Center once so the script knows your id.', 'error');
      return;
    }

    // 4. Call optimizer API — with the gold/pt the armory shows (pins included),
    // and with Plan as held on, the ratings as they'd read with every weapon held
    const gppNow = gppResolve(gppReadArmory());
    const planHeld = gppPlanAsHeld();
    const gppParam = {};
    const ratingsParam = {};
    for (const cat of RESHUF_CATS) {
      const r = gppNow[cat];
      if (r.gpp > 0) gppParam[GPP_STAT_KEY[cat]] = Number(r.gpp.toPrecision(4));
      const held = gppHeldRating(r);
      if (planHeld && held > 0) ratingsParam[GPP_STAT_KEY[cat]] = held;
    }
    const apiUrl = `${API_URL}/api/roster/optimizer/${playerId}?mode=budget&value=${totalPotentialGold}` +
      `&gpp=${encodeURIComponent(JSON.stringify(gppParam))}` +
      (planHeld ? `&ratings=${encodeURIComponent(JSON.stringify(ratingsParam))}` : '');
    debugLog(`🌐 Calling optimizer API: ${apiUrl}`);

    try {
      const resp = await netFetch('read', apiUrl, {
        headers: {
          "Authorization": "Bearer " + token,
          "X-Script-Name": SCRIPT_NAME,
          "X-Script-Version": SCRIPT_VERSION,
          "X-KoC-Clock": "utc" // KoC times in this request are UTC
        }
      });

      if (!resp) throw new Error("Reading from the Sweet Revenge server is switched off in ⚙ Data Centre.");
      if (!resp.ok) {
        if (resp.status === 401) {
          throw new Error("Authentication failed. Please log in again.");
        }
        if (resp.status === 403) {
          throw new Error("Access denied. This may not be your linked player.");
        }
        if (resp.status === 404) {
          throw new Error("Player not found in database.");
        }
        if (resp.status === 500) {
          throw new Error("Server error. Please try again later.");
        }
        throw new Error(`API error: ${resp.status}`);
      }

      const result = await resp.json();
      debugLog('📊 Optimizer API response:', result);

      // Validate response
      if (!result || !result.allocation || !result.summary) {
        throw new Error("Invalid response from optimizer");
      }

      if (Object.keys(result.allocation).length === 0) {
        throw new Error("Optimizer returned no allocations");
      }

      // 5. Map stat names and extract gold amounts
      const apiToFormFieldMap = {
        'strikeAction': 'attack',
        'defensiveAction': 'defend',
        'spyRating': 'spy',
        'sentryRating': 'sentry',
        'poisonRating': 'poison',
        'antidoteRating': 'medicine',
        'theftRating': 'theft',
        'vigilanceRating': 'vigilance'
      };

      const statLabels = {
        'attack': 'Strike',
        'defend': 'Defense',
        'spy': 'Spy',
        'sentry': 'Sentry',
        'poison': 'Poison',
        'medicine': 'Antidote',
        'theft': 'Theft',
        'vigilance': 'Vigilance'
      };

      // Extract gold amounts for each stat
      const goldAllocations = {};
      const rankImprovements = [];
      let totalGoldSpent = 0;

      for (const [apiStat, data] of Object.entries(result.allocation)) {
        const formField = apiToFormFieldMap[apiStat];
        if (formField && data.goldSpent > 0) {
          goldAllocations[formField] = data.goldSpent;
          totalGoldSpent += data.goldSpent;

          // Collect rank improvements
          if (data.ranksGained > 0) {
            const label = statLabels[formField];
            rankImprovements.push(`  • ${label}: #${data.currentRank} → #${data.newRank} (+${data.ranksGained})`);
          }
        }
      }

      debugLog(`💎 Gold allocations:`, goldAllocations);
      debugLog(`📈 Total gold to spend: ${totalGoldSpent.toLocaleString()}`);

      // 6. Convert gold amounts to percentages
      const allocations = {};
      for (const [stat, goldAmount] of Object.entries(goldAllocations)) {
        if (goldAmount > 0) {
          const percentage = Math.round((goldAmount / totalGoldSpent) * 100);
          allocations[stat] = percentage;
          debugLog(`📊 ${stat}: ${goldAmount.toLocaleString()} gold = ${percentage}%`);
        } else {
          allocations[stat] = 0;
        }
      }

      // Ensure percentages add up to exactly 100% (fix rounding errors)
      const totalPercentage = Object.values(allocations).reduce((sum, pct) => sum + pct, 0);
      if (totalPercentage !== 100) {
        const diff = 100 - totalPercentage;
        // Adjust the largest allocation
        const largestStat = Object.keys(allocations).reduce((a, b) =>
          allocations[a] > allocations[b] ? a : b
        );
        allocations[largestStat] += diff;
        debugLog(`🔧 Adjusted ${largestStat} by ${diff}% to ensure total = 100%`);
      }

      // 7. Fill form fields
      const formFieldNames = ['attack', 'defend', 'spy', 'sentry', 'poison', 'medicine', 'theft', 'vigilance'];
      let filledCount = 0;
      const summary = [];

      for (const stat of formFieldNames) {
        const fieldName = `prefs[${stat}]`;
        const input = document.querySelector(`input[name="${fieldName}"]`);

        if (input) {
          const value = allocations[stat] || 0;
          input.value = value;
          filledCount++;

          if (value > 0) {
            summary.push(`${stat}: ${value}%`);
          }

          debugLog(`✅ Set ${fieldName} = ${value}%`);
        } else {
          debugLog(`⚠️ Could not find input field: ${fieldName}`);
        }
      }

      // 8. Format gold display
      const formatGold = (gold) => {
        if (gold >= 1e9) return (gold / 1e9).toFixed(1) + 'B';
        if (gold >= 1e6) return (gold / 1e6).toFixed(1) + 'M';
        if (gold >= 1e3) return (gold / 1e3).toFixed(1) + 'K';
        return gold.toFixed(0);
      };

      // 9. Display success message with rank improvements
      const currentRank = result.summary.currentTotalRankPoints || result.player?.currentTotalRankPoints || 0;
      const newRank = result.summary.newTotalRankPoints;
      const improvement = result.summary.totalRanksGained;

      let message = `✅ Optimizer Auto-Fill Complete!\n`;
      message += `📈 Total Rank Points: ${currentRank} → ${newRank} (-${improvement} ranks)\n`;

      if (rankImprovements.length > 0) {
        message += `🎯 Stat Rank Improvements:\n`;
        message += rankImprovements.join('\n') + '\n';
      }

      message += `💰 Gold allocated: ${formatGold(totalGoldSpent)} / ${formatGold(totalPotentialGold)}\n`;
      message += `📊 ${summary.join(', ')}`;
      if (planHeld) message += `\n🛡️ Planned as held — from your ratings with every weapon held`;

      showAutoFillMessage(message, 'success');

    } catch (error) {
      debugLog('❌ Optimizer error:', error);
      showAutoFillMessage(`❌ Optimizer Error: ${error.message}`, 'error');
      throw error; // Re-throw for button handler
    }
  }

  // ==================== NATIVE ARMORY PREFERENCES SLIDER UI ====================
  // Replaces KoC's percentage number-inputs with an auto-balancing slider allocator that
  // INHERITS the player's active theme: transparent backgrounds, inherited text, the accent
  // colour SAMPLED from a page link, sliders themed via accent-color, and presets as native
  // <input type=button> (so they pick up the theme's button styling). It writes into the real
  // prefs[...] inputs (kept on the page, hidden); the genuine "Update Preferences" button saves.
  // Fail-safe: native rows are only hidden AFTER the UI builds; any error leaves the form intact.
  function enhanceArmoryPrefsUI(){
    try{
      var attackInp=document.querySelector('input[name="prefs[attack]"]');
      if(!attackInp){ debugLog('prefs UI: prefs form not found'); return; }
      var form=attackInp.closest('form'); if(!form) return;
      if(form.querySelector('.kdc-prefui')) return; // already enhanced
      var firstRow=attackInp.closest('tr'); if(!firstRow||!firstRow.parentNode) return;
      var nCells=firstRow.children.length||3;

      var PK=[['attack','attweapon','Attack'],['defend','defweapon','Defense'],['spy','spyweapon','Spy'],['sentry','sentryweapon','Sentry'],['poison','poisonweapon','Poison'],['medicine','medicineweapon','Antidote'],['theft','theftweapon','Theft'],['vigilance','vigilanceweapon','Vigilance']];
      var pinp=function(k){ return document.querySelector('input[name="prefs['+k+']"]'); };
      var psel=function(s){ return document.querySelector('select[name="prefs['+s+']"]'); };

      // sample the active theme so the UI matches whatever theme the player has set
      var lnk=document.querySelector('td a[href]')||document.querySelector('a[href]');
      var accent=(lnk&&getComputedStyle(lnk).color)||'#3a7fd0';
      var line='rgba(140,160,190,0.28)';
      var nbtn=document.querySelector('input[type="submit"]')||document.querySelector('input[type="button"]')||document.querySelector('button');
      var bcss=''; if(nbtn){ var bcs=getComputedStyle(nbtn); ['background-color','background-image','color','border-width','border-style','border-color','border-radius','padding','font-family','font-size','font-weight','text-shadow'].forEach(function(pp){ var v=bcs.getPropertyValue(pp); if(v) bcss+=pp+':'+v+';'; }); } // clone a native button's look so presets match the theme exactly

      var st=PK.map(function(p){ var i=pinp(p[0]); return {k:p[0], pct:i?(parseInt(i.value,10)||0):0, locked:false}; });
      var auto=true, sliders=[], labels=[], lockBtns=[], barEl, statEl, toastEl;
      var sum=function(){ var t=0; st.forEach(function(s){ t+=s.pct; }); return t; };
      var writeForm=function(){ st.forEach(function(s){ var i=pinp(s.k); if(i) i.value=s.pct; }); };
      var readState=function(){ st.forEach(function(s){ var i=pinp(s.k); s.pct=i?(parseInt(i.value,10)||0):0; }); };
      var reduceOthers=function(idx,over){ var pool=[]; st.forEach(function(s,j){ if(j!==idx&&!s.locked&&s.pct>0) pool.push(j); }); var ps=0; pool.forEach(function(j){ ps+=st[j].pct; }); if(ps<=0){ st[idx].pct-=over; return; } if(over>=ps){ pool.forEach(function(j){ st[j].pct=0; }); st[idx].pct-=(over-ps); return; } var tk=pool.map(function(j){ return Math.floor(over*st[j].pct/ps); }),al=0; tk.forEach(function(t){ al+=t; }); pool.sort(function(a,b){ return st[b].pct-st[a].pct; }); for(var k=0;k<over-al;k++) tk[k%pool.length]++; pool.forEach(function(j,x){ st[j].pct-=tk[x]; }); };
      var refresh=function(){
        if(barEl){ barEl.innerHTML=''; st.forEach(function(s){ if(s.pct>0){ var seg=document.createElement('div'); seg.style.cssText='height:100%;width:'+s.pct+'%;background:'+accent+';border-right:1px solid rgba(0,0,0,.4);'; barEl.appendChild(seg); } }); }
        st.forEach(function(s,i){ if(sliders[i]){ sliders[i].value=s.pct; sliders[i].disabled=s.locked; } if(labels[i]) labels[i].textContent=s.pct+'%'; if(lockBtns[i]){ lockBtns[i].textContent=s.locked?'🔒':'🔓'; lockBtns[i].style.opacity=s.locked?'1':'.45'; } });
        if(statEl){ var rem=100-sum(); statEl.textContent=rem===0?'✓ 100%':(rem>0?rem+'% left':(-rem)+'% over'); statEl.style.color=rem===0?'#5fcf7a':(rem>0?'#e6b450':'#e06a6a'); }
      };
      var setPct=function(idx,v){ v=Math.max(0,Math.min(100,Math.round(v))); if(st[idx].locked){ refresh(); return; } var old=st[idx].pct; st[idx].pct=v; if(auto&&v>old){ var over=sum()-100; if(over>0) reduceOthers(idx,over); } writeForm(); refresh(); };
      var applyAlloc=function(map){ st.forEach(function(s){ s.locked=false; s.pct=map[s.k]||0; }); writeForm(); refresh(); };
      var toast=function(m){ if(toastEl){ toastEl.textContent=m; toastEl.style.display='block'; } };
      var SKEY='KoC_PrefPresets';
      var savedGet=function(){ try{ return SafeStorage.get(SKEY, []) || []; }catch(e){ return []; } };
      var savedSet=function(a){ try{ SafeStorage.set(SKEY, a); }catch(e){} };

      var wrap=document.createElement('div'); wrap.style.color='inherit';
      var pr=document.createElement('div'); pr.style.cssText='margin-bottom:8px;';
      var mkBtn=function(label){ var b=document.createElement('input'); b.type='button'; b.value=label; b.style.cssText=bcss+'margin:0 6px 6px 0;cursor:pointer;'; return b; };
      var renderPresets=function(){
        pr.innerHTML='';
        var cheap=mkBtn('⚡ Cheapest first'); cheap.title='Spend gold-in-hand ranking up the cheapest stat first'; cheap.addEventListener('click', function(){ try{ autoFillArmoryPreferences(); }catch(e){} readState(); refresh(); }); pr.appendChild(cheap);
        var opt=mkBtn('🚀 Optimizer'); opt.title='Ask the roster database for the best allocation'; opt.addEventListener('click', function(){ opt.value='⏳ Optimizing…'; opt.disabled=true; Promise.resolve().then(function(){ return autoFillArmoryWithOptimizer(); }).catch(function(){}).then(function(){ readState(); refresh(); opt.value='🚀 Optimizer'; opt.disabled=false; }); }); pr.appendChild(opt);
        var sp=mkBtn('🔎 All spy'); sp.addEventListener('click', function(){ applyAlloc({spy:100}); toast('All spy.'); }); pr.appendChild(sp);
        var df=mkBtn('🛡 All defense'); df.addEventListener('click', function(){ applyAlloc({defend:100}); toast('All defense.'); }); pr.appendChild(df);
        savedGet().forEach(function(p,idx){ var b=mkBtn('⭐ '+p.name); b.addEventListener('click', function(){ applyAlloc(p.alloc); toast('Loaded "'+p.name+'".'); }); var x=mkBtn('✕'); x.title='Delete '+p.name; x.addEventListener('click', function(){ var a=savedGet(); a.splice(idx,1); savedSet(a); renderPresets(); }); pr.appendChild(b); pr.appendChild(x); });
        var sv=mkBtn('＋ Save'); sv.addEventListener('click', function(){ var nm=prompt('Preset name:', 'Preset '+(savedGet().length+1)); if(!nm) return; var a={}; st.forEach(function(s){ a[s.k]=s.pct; }); var arr=savedGet(); arr.push({name:nm, alloc:a}); savedSet(arr); renderPresets(); toast('Saved "'+nm+'".'); }); pr.appendChild(sv);
      };
      renderPresets(); wrap.appendChild(pr);
      toastEl=document.createElement('div'); toastEl.style.cssText='display:none;font-size:11px;opacity:.85;margin-bottom:8px;'; wrap.appendChild(toastEl);
      var brow=document.createElement('div'); brow.style.cssText='display:flex;align-items:center;gap:10px;margin-bottom:10px;';
      barEl=document.createElement('div'); barEl.style.cssText='flex:1;display:flex;height:14px;border-radius:3px;overflow:hidden;border:1px solid '+line+';background:rgba(0,0,0,.25);';
      statEl=document.createElement('span'); statEl.style.cssText='font-size:12px;font-weight:bold;min-width:70px;text-align:right;';
      brow.appendChild(barEl); brow.appendChild(statEl); wrap.appendChild(brow);
      var alab=document.createElement('label'); alab.style.cssText='display:flex;align-items:center;gap:7px;font-size:11px;opacity:.8;margin-bottom:10px;cursor:pointer;';
      var ac=document.createElement('input'); ac.type='checkbox'; ac.checked=true; ac.addEventListener('change', function(){ auto=ac.checked; }); alab.appendChild(ac); alab.appendChild(document.createTextNode(' Auto-balance — raising one takes from the others')); wrap.appendChild(alab);
      PK.forEach(function(p,i){
        var row=document.createElement('div'); row.style.cssText='padding:6px 0;border-top:1px solid '+line+';';
        var r1=document.createElement('div'); r1.style.cssText='display:flex;align-items:center;gap:8px;';
        var dot=document.createElement('span'); dot.style.cssText='width:8px;height:8px;border-radius:50%;background:'+accent+';flex:0 0 auto;'; r1.appendChild(dot);
        var nm=document.createElement('span'); nm.textContent=p[2]; nm.style.cssText='font-size:13px;min-width:72px;'; r1.appendChild(nm);
        var rsel=psel(p[1]);
        if(rsel){ var ms=document.createElement('select'); ms.style.cssText='margin-left:auto;max-width:170px;'; [].slice.call(rsel.options).forEach(function(o){ var oo=document.createElement('option'); oo.value=o.value; oo.textContent=o.text; if(o.selected) oo.selected=true; ms.appendChild(oo); }); ms.addEventListener('change', function(){ rsel.value=ms.value; }); r1.appendChild(ms); }
        var r2=document.createElement('div'); r2.style.cssText='display:flex;align-items:center;gap:10px;margin-top:5px;';
        var sl=document.createElement('input'); sl.type='range'; sl.min='0'; sl.max='100'; sl.step='1'; sl.value=st[i].pct; sl.style.cssText='flex:1;accent-color:'+accent+';';
        (function(idx){ sl.addEventListener('input', function(){ setPct(idx, parseInt(sl.value,10)); }); })(i);
        var lab=document.createElement('span'); lab.textContent=st[i].pct+'%'; lab.style.cssText='font-size:13px;font-weight:bold;min-width:38px;text-align:right;';
        var lk=document.createElement('span'); lk.textContent='🔓'; lk.title='Lock'; lk.style.cssText='cursor:pointer;opacity:.45;flex:0 0 auto;font-size:14px;';
        (function(idx){ lk.addEventListener('click', function(){ st[idx].locked=!st[idx].locked; refresh(); }); })(i);
        r2.appendChild(sl); r2.appendChild(lab); r2.appendChild(lk);
        row.appendChild(r1); row.appendChild(r2); wrap.appendChild(row);
        sliders[i]=sl; labels[i]=lab; lockBtns[i]=lk;
      });

      var tr=document.createElement('tr'); var td=document.createElement('td'); td.className='kdc-prefui'; td.colSpan=nCells; td.style.cssText='padding:10px 14px;color:inherit;'; td.appendChild(wrap); tr.appendChild(td);
      firstRow.parentNode.insertBefore(tr, firstRow);
      PK.forEach(function(p){ var i=pinp(p[0]); if(i){ var r=i.closest('tr'); if(r) r.style.display='none'; } });
      var ch=firstRow.previousElementSibling && firstRow.previousElementSibling.previousElementSibling; // the column-header row (Type|Percentage|Weapon), now two above (panel is directly above firstRow)
      if(ch && /Percentage/i.test(ch.textContent) && !ch.querySelector('input[name^="prefs["]')) ch.style.display='none';
      // Keep the sliders in sync with KoC's native "Clear Percentage Prefills" button — it zeroes
      // the prefs[*] inputs (now hidden behind the sliders), so re-read + refresh after it fires.
      var clrBtn=[].slice.call(form.querySelectorAll('input[type="submit"],input[type="button"],button')).filter(function(b){ return /Clear Percentage Prefills/i.test(b.value||b.textContent||''); })[0];
      if(clrBtn) clrBtn.addEventListener('click', function(){ setTimeout(function(){ st.forEach(function(s){ var i=pinp(s.k); s.pct=i?(parseInt(i.value,10)||0):0; s.locked=false; }); refresh(); }, 50); });
      refresh();
      debugLog('✅ Native armory prefs slider UI injected (theme accent: '+accent+')');
    }catch(e){ debugLog('⚠️ prefs UI enhance failed — native form left intact:', e); }
  }

  // ==================== PURCHASE CONFIRMATION SCRAPER ====================

  // Reads the "You Purchased …" lines. A buy that gained nothing went unheld —
  // often on purpose (rank hiding, keeping soldiers on income, holding
  // Poison/Antidote for the last day), so it gets a neutral note, not an error.
  // Gold per point comes from the page (GOLD PER STAT POINT), not from purchases.
  function scrapePurchaseConfirmation() {
    const bodyText = document.body.textContent;

    // Regex: "You Purchased 20 Serpentbane Arbalest, and Gained 1,122,377 Antidote."
    const purchaseRegex = /You Purchased ([\d,]+) (.+?), and Gained ([\d,]+) (\w+)\./gi;
    const matches = [...bodyText.matchAll(purchaseRegex)];

    if (matches.length === 0) return null;

    debugLog(`🛒 Found ${matches.length} purchase(s) on page`);

    const results = [];
    for (const match of matches) {
      const quantity = parseInt(match[1].replace(/,/g, ''), 10);
      const weaponName = match[2].trim();
      const statGained = parseInt(match[3].replace(/,/g, ''), 10);
      const statType = match[4].toLowerCase();

      debugLog('🛒 Purchase detected:', { quantity, weaponName, statGained, statType });

      if (statGained === 0) {
        showAutoFillMessage(
          `ℹ️ ${quantity.toLocaleString()} ${weaponName} bought unheld — no ${statType} yet.\n` +
          `They count once units are there to hold them.`,
          'info'
        );
      }
      results.push({ weaponName, quantity, statGained, statType });
    }

    return results;
  }

  // ==================== ARMORY SELF COLLECTOR ====================

  async function collectTIVAndStatsFromArmory() {
    const myId = SafeStorage.get("KoC_MyId", null);
    const myName = SafeStorage.get("KoC_MyName", null);
    if (!myId) return;

    // TIV
    const header = [...document.querySelectorAll("th.subh")]
      .find(th => th.textContent.includes("Total Invested Value"));
    const tivCell = header?.closest("tr").nextElementSibling?.querySelector("td b");
    // null = the box couldn't be read, so nothing is sent; 0 = a real empty
    // TIV, which is recorded.
    const tivText = tivCell ? tivCell.textContent.replace(/,/g, "").trim() : null;
    const tivDigits = tivText === null ? null : tivText.replace(/[^\d]/g, "");
    const tiv = tivDigits === null ? null : (tivDigits === "" ? 0 : parseInt(tivDigits, 10));

    // Military Stats - use centralized parser
    const stats = collectMilitaryStats();

    // === WEAPONS INVENTORY COLLECTION ===
    const weapons = collectWeaponsFromArmory();

    // === STORE TIV DISTRIBUTION BY CATEGORY ===
    // Calculate and store TIV by category for use on safe.php
    const tivByCategory = {};
    let totalWeaponTiv = 0;

    for (const weapon of weapons) {
      const cat = weapon.category.toLowerCase();
      if (!tivByCategory[cat]) {
        tivByCategory[cat] = 0;
      }
      tivByCategory[cat] += weapon.totalStrength || 0;
      totalWeaponTiv += weapon.totalStrength || 0;
    }

    // Store as percentages for easier use
    const tivDistribution = {};
    const categories = ['attack', 'defense', 'spy', 'sentry', 'poison', 'antidote', 'theft', 'vigilance'];
    for (const cat of categories) {
      tivDistribution[cat] = totalWeaponTiv > 0 ? (tivByCategory[cat] || 0) / totalWeaponTiv : 0;
    }

    SafeStorage.set('KoC_TivDistribution', {
      distribution: tivDistribution,
      totalTiv: totalWeaponTiv,
      timestamp: Date.now()
    });
    debugLog('📊 Stored TIV distribution:', tivDistribution);

    // Also cache the armory SPEND preferences (how gold is actually allocated when
    // buying), so safe.php can project attack-gold by spend %, not current holdings.
    collectSpendPrefs();

    // === CALCULATE GOLD-PER-POINT EFFICIENCY ===
    // Sent to the API below — the server rank optimizer needs gold_per_point.
    const efficiency = gppEfficiencyMap(gppResolve(gppReadArmory()));

    const now = getKoCServerTimeUTC();

    // A real zero counts: the /tiv endpoint records what the armory says today.
    if (tiv !== null) {
      await auth.apiCall("armory", "tiv", { playerId: myId, tiv, time: now });
    }

    // Extract real ranks from stats for API submission
    const realRanks = {
      realStrikeRank: stats._realRanks?.strike || null,
      realDefenseRank: stats._realRanks?.defense || null,
      realSpyRank: stats._realRanks?.spy || null,
      realSentryRank: stats._realRanks?.sentry || null,
      realPoisonRank: stats._realRanks?.poison || null,
      realAntidoteRank: stats._realRanks?.antidote || null,
      realTheftRank: stats._realRanks?.theft || null,
      realVigilanceRank: stats._realRanks?.vigilance || null
    };

    // Send TIV, stats, timestamps, and real ranks to API
    const payload = {
      name: myName,
      tiv,
      tivTime: now,
      // All 8 stats with their timestamps
      strikeAction: stats.strikeAction,
      strikeActionTime: stats.strikeActionTime,
      defensiveAction: stats.defensiveAction,
      defensiveActionTime: stats.defensiveActionTime,
      spyRating: stats.spyRating,
      spyRatingTime: stats.spyRatingTime,
      sentryRating: stats.sentryRating,
      sentryRatingTime: stats.sentryRatingTime,
      poisonRating: stats.poisonRating,
      poisonRatingTime: stats.poisonRatingTime,
      antidoteRating: stats.antidoteRating,
      antidoteRatingTime: stats.antidoteRatingTime,
      theftRating: stats.theftRating,
      theftRatingTime: stats.theftRatingTime,
      vigilanceRating: stats.vigilanceRating,
      vigilanceRatingTime: stats.vigilanceRatingTime,
      // Real ranks
      ...realRanks,
      // Gold per stat point: the server's rank optimizer skips any stat without one.
      ...efficiency
    };

    // Save to localStorage (skip updatePlayerInfo to avoid duplicate API call)
    const map = getNameMap();
    map[myId] = { ...map[myId], ...sanitizePlayerData(payload) };
    saveNameMap(map);

    await auth.apiCall("armory", "players", { id: myId, ...payload });

    debugLog("📊 Armory data sent to API", { id: myId, name: myName, tiv, ...realRanks });
    debugLog("📊 Local stats captured for UI", { stats, weapons: weapons.length, efficiency });
  }

  // Read the armory spend preferences (prefs[...] % per weapon type) and cache them as a
  // stat->fraction distribution. Re-read on every armory load so the safe.php "Attacked
  // Instead" projection mirrors preference changes as soon as they're saved. KoC field
  // names differ from our stat keys: defend->defense, medicine->antidote.
  function collectSpendPrefs() {
    const fieldToStat = { attack:'attack', defend:'defense', spy:'spy', sentry:'sentry', poison:'poison', medicine:'antidote', theft:'theft', vigilance:'vigilance' };
    const raw = {}; let sum = 0, found = 0;
    for (const field in fieldToStat) {
      const el = document.querySelector(`input[name="prefs[${field}]"]`);
      if (!el) continue;
      found++;
      const v = parseFloat(String(el.value).replace(/[^\d.]/g, ''));
      if (!isNaN(v)) { raw[fieldToStat[field]] = v; sum += v; }
    }
    if (found < 8 || sum <= 0) { debugLog('[Armory] Spend prefs not fully readable - not caching'); return; }
    const distribution = {};
    for (const stat of ['attack','defense','spy','sentry','poison','antidote','theft','vigilance']) {
      distribution[stat] = (raw[stat] || 0) / sum;
    }
    SafeStorage.set('KoC_SpendPrefs', { distribution, raw, timestamp: Date.now() });
    debugLog('📊 Cached armory spend prefs:', distribution);
  }

  function collectWeaponsFromArmory() {
    const weapons = [];

    // Find inventory tables by looking for:
    // - Has "Quantity" and "Strength" columns (inventory indicators)
    // - Has "Repair" or "Sell" column (inventory actions)
    // - Does NOT have "Buy" column (distinguishes from buying tables)
    const allTables = [...document.querySelectorAll('table')];
    const inventoryTables = allTables.filter(table => {
      const headers = [...table.querySelectorAll('th')];
      const headerTexts = headers.map(th => th.textContent);

      const hasQuantity = headerTexts.some(text => text.includes('Quantity'));
      const hasStrength = headerTexts.some(text => text.includes('Strength'));
      const hasSellOrRepair = headerTexts.some(text => text.includes('Sell') || text.includes('Repair'));
      const hasBuy = headerTexts.some(text => text.includes('Buy') && !text.includes('Sell'));

      return hasQuantity && hasStrength && hasSellOrRepair && !hasBuy;
    });

    if (inventoryTables.length === 0) {
      debugLog('⚠️ No weapon inventory tables found on armory page');
      return weapons;
    }

    debugLog(`🔍 Found ${inventoryTables.length} inventory table(s) in armory`);

    // All weapon/tool categories in armory
    const validCategories = [
      'Attack',
      'Defense',
      'Spy Tools',
      'Sentry Tools',
      'Poison Tools',
      'Antidote Tools',
      'Theft Tools',
      'Vigilance Tools'
    ];

    // For each inventory table, find category headers within it
    inventoryTables.forEach((inventoryTable, idx) => {
      debugLog(`📦 Processing inventory table ${idx + 1}`);

      // Find all category headers within this inventory table only
      const categoryHeaders = [...inventoryTable.querySelectorAll("th.subh")]
        .filter(th => {
          const text = th.textContent.replace(/<br>/gi, ' ').trim();
          return validCategories.some(cat => text.includes(cat));
        });

      debugLog(`  Found ${categoryHeaders.length} weapon/tool categories in this table`);

    categoryHeaders.forEach(categoryHeader => {
      // Normalize text (remove line breaks and extra spaces)
      const categoryText = categoryHeader.textContent.replace(/\s+/g, ' ').trim();

      // Normalize category names to match database conventions
      // Check if text CONTAINS the category (to handle "Attack Weapons" etc.)
      let category = null;
      if (categoryText.includes('Attack')) category = 'attack';
      else if (categoryText.includes('Defense')) category = 'defense';
      else if (categoryText.includes('Spy Tools') || categoryText.includes('Spy')) category = 'spy';
      else if (categoryText.includes('Sentry Tools') || categoryText.includes('Sentry')) category = 'sentry';
      else if (categoryText.includes('Poison Tools') || categoryText.includes('Poison')) category = 'poison';
      else if (categoryText.includes('Antidote Tools') || categoryText.includes('Antidote')) category = 'antidote';
      else if (categoryText.includes('Theft Tools') || categoryText.includes('Theft')) category = 'theft';
      else if (categoryText.includes('Vigilance Tools') || categoryText.includes('Vigilance')) category = 'vigilance';
      else category = categoryText.toLowerCase();

      if (!category) return;

      // Find the table following this header
      let currentNode = categoryHeader.closest('tr');
      const weaponRows = [];

      // Traverse siblings until we hit another category or end
      while (currentNode && currentNode.nextElementSibling) {
        currentNode = currentNode.nextElementSibling;

        // Stop if we hit another category header
        if (currentNode.querySelector('th.subh')) break;

        const cells = currentNode.querySelectorAll('td');
        if (cells.length >= 4) {
          weaponRows.push(currentNode);
        }
      }

      debugLog(`  ${category}: Found ${weaponRows.length} potential weapon rows`);

      // Each weapon is a single row with all data
      weaponRows.forEach((row, idx) => {
        try {
          const cells = row.querySelectorAll('td');
          if (cells.length < 3) return;

          // Extract weapon name (first line of cell 0, remove sell value)
          const nameText = cells[0]?.textContent.trim() || '';
          let weaponName = nameText.split('\n')[0].trim();
          // Remove "*Sell value (number)" from name (note: space before paren, not colon)
          weaponName = weaponName.split('*Sell')[0].trim();

          // Capture the per-weapon sell value the game prints in the same cell
          // ("*Sell value (63,829)") — the Stat Reshuffler prices sales with it.
          const sellMatch = nameText.match(/\*\s*Sell value\s*\(\s*([\d,]+)/i);
          const sellValue = sellMatch ? parseInt(sellMatch[1].replace(/,/g, ''), 10) : null;

          // Cell 1 is ignored (has unrelated values)

          // Cell 2 contains the QUANTITY
          const quantityText = cells[2]?.textContent.trim() || '';
          const quantity = parseInt(quantityText.replace(/,/g, ''), 10) || 0;

          // Cell 3 contains the STRENGTH. Repairable weapons (attack/defense) show
          // "current / max" e.g. "1,000 / 1,000"; covert tools DON'T degrade so KoC
          // prints a single number e.g. "1,000". Attack/defense weapons print
          // 'current / max'; covert tools print one number. Both are parsed.
          const strengthText = cells[3]?.textContent.trim() || '';
          const slashMatch = strengthText.match(/([\d,]+)\s*\/\s*([\d,]+)/);
          let minStrength, maxStrength;
          if (slashMatch) {
            minStrength = parseInt(slashMatch[1].replace(/,/g, ''), 10);
            maxStrength = parseInt(slashMatch[2].replace(/,/g, ''), 10);
          } else {
            const single = strengthText.match(/([\d,]+)/);
            maxStrength = minStrength = single ? parseInt(single[1].replace(/,/g, ''), 10) : 0;
          }

          const totalStrength = quantity * maxStrength;

          if (weaponName && quantity > 0) {
            weapons.push({
              name: weaponName,
              category: category,
              quantity: quantity,
              minStrength: minStrength,
              maxStrength: maxStrength,
              totalStrength: totalStrength,  // quantity × max strength
              sellValue: sellValue           // per-unit sell value as printed (null if unreadable)
            });
          }
        } catch (err) {
          console.warn(`⚠️ Failed to parse weapon row in ${category}:`, err);
        }
      });
    });
    }); // Close inventoryTables.forEach

    debugLog(`📦 Total weapons collected: ${weapons.length}`);
    return weapons;
  }

  // ==================== STAT RESHUFFLER ====================
  // "What if I completely reworked my army?" calculator for the Armory page.
  // Pick weapons to sell (or whole categories), optionally switch race, and
  // pour the proceeds (plus gold on hand, if ticked) into any mix of stats.
  // Projects gold recovered, weapons bought, carrier caps (unheld weapons add
  // nothing), new ratings with the race-bonus swing, and new TIV after the
  // 50% sell tax. Display-only: it reads the page and computes — it never
  // sells, buys or presses any game control.

  const RESHUF_CATS = ['attack', 'defense', 'spy', 'sentry', 'poison', 'antidote', 'theft', 'vigilance'];
  const RESHUF_LABELS = { attack: 'Attack', defense: 'Defense', spy: 'Spy', sentry: 'Sentry', poison: 'Poison', antidote: 'Antidote', theft: 'Theft', vigilance: 'Vigilance' };
  const RESHUF_CATALOG = {
    attack:    [{ name: 'Sarumans Ball', price: 100, strength: 1 }, { name: 'Heavy Steed', price: 50000, strength: 100 }, { name: 'Chariot', price: 450000, strength: 600 }, { name: 'Blackpowder Missile', price: 1000000, strength: 1000 }],
    defense:   [{ name: 'Spider', price: 5000, strength: 10 }, { name: 'Mithril', price: 50000, strength: 100 }, { name: 'Ebony Platemail', price: 450000, strength: 600 }, { name: 'Invisibility Shield', price: 1000000, strength: 1000 }],
    spy:       [{ name: 'Cloak', price: 140000, strength: 140 }, { name: 'Grappling Hook', price: 250000, strength: 250 }, { name: 'Skeleton Key', price: 600000, strength: 600 }, { name: 'Nunchaku', price: 1000000, strength: 1000 }],
    sentry:    [{ name: 'Horn', price: 140000, strength: 140 }, { name: 'Tripwire', price: 250000, strength: 250 }, { name: 'Guard Dog', price: 600000, strength: 600 }, { name: 'Lookout Tower', price: 1000000, strength: 1000 }],
    poison:    [{ name: 'Toxic Needle Dagger', price: 140000, strength: 140 }, { name: 'Venomfang Staff', price: 250000, strength: 250 }, { name: 'Blightbane Bow', price: 600000, strength: 600 }, { name: 'Plaguebringer Scythe', price: 1000000, strength: 1000 }],
    antidote:  [{ name: 'Viperfang Dirk', price: 140000, strength: 140 }, { name: 'Basiliskbane Halberd', price: 250000, strength: 250 }, { name: 'Wyrmclaw Longsword', price: 600000, strength: 600 }, { name: 'Serpentbane Arbalest', price: 1000000, strength: 1000 }],
    theft:     [{ name: 'Greasy Gloves', price: 140000, strength: 140 }, { name: 'Rusty Lockpick', price: 250000, strength: 250 }, { name: 'Shadow Cloak', price: 600000, strength: 600 }, { name: 'Ethereal Grasp', price: 1000000, strength: 1000 }],
    vigilance: [{ name: 'Wooden Whistle', price: 140000, strength: 140 }, { name: 'Steel Shackles', price: 250000, strength: 250 }, { name: 'Silver Scepter', price: 600000, strength: 600 }, { name: 'Adamantine Bastion', price: 1000000, strength: 1000 }]
  };
  // Race bonuses that touch armory stats (Humans' 15% Hostage isn't one).
  const RESHUF_RACES = ['Humans', 'Dwarves', 'Elves', 'Orcs', 'Undead', 'Trolls', 'Goblins'];
  const RESHUF_RACE_BONUS = { Humans: { poison: 0.10 }, Dwarves: { defense: 0.25 }, Elves: { spy: 0.25 }, Orcs: { attack: 0.25 }, Undead: { sentry: 0.25 }, Trolls: { theft: 0.25 }, Goblins: { vigilance: 0.25 } };
  // Which units carry each category's weapons (personnel-table labels).
  const RESHUF_UNIT_LABEL = { attack: 'Trained Attack Soldiers', defense: 'Trained Defense Soldiers', spy: 'Spies', sentry: 'Sentries', poison: 'Venomweavers', antidote: 'Serpentwardens', theft: 'Thieves', vigilance: 'Rangers' };

  function reshufRaceBonus(race, cat) {
    return (RESHUF_RACE_BONUS[race] && RESHUF_RACE_BONUS[race][cat]) || 0;
  }

  // Per-category weapon-carrier counts from the personnel table (null = unknown).
  function reshufUnitCaps() {
    try {
      const table = document.querySelector('table.table_lines.personnel') ||
                    findInnermostTable('Trained Attack Soldiers');
      if (!table) return null;
      const counts = {};
      [...table.rows].forEach(row => {
        if (row.cells.length < 2) return;
        const label = row.cells[0].textContent.trim();
        const val = parseInt(row.cells[1].textContent.replace(/[^\d]/g, ''), 10);
        if (!isNaN(val)) counts[label] = val;
      });
      const caps = {};
      for (const cat of RESHUF_CATS) {
        caps[cat] = (RESHUF_UNIT_LABEL[cat] in counts) ? counts[RESHUF_UNIT_LABEL[cat]] : null;
      }
      // Mercenaries carry attack/defense weapons too
      for (const label in counts) {
        if (!/mercenar/i.test(label)) continue;
        if (/attack/i.test(label) && caps.attack !== null) caps.attack += counts[label];
        else if (/defen/i.test(label) && caps.defense !== null) caps.defense += counts[label];
      }
      return caps;
    } catch (e) {
      debugLog('⚠️ Reshuffler: personnel read failed:', e);
      return null;
    }
  }

  // Per-unit sell value for an inventory row. The armory prints "*Sell value (…)"
  // per weapon; guard against a row-total reading (a per-unit sell can never top
  // 50% of purchase price) and fall back to 50% of the condition-scaled price.
  function reshufPerUnitSell(w) {
    const spec = (RESHUF_CATALOG[w.category] || []).find(s => s.name === w.name);
    const price = spec ? spec.price : null;
    let sell = (typeof w.sellValue === 'number' && !isNaN(w.sellValue)) ? w.sellValue : null;
    if (sell !== null && price && w.quantity > 1 && sell > price * 0.55) {
      const per = sell / w.quantity;
      if (per <= price * 0.55) sell = per;
    }
    if (sell === null) {
      sell = (price && w.maxStrength > 0) ? 0.5 * price * ((w.minStrength || 0) / w.maxStrength) : 0;
    }
    return sell;
  }

  // Strength the carriers can actually hold: strongest weapons first, capped at
  // the unit count (capacity null = unknown, everything counts).
  function reshufHeldStrength(list, capacity) {
    let space = (capacity === null || capacity === undefined) ? Infinity : capacity;
    let total = 0;
    for (const it of list) {
      if (space <= 0) break;
      const held = Math.min(it.qty, space);
      total += held * it.str;
      space -= held;
    }
    return total;
  }

  function reshufSnapshot() {
    const weapons = collectWeaponsFromArmory();
    const statsRaw = collectMilitaryStats();
    const num = v => parseInt(String(v == null ? '0' : v).replace(/,/g, ''), 10) || 0;
    const ratings = {
      attack: num(statsRaw.strikeAction), defense: num(statsRaw.defensiveAction),
      spy: num(statsRaw.spyRating), sentry: num(statsRaw.sentryRating),
      poison: num(statsRaw.poisonRating), antidote: num(statsRaw.antidoteRating),
      theft: num(statsRaw.theftRating), vigilance: num(statsRaw.vigilanceRating)
    };
    const tivHeader = [...document.querySelectorAll('th.subh')].find(th => th.textContent.includes('Total Invested Value'));
    const tivCell = tivHeader?.closest('tr').nextElementSibling?.querySelector('td b');
    const tiv = tivCell ? num(tivCell.textContent) : 0;
    // Available Funds and Vault Gold, as printed on the Armory.
    const bodyText = document.body.textContent;
    const funds = num(bodyText.match(/Available\s+Funds:\s*([\d,]+)\s*Gold/i)?.[1]);
    const vault = num(bodyText.match(/Vault\s+Gold:\s*([\d,]+)\s*Gold/i)?.[1]);
    const caps = reshufUnitCaps();
    const unheld = gppUnheldCounts();
    const gpp = gppResolve(gppReadArmory());

    const cats = {};
    for (const cat of RESHUF_CATS) {
      const rows = weapons.filter(w => w.category === cat).map(w => ({
        name: w.name, qty: w.quantity, cur: w.minStrength || 0, max: w.maxStrength || 0,
        sell: reshufPerUnitSell(w)
      }));
      rows.sort((a, b) => b.cur - a.cur); // carriers grab the strongest first
      let capacity = caps ? caps[cat] : null;
      // The game's own unheld count beats our carrier count: untrained soldiers
      // hold SA/DA weapons too (live: 479,671 SA weapons, 462,511 trained attack
      // soldiers, "Unheld = 0"). With unheld weapons it IS the carrier count.
      if (unheld[cat] !== null) {
        const totalQty = rows.reduce((s, r) => s + r.qty, 0);
        capacity = unheld[cat] > 0 ? totalQty - unheld[cat] : Math.max(capacity || 0, totalQty);
      }
      const heldNow = reshufHeldStrength(rows.map(r => ({ qty: r.qty, str: r.cur })), capacity);
      const g = gpp[cat];
      cats[cat] = {
        rows, capacity, heldNow, rating: ratings[cat],
        mult: g.mult > 0 ? g.mult : null,
        multSource: g.source,
        multTs: g.ts,
        stale: g.stale
      };
    }
    return { cats, tiv, funds, vault, capsKnown: caps !== null };
  }

  // A Remembered reading taken before that stat's skill upgrade is flagged as stale.
  function reshufStaleCheck(c) {
    return c.stale ? { from: c.stale.from, to: c.stale.to } : null;
  }

  // ==================== GOLD PER STAT POINT ====================
  // One gold-per-point figure per stat, shared by the rank-up costs, the
  // Optimizer, the Stat Reshuffler and the safe.php projection. Sources, best first:
  //   pinned     — typed by the player (gold/pt); wins until cleared
  //   live       — this armory visit: rating ÷ strength of the weapons the game
  //                says are held (its own "Total … Unheld = N" lines), plus 1
  //                per carrier unit for the covert stats (see gppReadArmory)
  //   remembered — the last live reading, kept when a stat goes unheld on purpose
  //                (rank hiding, income, holding Poison/Antidote for the last day)
  //   paired     — Poison↔Antidote, Theft↔Vigilance: the partner's multiplier,
  //                only while both skills sit at the same upgrade level
  // Purchases are not used: a buy that displaces held weapons (BPMs over held
  // chariots) or lands unheld reads low.
  const GPP_LIVE_KEY = 'KoC_GppLive';
  const GPP_PINS_KEY = 'KoC_GppPins';
  const GPP_HELD_KEY = 'KoC_PlanAsHeld';
  const SKILL_LEVELS_KEY = 'KoC_MySkillLevels';
  const GPP_PAIR = { poison: 'antidote', antidote: 'poison', theft: 'vigilance', vigilance: 'theft' };
  const GPP_UNHELD_LABEL = { attack: 'SA Weapons', defense: 'DA Weapons', spy: 'Spy Tools', sentry: 'Sentry Tools', poison: 'Poison Tools', antidote: 'Antidote Tools', theft: 'Theft Tools', vigilance: 'Vigilance Tools' };
  const GPP_STAT_KEY = { attack: 'strikeAction', defense: 'defensiveAction', spy: 'spyRating', sentry: 'sentryRating', poison: 'poisonRating', antidote: 'antidoteRating', theft: 'theftRating', vigilance: 'vigilanceRating' };
  const GPP_EFF_KEY = { attack: 'goldPerAttackPoint', defense: 'goldPerDefensePoint', spy: 'goldPerSpyPoint', sentry: 'goldPerSentryPoint', poison: 'goldPerPoisonPoint', antidote: 'goldPerAntidotePoint', theft: 'goldPerTheftPoint', vigilance: 'goldPerVigilancePoint' };
  // upgrades.php section headers → stat ("Upgrade Covert Skill", "Siege", …)
  const SKILL_SECTIONS = [
    [/Siege/i, 'attack'], [/Fortification/i, 'defense'], [/Covert Skill/i, 'spy'], [/Sentry Skill/i, 'sentry'],
    [/Poison Skill/i, 'poison'], [/Antidote Skill/i, 'antidote'], [/Theft Skill/i, 'theft'], [/Vigilance Skill/i, 'vigilance']
  ];

  // Gold per base strength point of the cheapest of the top two tiers — the
  // weapon a high-level player actually buys (Chariot for attack/defense).
  function gppBestRatio(cat) {
    return Math.min(...RESHUF_CATALOG[cat].slice(-2).map(w => w.price / w.strength));
  }

  // On upgrades.php each skill table prints "Level N" under "Current … Skill".
  // Recorded so a Paired estimate is only offered at equal levels, and a
  // Remembered reading taken before an upgrade is called out.
  function collectSkillLevels() {
    const levels = {};
    document.querySelectorAll('table').forEach(t => {
      if (t.querySelector('table')) return; // innermost tables only
      const th = t.querySelector('th');
      if (!th) return;
      const hit = SKILL_SECTIONS.find(([re]) => re.test(th.textContent));
      if (!hit) return;
      const m = t.textContent.match(/Level\s+(\d+)/i); // first one is the current level
      if (m) levels[hit[1]] = parseInt(m[1], 10);
    });
    if (Object.keys(levels).length === 0) { debugLog('[GPP] No skill levels found on upgrades.php'); return; }
    SafeStorage.set(SKILL_LEVELS_KEY, { levels, ts: Date.now() });
    debugLog('[GPP] Skill levels recorded:', levels);
  }

  // The game's own count of unheld weapons per category (null = not printed).
  function gppUnheldCounts() {
    const text = document.body.textContent.replace(/\s+/g, ' ');
    const out = {};
    for (const cat of RESHUF_CATS) {
      const m = text.match(new RegExp('Total ' + GPP_UNHELD_LABEL[cat] + ' Unheld\\s*=\\s*([\\d,]+)', 'i'));
      out[cat] = m ? parseInt(m[1].replace(/,/g, ''), 10) : null;
    }
    return out;
  }

  // Armory reading per stat: rating, held and unheld strength. Held = the
  // strongest weapons first, as many as the game says are held. Null for a
  // stat whose unheld line isn't on the page (no live reading from guesses).
  //
  // unitStrength: every spy, sentry, venomweaver… adds about 1 strength point
  // of its own to the rating, tool or no tool: 3 Nunchaku + 1,379 spies read
  // 243,131 Spy (×55.5 over tools + spies), and a bought Nunchaku gained
  // 55,505. Sentry fits "all units", not "unarmed only".
  // Attack/Defense are left out: not measured, and untrained soldiers hold too.
  function gppReadArmory() {
    const weapons = collectWeaponsFromArmory();
    const stats = collectMilitaryStats();
    const unheld = gppUnheldCounts();
    const caps = reshufUnitCaps();
    const num = v => parseInt(String(v == null ? '0' : v).replace(/,/g, ''), 10) || 0;
    const cats = {};
    for (const cat of RESHUF_CATS) {
      const rating = num(stats[GPP_STAT_KEY[cat]]);
      if (unheld[cat] === null) { cats[cat] = null; continue; }
      const rows = weapons.filter(w => w.category === cat)
        .map(w => ({ qty: w.quantity, str: w.minStrength || 0 }))
        .sort((a, b) => b.str - a.str);
      const totalQty = rows.reduce((s, r) => s + r.qty, 0);
      const totalStrength = rows.reduce((s, r) => s + r.qty * r.str, 0);
      const heldQty = Math.max(0, totalQty - unheld[cat]);
      const heldStrength = reshufHeldStrength(rows, heldQty);
      const units = (cat !== 'attack' && cat !== 'defense' && caps && caps[cat] > 0) ? caps[cat] : 0;
      cats[cat] = { rating, totalQty, unheldQty: unheld[cat], heldStrength, unheldStrength: totalStrength - heldStrength, unitStrength: units };
    }
    return { cats, stats };
  }

  function gppLevels() {
    const s = SafeStorage.get(SKILL_LEVELS_KEY, null);
    return (s && s.levels) ? s.levels : {};
  }

  // Resolve every stat's multiplier and gold/pt. Pass gppReadArmory() on the
  // armory (records fresh live readings); pass nothing elsewhere.
  function gppResolve(armory) {
    const live = SafeStorage.get(GPP_LIVE_KEY, {});
    const pins = SafeStorage.get(GPP_PINS_KEY, {});
    const levels = gppLevels();
    const race = SafeStorage.get('KoC_MyRace', null);
    let dirty = false;

    if (armory) {
      for (const cat of RESHUF_CATS) {
        const a = armory.cats[cat];
        if (!a || !(a.heldStrength > 0) || !(a.rating > 0)) continue;
        live[cat] = { mult: a.rating / (a.heldStrength + (a.unitStrength || 0)), ts: Date.now(), level: levels[cat] ?? null };
        dirty = true;
      }
    }
    // Readings marked `seeded` came from purchases, which are not used.
    for (const cat of RESHUF_CATS) {
      if (live[cat] && live[cat].seeded) { delete live[cat]; dirty = true; }
    }
    if (dirty) SafeStorage.set(GPP_LIVE_KEY, live);

    const staleOf = (cat) => {
      const e = live[cat];
      if (!e || e.level == null || levels[cat] == null || e.level === levels[cat]) return null;
      return { from: e.level, to: levels[cat] };
    };
    const out = {};
    for (const cat of RESHUF_CATS) {
      const a = armory ? armory.cats[cat] : null;
      const r = { cat, mult: null, gpp: null, source: null, ts: null, stale: null, pairFrom: null, pinned: false,
                  rating: a ? a.rating : null, unheldQty: a ? a.unheldQty : null, unheldStrength: a ? a.unheldStrength : null };
      const fresh = !!(a && a.heldStrength > 0 && a.rating > 0);
      const e = live[cat];
      if (e) {
        r.mult = e.mult; r.ts = e.ts;
        r.source = fresh ? 'live' : 'remembered';
        if (!fresh) r.stale = staleOf(cat);
      } else {
        const p = GPP_PAIR[cat];
        const pe = p ? live[p] : null;
        if (pe && levels[cat] != null && levels[cat] === levels[p] && !staleOf(p)) {
          r.mult = pe.mult * (1 + reshufRaceBonus(race, cat)) / (1 + reshufRaceBonus(race, p));
          r.source = 'paired'; r.pairFrom = p; r.ts = pe.ts;
        }
      }
      if (r.mult > 0) r.gpp = gppBestRatio(cat) / r.mult;
      if (pins[cat] > 0) {
        r.under = { source: r.source, gpp: r.gpp };
        r.gpp = pins[cat]; r.mult = gppBestRatio(cat) / pins[cat];
        r.source = 'pinned'; r.pinned = true; r.stale = null;
      }
      out[cat] = r;
    }
    return out;
  }

  // The efficiency map the rank-up display and the roster API take.
  function gppEfficiencyMap(resolved) {
    const eff = {};
    for (const cat of RESHUF_CATS) {
      const r = resolved[cat];
      if (r && r.gpp > 0) eff[GPP_EFF_KEY[cat]] = Number(r.gpp.toPrecision(4));
    }
    return eff;
  }

  function gppPlanAsHeld() { return SafeStorage.get(GPP_HELD_KEY, false) === true; }

  // Rating as it would read with every owned weapon held.
  function gppHeldRating(r) {
    if (!(r.rating > 0) || !(r.unheldStrength > 0) || !(r.mult > 0)) return r.rating;
    return Math.round(r.rating + r.mult * r.unheldStrength);
  }

  function gppSourceLabel(r) {
    const age = r.ts ? Math.max(0, Math.round((Date.now() - r.ts) / 86400000)) : null;
    const ago = age === null ? '' : (age === 0 ? ' · today' : ' · ' + age + 'd ago');
    switch (r.source) {
      case 'pinned': return 'Pinned';
      case 'live': return 'Live';
      case 'remembered': return 'Remembered' + ago + (r.stale ? ' · before L' + r.stale.from + '→L' + r.stale.to + ' upgrade — hold 1 to refresh' : '');
      case 'paired': return 'est. from ' + RESHUF_LABELS[r.pairFrom] + ' (both L' + gppLevels()[r.cat] + ')';
      default: return 'none — pin one';
    }
  }

  // Parse a goal target: plain digits, commas/spaces, or K/M/B/T shorthand
  // ("4,784,687,574,927", "4.78T", "500b"). Returns null when unreadable.
  function reshufParseTarget(s) {
    if (!s) return null;
    const m = String(s).trim().replace(/[,\s]/g, '').match(/^(\d+(?:\.\d+)?|\.\d+)([kmbt])?$/i); // one decimal point at most
    if (!m) return null;
    let v = parseFloat(m[1]);
    if (isNaN(v) || v <= 0) return null;
    const suf = (m[2] || '').toLowerCase();
    if (suf === 'k') v *= 1e3;
    else if (suf === 'm') v *= 1e6;
    else if (suf === 'b') v *= 1e9;
    else if (suf === 't') v *= 1e12;
    return Math.round(v);
  }

  // Goal mode: how far is the scenario's PROJECTED rating from a target, and
  // what would closing the gap cost with the selected weapon? Uses the
  // race-ADJUSTED multiplier (buying happens as the new race), and reports
  // how many of the needed weapons your units could actually hold.
  function reshufGoalCalc(snap, plan, sim, cat, target) {
    const c = snap.cats[cat];
    const r = sim.results[cat];
    if (r.newRating === null) return { unknown: true };
    const projected = r.newRating;
    const gap = target - projected;
    if (gap <= 0) return { projected, gap, reached: true, surplus: -gap };
    const scale = (1 + reshufRaceBonus(plan.raceTo, cat)) / (1 + reshufRaceBonus(plan.raceFrom, cat));
    const multEff = (c.mult !== null) ? c.mult * scale : null;
    if (!multEff) return { projected, gap, noMult: true };
    const tiers = RESHUF_CATALOG[cat];
    const spec = tiers.find(s => s.name === plan.buyWeapon[cat]) || tiers[tiers.length - 1];
    const perWeapon = multEff * spec.strength;
    const weaponsNeeded = Math.ceil(gap / perWeapon);
    const goldNeeded = weaponsNeeded * spec.price;
    let slotsLeft = null;
    if (!plan.ignoreCaps && c.capacity !== null) slotsLeft = Math.max(0, c.capacity - r.unitsAfter);
    return { projected, gap, weapon: spec.name, weaponsNeeded, goldNeeded, perWeapon, slotsLeft };
  }

  function reshufSimulate(snap, plan) {
    let proceeds = 0, removedValue = 0;
    const afterRows = {};
    for (const cat of RESHUF_CATS) {
      const c = snap.cats[cat];
      const sellMap = plan.sell[cat] || {};
      const after = [];
      c.rows.forEach((r, i) => {
        const sellQty = Math.max(0, Math.min(r.qty, Math.floor(sellMap[i] || 0)));
        proceeds += sellQty * r.sell;
        removedValue += sellQty * r.sell * 2; // TIV loses the full value; you get half back
        if (r.qty - sellQty > 0) after.push({ qty: r.qty - sellQty, str: r.cur });
      });
      afterRows[cat] = after;
    }
    const pool = proceeds + (plan.includeOnHand ? (snap.funds + snap.vault) : 0);
    let totalSpent = 0, allocTotal = 0;
    for (const cat of RESHUF_CATS) allocTotal += (plan.alloc[cat] || 0);
    const results = {};
    for (const cat of RESHUF_CATS) {
      const c = snap.cats[cat];
      const pct = plan.alloc[cat] || 0;
      const tiers = RESHUF_CATALOG[cat];
      const spec = tiers.find(s => s.name === plan.buyWeapon[cat]) || tiers[tiers.length - 1];
      const bought = pct > 0 ? Math.floor((pool * pct / 100) / spec.price) : 0;
      const spent = bought * spec.price;
      totalSpent += spent;
      const list = afterRows[cat].slice();
      if (bought > 0) list.push({ qty: bought, str: spec.strength });
      list.sort((a, b) => b.str - a.str);
      // "Ignore carrier caps" = the player will train units as needed: every
      // weapon counts as held — including ones unheld TODAY, since Δ is taken
      // against the capped heldNow (so training alone can show a gain).
      const effCapacity = plan.ignoreCaps ? null : c.capacity;
      const heldAfter = reshufHeldStrength(list, effCapacity);
      const unitsAfter = list.reduce((s, it) => s + it.qty, 0);
      const unheld = (effCapacity === null) ? 0 : Math.max(0, unitsAfter - effCapacity);
      const scale = (1 + reshufRaceBonus(plan.raceTo, cat)) / (1 + reshufRaceBonus(plan.raceFrom, cat));
      let newRating = null;
      if (c.mult !== null) {
        newRating = Math.max(0, Math.round(scale * (c.rating + c.mult * (heldAfter - c.heldNow))));
      } else if (heldAfter === c.heldNow) {
        newRating = Math.round(scale * c.rating);
      }
      results[cat] = {
        bought, weapon: spec.name, spent, newRating, unheld, scale, unitsAfter,
        changed: heldAfter !== c.heldNow || scale !== 1
      };
    }
    return {
      proceeds, pool, totalSpent,
      leftover: pool - totalSpent,
      newTiv: snap.tiv - removedValue + totalSpent,
      removedValue, results, allocTotal
    };
  }

  function openStatReshuffler() {
    if (document.getElementById('kdc-reshuffle-overlay')) return;
    const snap = reshufSnapshot();
    const h = escapeHtml;
    const fmt = n => (n === null || n === undefined || isNaN(n)) ? '?' : Math.round(n).toLocaleString('en-US');

    // Best guess at current race: last manual pick, else the roster's view of us
    const raceStored = SafeStorage.get('KoC_MyRace', null);
    const mapRace = (getNameMap()[SafeStorage.get('KoC_MyId', null)] || {}).race || null;
    const guessRace = [raceStored, mapRace]
      .map(r => RESHUF_RACES.find(x => r && x.toLowerCase() === String(r).toLowerCase()))
      .find(Boolean) || '';

    const overlay = document.createElement('div');
    overlay.id = 'kdc-reshuffle-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:1000000;display:flex;align-items:center;justify-content:center;';
    const panel = document.createElement('div');
    panel.style.cssText = 'background:linear-gradient(160deg,#1d222b,#12151b);color:#d8dee9;border:1px solid #3a4150;border-radius:10px;width:min(760px,96vw);max-height:88vh;display:flex;flex-direction:column;font-family:Verdana,Arial,sans-serif;font-size:12px;box-shadow:0 8px 30px rgba(0,0,0,0.6);';

    // Header
    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid #3a4150;';
    const title = document.createElement('div');
    title.innerHTML = '<b style="color:#e8edf5;">🔀 Stat Reshuffler</b> <span style="color:#8b94a7;font-size:10px;">what-if only — nothing is sold or bought</span>';
    const resetBtn = document.createElement('button');
    resetBtn.textContent = '↺ Reset';
    resetBtn.title = 'Clear the scenario and re-read the page';
    resetBtn.style.cssText = 'margin-left:auto;background:none;border:1px solid #3a4150;border-radius:4px;color:#8b94a7;font-size:11px;cursor:pointer;padding:2px 8px;';
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    closeBtn.title = 'Close';
    closeBtn.style.cssText = 'background:none;border:none;color:#8b94a7;font-size:14px;cursor:pointer;padding:2px 6px;';
    header.appendChild(title);
    header.appendChild(resetBtn);
    header.appendChild(closeBtn);
    panel.appendChild(header);

    const inpCss = 'background:#12151b;color:#d8dee9;border:1px solid #3a4150;border-radius:4px;padding:3px 5px;';
    const selCss = inpCss + 'max-width:220px;';
    const secCss = 'padding:8px 12px 4px 12px;color:#7ea0c9;font-size:10px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;';
    const thCss = 'padding:4px 10px;color:#7ea0c9;font-size:10px;text-transform:uppercase;letter-spacing:1px;text-align:left;';

    const raceOpt = r => {
      const b = RESHUF_RACE_BONUS[r];
      const cat = b ? Object.keys(b)[0] : null;
      return '<option value="' + r + '">' + r + (cat ? ' (+' + Math.round(b[cat] * 100) + '% ' + RESHUF_LABELS[cat] + ')' : '') + '</option>';
    };

    // — Sell section rows —
    let sellHtml = '';
    for (const cat of RESHUF_CATS) {
      const c = snap.cats[cat];
      if (!c.rows.length) continue;
      const capTxt = c.capacity !== null ? fmt(c.capacity) + ' ' + h(RESHUF_UNIT_LABEL[cat]) : 'carriers unknown';
      sellHtml += '<tr style="background:rgba(255,255,255,0.05);">' +
        '<td colspan="3" style="padding:7px 10px;"><b style="color:#7ea0c9;">' + h(RESHUF_LABELS[cat]) + '</b> ' +
        '<span style="color:#8b94a7;font-size:10px;">rating ' + fmt(c.rating) + ' · ' + capTxt + '</span></td>' +
        '<td style="padding:4px 10px;text-align:right;"><button type="button" class="kdc-rs-sellall" data-cat="' + cat + '" style="background:#3d2f13;color:#f0c674;border:1px solid #57431d;border-radius:4px;padding:2px 8px;font-size:10px;cursor:pointer;">Sell all</button></td></tr>';
      c.rows.forEach((r, i) => {
        sellHtml += '<tr style="border-top:1px solid #262c37;">' +
          '<td style="padding:4px 10px;">' + h(r.name) + ' <span style="color:#5c6472;font-size:10px;">' + fmt(r.cur) + (r.max !== r.cur ? '/' + fmt(r.max) : '') + '</span></td>' +
          '<td style="padding:4px 10px;text-align:right;">' + fmt(r.qty) + '</td>' +
          '<td style="padding:4px 10px;text-align:right;color:#c9a959;">' + fmt(r.sell) + '</td>' +
          '<td style="padding:4px 10px;text-align:right;white-space:nowrap;">' +
          '<input type="number" class="kdc-rs-sell" data-cat="' + cat + '" data-row="' + i + '" min="0" max="' + r.qty + '" value="0" style="width:90px;' + inpCss + '"> ' +
          '<a href="#" class="kdc-rs-rowall" data-cat="' + cat + '" data-row="' + i + '" style="color:#7ea0c9;font-size:10px;text-decoration:none;">all</a></td></tr>';
      });
    }
    if (!sellHtml) sellHtml = '<tr><td colspan="4" style="padding:8px 10px;color:#8b94a7;">No weapons found in your armory inventory.</td></tr>';

    // — Buy section rows —
    let buyHtml = '';
    for (const cat of RESHUF_CATS) {
      const tiers = RESHUF_CATALOG[cat];
      const opts = tiers.map((s, i) =>
        '<option value="' + h(s.name) + '"' + (i === tiers.length - 1 ? ' selected' : '') + '>' + h(s.name) + ' (' + fmt(s.price) + 'g)</option>').join('');
      buyHtml += '<tr style="border-top:1px solid #262c37;">' +
        '<td style="padding:4px 10px;"><b>' + h(RESHUF_LABELS[cat]) + '</b></td>' +
        '<td style="padding:4px 10px;"><select class="kdc-rs-weap" data-cat="' + cat + '" style="' + selCss + '">' + opts + '</select></td>' +
        '<td style="padding:4px 10px;text-align:right;white-space:nowrap;">' +
        '<input type="number" class="kdc-rs-alloc" data-cat="' + cat + '" min="0" max="100" value="0" style="width:64px;' + inpCss + '"> % ' +
        '<a href="#" class="kdc-rs-allocall" data-cat="' + cat + '" style="color:#7ea0c9;font-size:10px;text-decoration:none;">all</a></td></tr>';
    }

    const body = document.createElement('div');
    body.style.cssText = 'overflow-y:auto;flex:1 1 auto;';
    body.innerHTML =
      '<div style="padding:8px 12px;color:#8b94a7;font-size:11px;border-bottom:1px solid #262c37;">Every sale returns <b>50%</b> of a weapon\'s value (and lands in your Vault), so a full rework costs half of what you liquidate. Projections use the gold per point from the Gold per Stat Point panel (Live, Remembered, Paired or Pinned).</div>' +
      '<div style="' + secCss + '">Race</div>' +
      '<div style="display:flex;align-items:center;gap:8px;padding:2px 12px 8px 12px;font-size:11px;flex-wrap:wrap;">' +
      '<span style="color:#8b94a7;">Now:</span><select id="kdc-rs-race-from" style="' + selCss + '"><option value="">— set race —</option>' + RESHUF_RACES.map(raceOpt).join('') + '</select>' +
      '<span style="color:#8b94a7;">→ after:</span><select id="kdc-rs-race-to" style="' + selCss + '"><option value="">No change</option>' + RESHUF_RACES.map(raceOpt).join('') + '</select>' +
      '</div>' +
      '<div style="' + secCss + '">1 · Sell</div>' +
      '<table style="width:100%;border-collapse:collapse;font-size:11px;">' +
      '<tr><td style="' + thCss + '">Weapon</td><td style="' + thCss + 'text-align:right;">Have</td><td style="' + thCss + 'text-align:right;">Sell each</td><td style="' + thCss + 'text-align:right;">Sell qty</td></tr>' +
      sellHtml + '</table>' +
      '<div style="' + secCss + '">2 · Re-buy</div>' +
      '<label style="display:flex;align-items:center;gap:7px;padding:2px 12px 2px 12px;font-size:11px;cursor:pointer;">' +
      '<input type="checkbox" id="kdc-rs-onhand" style="margin:0;"> Also spend gold on hand + vault (' + fmt(snap.funds + snap.vault) + ' gold)</label>' +
      '<label style="display:flex;align-items:center;gap:7px;padding:2px 12px 6px 12px;font-size:11px;cursor:pointer;">' +
      '<input type="checkbox" id="kdc-rs-ignorecap" style="margin:0;"> Ignore carrier caps — I\'ll train units to hold everything (currently-unheld weapons count too)</label>' +
      '<table style="width:100%;border-collapse:collapse;font-size:11px;">' +
      '<tr><td style="' + thCss + '">Stat</td><td style="' + thCss + '">Weapon to buy</td><td style="' + thCss + 'text-align:right;">% of pool</td></tr>' +
      buyHtml + '</table>' +
      '<div style="' + secCss + '">3 · Goal <span style="letter-spacing:0;text-transform:none;color:#5c6472;">(optional)</span></div>' +
      '<div style="display:flex;align-items:center;gap:8px;padding:2px 12px 4px 12px;font-size:11px;flex-wrap:wrap;">' +
      '<span style="color:#8b94a7;">Reach</span>' +
      '<select id="kdc-rs-goal-stat" style="' + selCss + '"><option value="">— pick a stat —</option>' +
      RESHUF_CATS.map(c => '<option value="' + c + '">' + RESHUF_LABELS[c] + '</option>').join('') + '</select>' +
      '<span style="color:#8b94a7;">of</span>' +
      '<input type="text" id="kdc-rs-goal-target" placeholder="e.g. 4,784,687,574,927 or 4.78T" style="width:190px;' + inpCss + '">' +
      '</div>' +
      '<div id="kdc-rs-goal-out"></div>' +
      '<div style="' + secCss + '">4 · Result</div>' +
      '<div id="kdc-rs-results"></div>' +
      '<div style="padding:6px 12px 10px 12px;color:#5c6472;font-size:10px;">Estimates only — repairs, purchases and battle damage between now and the rework will shift the numbers. This tool never touches the game\'s forms.</div>';
    panel.appendChild(body);

    const resDiv = body.querySelector('#kdc-rs-results');
    const raceFromSel = body.querySelector('#kdc-rs-race-from');
    if (guessRace) raceFromSel.value = guessRace;

    const goalOut = body.querySelector('#kdc-rs-goal-out');
    const goalStatSel = body.querySelector('#kdc-rs-goal-stat');
    const goalTargetInp = body.querySelector('#kdc-rs-goal-target');

    function renderGoal(sim, plan) {
      const cat = goalStatSel.value;
      const raw = goalTargetInp.value;
      const target = reshufParseTarget(raw);
      if (!cat || target === null) {
        goalOut.innerHTML = (cat && raw.trim()) ? '<div style="padding:0 12px 6px 12px;font-size:11px;color:#e6b450;">Couldn\'t read that target — use digits with commas, or K/M/B/T shorthand (e.g. 4.78T).</div>' : '';
        return;
      }
      const g = reshufGoalCalc(snap, plan, sim, cat, target);
      const L = h(RESHUF_LABELS[cat]);
      let html = '<div style="padding:0 12px 6px 12px;font-size:11px;line-height:1.7;">';
      if (g.unknown) {
        html += '<span style="color:#e6b450;">Projected ' + L + ' is unknown (no multiplier) — hold at least one, or pin a gold/pt under the Rank Gain table.</span>';
      } else {
        html += '<span style="color:#8b94a7;">Projected ' + L + ' after this plan:</span> <b>' + fmt(g.projected) + '</b> &nbsp;·&nbsp; <span style="color:#8b94a7;">goal:</span> <b>' + fmt(target) + '</b><br>';
        if (g.reached) {
          html += '<span style="color:#5fcf7a;">✅ Goal reached — ' + fmt(g.surplus) + ' over the target.</span>';
        } else if (g.noMult) {
          html += '<span style="color:#e6b450;">Gap ' + fmt(g.gap) + ', but no ' + L + ' multiplier — hold at least one, or pin a gold/pt under the Rank Gain table.</span>';
        } else {
          html += '<span style="color:#8b94a7;">Gap:</span> <b style="color:#e06a6a;">' + fmt(g.gap) + '</b> &nbsp;≈&nbsp; <b>' + fmt(g.weaponsNeeded) + ' × ' + h(g.weapon) + '</b> &nbsp;=&nbsp; <b style="color:#c9a959;">' + fmt(g.goldNeeded) + ' gold</b> on top of this plan';
          if (sim.leftover > 0) {
            html += '<br><span style="color:#8b94a7;">This plan leaves ' + fmt(sim.leftover) + ' gold unspent — net extra needed ≈ </span><b style="color:#c9a959;">' + fmt(Math.max(0, g.goldNeeded - sim.leftover)) + '</b>';
          }
          if (g.slotsLeft !== null && g.weaponsNeeded > g.slotsLeft) {
            html += '<br><span style="color:#e6b450;">⚠ Only ' + fmt(g.slotsLeft) + ' more can be held by your ' + fmt(snap.cats[cat].capacity) + ' ' + h(RESHUF_UNIT_LABEL[cat]) + ' — train more or tick Ignore carrier caps.</span>';
          }
        }
      }
      html += '</div>';
      goalOut.innerHTML = html;
    }

    function renderResults(sim, plan) {
      const rowsHtml = RESHUF_CATS.map(cat => {
        const c = snap.cats[cat];
        const r = sim.results[cat];
        const after = r.newRating;
        let delta;
        if (after === null) delta = '<span style="color:#e6b450;">?</span>';
        else if (c.rating > 0) {
          const pc = (after - c.rating) / c.rating * 100;
          if (Math.abs(pc) < 0.05) delta = '<span style="color:#5c6472;">—</span>';
          else delta = '<span style="color:' + (pc >= 0 ? '#5fcf7a' : '#e06a6a') + ';">' + (pc >= 0 ? '+' : '') + pc.toFixed(1) + '%</span>';
        } else if (after > 0) delta = '<span style="color:#5fcf7a;">new</span>';
        else delta = '<span style="color:#5c6472;">—</span>';
        const notes = [];
        const staleInfo = reshufStaleCheck(c);
        if (staleInfo) {
          notes.push('<span style="color:#e6b450;">⚠ multiplier from before the L' + staleInfo.from + '→L' + staleInfo.to +
            ' upgrade — hold 1 to refresh</span>');
        }
        if (r.bought > 0) notes.push(fmt(r.bought) + ' × ' + h(r.weapon));
        if (r.unheld > 0) notes.push('<span style="color:#8b94a7;">' + fmt(r.unheld) + ' unheld (' + fmt(c.capacity) + ' held)</span>');
        if (c.multSource === 'paired' && r.changed) notes.push('<span style="color:#8b94a7;">est. multiplier</span>');
        if (c.mult === null && after === null) notes.push('<span style="color:#e6b450;">no multiplier — pin a gold/pt for ' + h(RESHUF_LABELS[cat]) + ' under the Rank Gain table</span>');
        return '<tr style="border-top:1px solid #262c37;' + (r.changed ? '' : 'opacity:.55;') + '">' +
          '<td style="padding:4px 10px;">' + h(RESHUF_LABELS[cat]) + '</td>' +
          '<td style="padding:4px 10px;text-align:right;">' + fmt(c.rating) + '</td>' +
          '<td style="padding:4px 10px;text-align:right;font-weight:bold;">' + (after === null ? '?' : fmt(after)) + '</td>' +
          '<td style="padding:4px 10px;text-align:right;">' + delta + '</td>' +
          '<td style="padding:4px 10px;font-size:10px;">' + notes.join(' · ') + '</td></tr>';
      }).join('');

      const tivDelta = sim.newTiv - snap.tiv;
      const tivPc = snap.tiv > 0 ? (tivDelta / snap.tiv * 100) : 0;
      const allocNote = sim.allocTotal > 100
        ? '<span style="color:#e06a6a;">Allocation is ' + sim.allocTotal.toFixed(0) + '% — over 100%, the pool is overspent!</span>'
        : (sim.allocTotal > 0 && sim.allocTotal < 100 ? '<span style="color:#8b94a7;">' + (100 - sim.allocTotal).toFixed(0) + '% of the pool is unallocated.</span>' : '');
      const warn = [];
      const staleCats = RESHUF_CATS.filter(cat => reshufStaleCheck(snap.cats[cat]));
      if (staleCats.length) warn.push('⚠ Multiplier' + (staleCats.length > 1 ? 's' : '') + ' from before a skill upgrade: ' +
        staleCats.map(cat => RESHUF_LABELS[cat]).join(', ') +
        ' — hold at least 1 weapon/tool in each and reload before trusting these projections.');
      if (!snap.capsKnown && !plan.ignoreCaps) warn.push('⚠ Personnel table not readable — every weapon is assumed held (no carrier caps applied).');
      if (plan.raceTo && plan.raceTo !== plan.raceFrom && !plan.raceFrom) warn.push('⚠ Set your CURRENT race for the race switch to be calculated.');

      resDiv.innerHTML =
        '<div style="display:grid;grid-template-columns:auto auto;gap:2px 14px;padding:8px 10px;font-size:11px;max-width:420px;">' +
        '<span style="color:#8b94a7;">Gold from sales (→ Vault)</span><b style="text-align:right;color:#c9a959;">' + fmt(sim.proceeds) + '</b>' +
        '<span style="color:#8b94a7;">Buying pool' + (plan.includeOnHand ? ' (incl. on-hand + vault)' : '') + '</span><b style="text-align:right;">' + fmt(sim.pool) + '</b>' +
        '<span style="color:#8b94a7;">Spent on new weapons</span><b style="text-align:right;">' + fmt(sim.totalSpent) + '</b>' +
        '<span style="color:#8b94a7;">Gold left over</span><b style="text-align:right;color:' + (sim.leftover < 0 ? '#e06a6a' : '#c9a959') + ';">' + fmt(sim.leftover) + '</b>' +
        '<span style="color:#8b94a7;">TIV now → after</span><b style="text-align:right;">' + fmt(snap.tiv) + ' → ' + fmt(sim.newTiv) +
        ' <span style="color:' + (tivDelta >= 0 ? '#5fcf7a' : '#e06a6a') + ';">(' + (tivDelta >= 0 ? '+' : '') + fmt(tivDelta) + ', ' + tivPc.toFixed(1) + '%)</span></b>' +
        '</div>' +
        (plan.ignoreCaps ? '<div style="padding:0 10px 6px 10px;font-size:11px;color:#8b94a7;">Carrier caps ignored — assumes you train enough units to hold every weapon.</div>' : '') +
        (allocNote ? '<div style="padding:0 10px 6px 10px;font-size:11px;">' + allocNote + '</div>' : '') +
        (warn.length ? '<div style="padding:0 10px 6px 10px;font-size:11px;color:#e6b450;">' + warn.join('<br>') + '</div>' : '') +
        '<table style="width:100%;border-collapse:collapse;font-size:11px;">' +
        '<tr><td style="' + thCss + '">Stat</td><td style="' + thCss + 'text-align:right;">Now</td><td style="' + thCss + 'text-align:right;">Projected</td><td style="' + thCss + 'text-align:right;">Δ</td><td style="' + thCss + '">Notes</td></tr>' +
        rowsHtml + '</table>';
    }

    const recalc = () => {
      try {
        const plan = { sell: {}, alloc: {}, buyWeapon: {}, raceFrom: '', raceTo: '', includeOnHand: false };
        body.querySelectorAll('input.kdc-rs-sell').forEach(inp => {
          const v = Math.floor(parseFloat(inp.value) || 0);
          if (v > 0) (plan.sell[inp.dataset.cat] = plan.sell[inp.dataset.cat] || {})[parseInt(inp.dataset.row, 10)] = v;
        });
        body.querySelectorAll('input.kdc-rs-alloc').forEach(inp => { plan.alloc[inp.dataset.cat] = Math.max(0, parseFloat(inp.value) || 0); });
        body.querySelectorAll('select.kdc-rs-weap').forEach(sel => { plan.buyWeapon[sel.dataset.cat] = sel.value; });
        plan.raceFrom = raceFromSel.value;
        plan.raceTo = body.querySelector('#kdc-rs-race-to').value || plan.raceFrom;
        plan.includeOnHand = body.querySelector('#kdc-rs-onhand').checked;
        plan.ignoreCaps = body.querySelector('#kdc-rs-ignorecap').checked;
        const sim = reshufSimulate(snap, plan);
        renderResults(sim, plan);
        renderGoal(sim, plan);
      } catch (e) {
        debugLog('⚠️ Reshuffler recalc failed:', e);
      }
    };

    body.addEventListener('input', recalc);
    body.addEventListener('change', recalc);
    body.addEventListener('click', (e) => {
      const t = e.target;
      if (t.classList.contains('kdc-rs-sellall')) {
        body.querySelectorAll('input.kdc-rs-sell[data-cat="' + t.dataset.cat + '"]').forEach(inp => { inp.value = inp.max; });
        recalc();
      } else if (t.classList.contains('kdc-rs-rowall')) {
        e.preventDefault();
        const inp = body.querySelector('input.kdc-rs-sell[data-cat="' + t.dataset.cat + '"][data-row="' + t.dataset.row + '"]');
        if (inp) { inp.value = inp.max; recalc(); }
      } else if (t.classList.contains('kdc-rs-allocall')) {
        e.preventDefault();
        body.querySelectorAll('input.kdc-rs-alloc').forEach(inp => { inp.value = (inp.dataset.cat === t.dataset.cat) ? 100 : 0; });
        recalc();
      }
    });
    raceFromSel.addEventListener('change', () => {
      if (raceFromSel.value) SafeStorage.set('KoC_MyRace', raceFromSel.value);
    });
    // "Ignore carrier caps" is a standing stance ("I'll train as needed") — remember it
    const ignoreCapCb = body.querySelector('#kdc-rs-ignorecap');
    ignoreCapCb.checked = !!SafeStorage.get('KoC_ReshufIgnoreCaps', false);
    ignoreCapCb.addEventListener('change', () => {
      SafeStorage.set('KoC_ReshufIgnoreCaps', ignoreCapCb.checked);
    });
    // The goal usually outlives one visit (chasing a rank threshold) — remember it
    const savedGoal = SafeStorage.get('KoC_ReshufGoal', null);
    if (savedGoal && savedGoal.cat && RESHUF_CATS.includes(savedGoal.cat)) {
      goalStatSel.value = savedGoal.cat;
      goalTargetInp.value = savedGoal.target || '';
    }
    const saveGoal = () => SafeStorage.set('KoC_ReshufGoal', { cat: goalStatSel.value, target: goalTargetInp.value });
    goalStatSel.addEventListener('change', saveGoal);
    goalTargetInp.addEventListener('input', saveGoal);

    const close = () => overlay.remove();
    closeBtn.addEventListener('click', close);
    resetBtn.addEventListener('click', () => { close(); openStatReshuffler(); });
    // Close only when the press STARTED on the backdrop (same guard as settings)
    let pressOnOverlay = false;
    overlay.addEventListener('pointerdown', (e) => { pressOnOverlay = e.target === overlay; });
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay && pressOnOverlay) close();
    });

    overlay.appendChild(panel);
    document.body.appendChild(overlay);
    recalc();
  }

  function initStatReshuffler() {
    try {
      if (document.getElementById('kdc-reshuffle-btn')) return;
      const openIt = () => { try { openStatReshuffler(); } catch (e) { console.warn('⚠️ Reshuffler failed to open:', e); } };

      // Preferred spot: a full-width banner row directly ABOVE the "Armory
      // Preferences" header, cloned from that header's computed style so it
      // matches whatever theme the player runs.
      const prefsHeader = [...document.querySelectorAll('th, td')]
        .find(el => el.textContent.replace(/[\s ]+/g, ' ').trim().toLowerCase() === 'armory preferences');
      const prefsRow = prefsHeader && prefsHeader.closest('tr');
      if (prefsRow && prefsRow.parentNode) {
        const cs = getComputedStyle(prefsHeader);
        const cell = document.createElement(prefsHeader.tagName.toLowerCase() === 'td' ? 'td' : 'th');
        cell.id = 'kdc-reshuffle-btn';
        cell.colSpan = prefsHeader.colSpan || 1;
        cell.textContent = '🔀 Stat Reshuffler';
        cell.title = 'What-if calculator: sell weapons, switch race, re-buy other stats — nothing is actually sold or bought';
        let css = 'cursor:pointer;user-select:none;';
        ['background-color', 'background-image', 'color', 'border-top', 'border-right', 'border-bottom', 'border-left', 'padding', 'font-family', 'font-size', 'font-weight', 'text-align', 'text-shadow', 'letter-spacing'].forEach(p => {
          const v = cs.getPropertyValue(p);
          if (v) css += p + ':' + v + ';';
        });
        cell.style.cssText = css;
        cell.addEventListener('mouseenter', () => { cell.style.filter = 'brightness(1.35)'; });
        cell.addEventListener('mouseleave', () => { cell.style.filter = ''; });
        cell.addEventListener('click', openIt);
        const bannerRow = document.createElement('tr');
        bannerRow.appendChild(cell);
        prefsRow.parentNode.insertBefore(bannerRow, prefsRow);
        debugLog('✅ Stat Reshuffler banner injected above Armory Preferences');
        return;
      }

      // Fallback when the Armory Preferences header isn't found: a button under the TIV box.
      const tivHeader = [...document.querySelectorAll('th.subh')].find(th => th.textContent.includes('Total Invested Value'));
      const anchorRow = tivHeader && tivHeader.closest('tr');
      if (!anchorRow || !anchorRow.parentNode) { debugLog('🔀 Reshuffler: neither Armory Preferences nor TIV anchor found — skipped'); return; }
      // Clone a native button's look so the launcher matches the theme (same
      // trick as the prefs sliders' preset buttons)
      let bcss = '';
      const nbtn = document.querySelector('input[type="submit"]') || document.querySelector('input[type="button"]') || document.querySelector('button');
      if (nbtn) {
        const bcs = getComputedStyle(nbtn);
        ['background-color', 'background-image', 'color', 'border-width', 'border-style', 'border-color', 'border-radius', 'padding', 'font-family', 'font-size', 'font-weight', 'text-shadow'].forEach(p => {
          const v = bcs.getPropertyValue(p);
          if (v) bcss += p + ':' + v + ';';
        });
      }
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = tivHeader.colSpan || 1;
      td.style.cssText = 'text-align:center;padding:5px;';
      const btn = document.createElement('input');
      btn.type = 'button';
      btn.id = 'kdc-reshuffle-btn';
      btn.value = '🔀 Stat Reshuffler';
      btn.title = 'What-if calculator: sell weapons, switch race, re-buy other stats — nothing is actually sold or bought';
      btn.style.cssText = bcss + 'cursor:pointer;';
      btn.addEventListener('click', openIt);
      td.appendChild(btn);
      tr.appendChild(td);
      anchorRow.parentNode.appendChild(tr);
      debugLog('✅ Stat Reshuffler button injected');
    } catch (e) {
      debugLog('⚠️ initStatReshuffler failed:', e);
    }
  }

  // ==================== TRAINING PAGE WARNINGS ====================

  /**
   * Parse weapons/tools table from training page
   * Extracts total and unheld counts for all weapon/tool types
   */
  function parseWeaponsToolsTable() {
    const weaponsData = {
      saWeapons: { total: 0, unheld: 0 },
      daWeapons: { total: 0, unheld: 0 },
      spyTools: { total: 0, unheld: 0 },
      sentryTools: { total: 0, unheld: 0 },
      poisonTools: { total: 0, unheld: 0 },
      antidoteTools: { total: 0, unheld: 0 },
      theftTools: { total: 0, unheld: 0 },
      vigilanceTools: { total: 0, unheld: 0 }
    };

    // Find all table rows
    const rows = document.querySelectorAll('table.table_lines tr, table tr');

    rows.forEach(row => {
      const text = row.textContent.trim();

      // Regex pattern: "Total SA Weapons = 907,483 | Total SA Weapons Unheld = 0"
      const saMatch = text.match(/Total SA Weapons\s*=\s*([\d,]+)\s*\|\s*Total SA Weapons Unheld\s*=\s*([\d,]+)/i);
      if (saMatch) {
        weaponsData.saWeapons.total = parseInt(saMatch[1].replace(/,/g, ''), 10);
        weaponsData.saWeapons.unheld = parseInt(saMatch[2].replace(/,/g, ''), 10);
      }

      const daMatch = text.match(/Total DA Weapons\s*=\s*([\d,]+)\s*\|\s*Total DA Weapons Unheld\s*=\s*([\d,]+)/i);
      if (daMatch) {
        weaponsData.daWeapons.total = parseInt(daMatch[1].replace(/,/g, ''), 10);
        weaponsData.daWeapons.unheld = parseInt(daMatch[2].replace(/,/g, ''), 10);
      }

      const spyMatch = text.match(/Total Spy Tools\s*=\s*([\d,]+)\s*\|\s*Total Spy Tools Unheld\s*=\s*([\d,]+)/i);
      if (spyMatch) {
        weaponsData.spyTools.total = parseInt(spyMatch[1].replace(/,/g, ''), 10);
        weaponsData.spyTools.unheld = parseInt(spyMatch[2].replace(/,/g, ''), 10);
      }

      const sentryMatch = text.match(/Total Sentry Tools\s*=\s*([\d,]+)\s*\|\s*Total Sentry Tools Unheld\s*=\s*([\d,]+)/i);
      if (sentryMatch) {
        weaponsData.sentryTools.total = parseInt(sentryMatch[1].replace(/,/g, ''), 10);
        weaponsData.sentryTools.unheld = parseInt(sentryMatch[2].replace(/,/g, ''), 10);
      }

      const poisonMatch = text.match(/Total Poison Tools\s*=\s*([\d,]+)\s*\|\s*Total Poison Tools Unheld\s*=\s*([\d,]+)/i);
      if (poisonMatch) {
        weaponsData.poisonTools.total = parseInt(poisonMatch[1].replace(/,/g, ''), 10);
        weaponsData.poisonTools.unheld = parseInt(poisonMatch[2].replace(/,/g, ''), 10);
      }

      const antidoteMatch = text.match(/Total Antidote Tools\s*=\s*([\d,]+)\s*\|\s*Total Antidote Tools Unheld\s*=\s*([\d,]+)/i);
      if (antidoteMatch) {
        weaponsData.antidoteTools.total = parseInt(antidoteMatch[1].replace(/,/g, ''), 10);
        weaponsData.antidoteTools.unheld = parseInt(antidoteMatch[2].replace(/,/g, ''), 10);
      }

      const theftMatch = text.match(/Total Theft Tools\s*=\s*([\d,]+)\s*\|\s*Total Theft Tools Unheld\s*=\s*([\d,]+)/i);
      if (theftMatch) {
        weaponsData.theftTools.total = parseInt(theftMatch[1].replace(/,/g, ''), 10);
        weaponsData.theftTools.unheld = parseInt(theftMatch[2].replace(/,/g, ''), 10);
      }

      const vigilanceMatch = text.match(/Total Vigilance Tools\s*=\s*([\d,]+)\s*\|\s*Total Vigilance Tools Unheld\s*=\s*([\d,]+)/i);
      if (vigilanceMatch) {
        weaponsData.vigilanceTools.total = parseInt(vigilanceMatch[1].replace(/,/g, ''), 10);
        weaponsData.vigilanceTools.unheld = parseInt(vigilanceMatch[2].replace(/,/g, ''), 10);
      }
    });

    return weaponsData;
  }

  /**
   * Parse soldier counts from training page
   * Extracts trained/untrained soldier and mercenary counts
   */
  function parseSoldierCounts() {
    const soldierData = {
      trainedAttackSoldiers: 0,
      trainedAttackMercenaries: 0,
      trainedDefenseSoldiers: 0,
      trainedDefenseMercenaries: 0,
      untrainedSoldiers: 0,
      untrainedMercenaries: 0
    };

    const rows = document.querySelectorAll('table.table_lines tr, table tr');

    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      if (cells.length < 2) return;

      const label = cells[0].textContent.trim().toLowerCase();
      const valueText = cells[1].textContent.trim();

      if (valueText === '???' || valueText === 'Unknown' || !valueText) return;

      const value = parseInt(valueText.replace(/,/g, ''), 10) || 0;

      // Match labels (case-insensitive, flexible)
      if ((label.includes('attack soldiers') || label.includes('trained attack soldiers')) && !label.includes('merc')) {
        soldierData.trainedAttackSoldiers = value;
      }
      else if (label.includes('attack mercen') || label.includes('attack merc')) {
        soldierData.trainedAttackMercenaries = value;
      }
      else if ((label.includes('defense soldiers') || label.includes('trained defense soldiers') || label.includes('defence soldiers')) && !label.includes('merc')) {
        soldierData.trainedDefenseSoldiers = value;
      }
      else if (label.includes('defense mercen') || label.includes('defence mercen') || label.includes('defense merc') || label.includes('defence merc')) {
        soldierData.trainedDefenseMercenaries = value;
      }
      else if (label.includes('untrained soldiers') && !label.includes('merc')) {
        soldierData.untrainedSoldiers = value;
      }
      else if (label.includes('untrained mercen') || label.includes('untrained merc')) {
        soldierData.untrainedMercenaries = value;
      }
    });

    return soldierData;
  }

  /**
   * Calculate warnings based on weapons and soldier data
   * Returns object with unheld warnings and untrained holding warnings
   */
  function calculateWarnings(weaponsData, soldierData) {
    const warnings = {
      unheldWarnings: [],
      untrainedHoldingWarnings: [],
      zeroMercsWarnings: []
    };

    // Check for unheld weapons/tools
    const weaponTypes = [
      { key: 'saWeapons', name: 'SA Weapons' },
      { key: 'daWeapons', name: 'DA Weapons' },
      { key: 'spyTools', name: 'Spy Tools' },
      { key: 'sentryTools', name: 'Sentry Tools' },
      { key: 'poisonTools', name: 'Poison Tools' },
      { key: 'antidoteTools', name: 'Antidote Tools' },
      { key: 'theftTools', name: 'Theft Tools' },
      { key: 'vigilanceTools', name: 'Vigilance Tools' }
    ];

    weaponTypes.forEach(type => {
      const data = weaponsData[type.key];
      if (data.unheld > 0) {
        warnings.unheldWarnings.push({
          name: type.name,
          count: data.unheld
        });
      }
    });

    // Check for untrained soldiers holding weapons
    const totalTrainedAttack = soldierData.trainedAttackSoldiers + soldierData.trainedAttackMercenaries;
    const totalTrainedDefense = soldierData.trainedDefenseSoldiers + soldierData.trainedDefenseMercenaries;

    // SA Weapons check
    if (weaponsData.saWeapons.total > totalTrainedAttack) {
      const excess = weaponsData.saWeapons.total - totalTrainedAttack;
      const needed = Math.ceil(excess);

      warnings.untrainedHoldingWarnings.push({
        type: 'SA Weapons',
        totalWeapons: weaponsData.saWeapons.total,
        trainedUnits: totalTrainedAttack,
        excess: excess,
        neededSoldiers: needed,
        effectiveness: '0.5x (50% penalty)',
        message: `${excess.toLocaleString()} SA Weapons held by untrained soldiers at 0.5x effectiveness. Train ${needed.toLocaleString()} more attack soldiers/mercenaries.`
      });
    }

    // DA Weapons check
    if (weaponsData.daWeapons.total > totalTrainedDefense) {
      const excess = weaponsData.daWeapons.total - totalTrainedDefense;
      const needed = Math.ceil(excess);

      warnings.untrainedHoldingWarnings.push({
        type: 'DA Weapons',
        totalWeapons: weaponsData.daWeapons.total,
        trainedUnits: totalTrainedDefense,
        excess: excess,
        neededSoldiers: needed,
        effectiveness: '0.5x (50% penalty)',
        message: `${excess.toLocaleString()} DA Weapons held by untrained soldiers at 0.5x effectiveness. Train ${needed.toLocaleString()} more defense soldiers/mercenaries.`
      });
    }

    // Check for zero mercenaries (mercs die first in combat, protecting soldiers who affect gold income)
    if (soldierData.trainedAttackMercenaries === 0) {
      warnings.zeroMercsWarnings.push({
        type: 'attack',
        message: 'No attack mercenaries - Real soldiers will die in combat, reducing gold income. Buy attack mercenaries as a buffer.'
      });
    }

    if (soldierData.trainedDefenseMercenaries === 0) {
      warnings.zeroMercsWarnings.push({
        type: 'defense',
        message: 'No defense mercenaries - Real soldiers will die when defending, reducing gold income. Buy defense mercenaries as a buffer.'
      });
    }

    return warnings;
  }

  /**
   * Create warning box HTML element
   * Returns table element styled with KoC theme
   */
  function createWarningBox(warnings) {
    // Don't show box if no warnings
    if (warnings.unheldWarnings.length === 0 && warnings.untrainedHoldingWarnings.length === 0 && warnings.zeroMercsWarnings.length === 0) {
      return null;
    }

    const warningBox = document.createElement('table');
    warningBox.className = 'table_lines';
    warningBox.style.cssText = `
      width: 100%;
      margin: 10px 0;
      border: 2px solid #f90;
      background: #1a1a1a;
    `;

    let html = '<tbody>';

    // Header
    html += '<tr><th style="text-align: center; font-size: 14px; padding: 10px; background: #2a2a2a;">⚠️ Training Warnings</th></tr>';

    // Unheld Warnings (Orange)
    if (warnings.unheldWarnings.length > 0) {
      html += `
        <tr>
          <td style="padding: 10px; background: rgba(255, 153, 0, 0.15); border-top: 2px solid #f90;">
            <div style="color: #f90; font-weight: bold; margin-bottom: 5px;">⚠️ Unheld Weapons/Tools</div>
            <div style="color: #ccc; font-size: 12px;">
      `;

      warnings.unheldWarnings.forEach(item => {
        html += `<div style="margin: 3px 0;">• ${item.name}: <span style="color: #f90; font-weight: bold;">${item.count.toLocaleString()}</span> unheld</div>`;
      });

      html += `
            </div>
          </td>
        </tr>
      `;
    }

    // Zero Mercenaries Warnings (Orange - Important)
    if (warnings.zeroMercsWarnings.length > 0) {
      html += `
        <tr>
          <td style="padding: 10px; background: rgba(255, 153, 0, 0.15); border-top: 2px solid #f90;">
            <div style="color: #f90; font-weight: bold; margin-bottom: 5px;">⚠️ No Mercenary Buffer</div>
            <div style="color: #ccc; font-size: 12px;">
      `;

      warnings.zeroMercsWarnings.forEach(item => {
        html += `<div style="margin: 3px 0;">• ${item.message}</div>`;
      });

      html += `
            </div>
          </td>
        </tr>
      `;
    }

    // Untrained Soldiers Holding Weapons Warnings (Red - Critical)
    if (warnings.untrainedHoldingWarnings.length > 0) {
      html += `
        <tr>
          <td style="padding: 10px; background: rgba(255, 68, 68, 0.15); border-top: 2px solid #f44;">
            <div style="color: #f44; font-weight: bold; margin-bottom: 5px;">🚨 CRITICAL: Untrained Soldiers Holding Weapons</div>
            <div style="color: #ccc; font-size: 12px;">
      `;

      warnings.untrainedHoldingWarnings.forEach(item => {
        html += `
          <div style="margin: 8px 0; padding: 8px; background: rgba(0, 0, 0, 0.3); border-left: 3px solid #f44;">
            <div style="color: #f44; font-weight: bold;">${item.type}</div>
            <div style="margin-top: 3px;">
              • Total: ${item.totalWeapons.toLocaleString()} weapons
            </div>
            <div>
              • Trained units: ${item.trainedUnits.toLocaleString()}
            </div>
            <div style="color: #f44;">
              • <strong>${item.excess.toLocaleString()} weapons</strong> held by untrained soldiers at <strong>0.5x effectiveness</strong>
            </div>
            <div style="color: #6f6; margin-top: 5px;">
              ✅ Solution: Train <strong>${item.neededSoldiers.toLocaleString()}</strong> more ${item.type === 'SA Weapons' ? 'attack' : 'defense'} soldiers/mercenaries
            </div>
          </div>
        `;
      });

      html += `
            </div>
          </td>
        </tr>
      `;
    }

    html += '</tbody>';
    warningBox.innerHTML = html;

    return warningBox;
  }

  /**
   * Insert warning box into training page
   * Prioritizes main content area to avoid sidebar overlap
   */
  function insertWarningBox(warningBox) {
    if (!warningBox) return;

    // Strategy 1: Insert at the top of the main content area (BEST - avoids sidebar)
    const contentCell = document.querySelector('td.content_cell');
    if (contentCell) {
      contentCell.insertBefore(warningBox, contentCell.firstChild);
      debugLog('[TrainingWarnings] Warning box inserted at top of content area');
      return;
    }

    // Strategy 2: Insert after any table with "Training" header
    const headers = document.querySelectorAll('th');
    for (const header of headers) {
      if (header.textContent.toLowerCase().includes('training')) {
        const table = header.closest('table');
        if (table && table.parentNode) {
          table.parentNode.insertBefore(warningBox, table.nextSibling);
          debugLog('[TrainingWarnings] Warning box inserted after training header');
          return;
        }
      }
    }

    // Strategy 3: Insert before the first table in main content
    const firstTable = document.querySelector('table.table_lines');
    if (firstTable && firstTable.parentNode) {
      firstTable.parentNode.insertBefore(warningBox, firstTable);
      debugLog('[TrainingWarnings] Warning box inserted before first table');
      return;
    }

    // Fallback: Insert at the beginning of body
    if (document.body.firstChild) {
      document.body.insertBefore(warningBox, document.body.firstChild);
      debugLog('[TrainingWarnings] Warning box inserted at body (fallback)');
    }
  }

  /**
   * Main function to enhance training page with warnings
   * Orchestrates parsing, calculation, and display
   */
  function enhanceTrainingPage() {
    debugLog('[TrainingWarnings] Starting training page enhancement');

    try {
      // Parse data from page
      const weaponsData = parseWeaponsToolsTable();
      const soldierData = parseSoldierCounts();

      debugLog('[TrainingWarnings] Parsed weapons data:', weaponsData);
      debugLog('[TrainingWarnings] Parsed soldier data:', soldierData);

      // Validate we have minimum required data
      if (!weaponsData || !soldierData) {
        debugLog('[TrainingWarnings] Missing data - cannot calculate warnings');
        return;
      }

      // Calculate warnings
      const warnings = calculateWarnings(weaponsData, soldierData);

      debugLog('[TrainingWarnings] Calculated warnings:', warnings);

      // Create and insert warning box
      const warningBox = createWarningBox(warnings);
      if (warningBox) {
        insertWarningBox(warningBox);
        debugLog('[TrainingWarnings] Warning box created and inserted');
      } else {
        debugLog('[TrainingWarnings] No warnings to display - all good!');
      }

    } catch (error) {
      console.error('[TrainingWarnings] Error enhancing training page:', error);
    }
  }

  // ==================== SLAYING COMPETITION TRACKING ====================

  /**
   * Competition tracking system - tracks attack missions and gold stolen
   * Supports individual and team competitions
   */

  const COMP_SETTINGS_PREFIX = "KoC_CompSettings"; // Per-competition settings
  const COMP_STATS_KEY_PREFIX = "KoC_CompStats"; // Cache stats across pages (per competition)
  const COMP_LAST_SUBMIT_PREFIX = "KoC_CompLastSubmit"; // Per-competition submission tracking

  // Competition settings storage
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
    const key = `${COMP_STATS_KEY_PREFIX}_${competitionId}`;
    try { return JSON.parse(localStorage.getItem(key) || "{}"); }
    catch { return {}; }
  }

  function saveCompStats(competitionId, stats) {
    if (!competitionId) return;
    const key = `${COMP_STATS_KEY_PREFIX}_${competitionId}`;
    localStorage.setItem(key, JSON.stringify(stats));
  }

  function clearOldCompData(activeCompIds) {
    // Clear stats, settings, and submission tracking for competitions not in activeCompIds
    const keys = Object.keys(localStorage);
    const activeIdSet = new Set(activeCompIds.map(id => String(id)));

    for (const key of keys) {
      // Check if it's a competition-related key
      if (key.startsWith(COMP_STATS_KEY_PREFIX) ||
          key.startsWith(COMP_SETTINGS_PREFIX) ||
          key.startsWith(COMP_LAST_SUBMIT_PREFIX)) {

        // Extract competition ID from key
        const parts = key.split('_');
        const compId = parts[parts.length - 1];

        // If this competition is not in the active list, remove it
        if (!activeIdSet.has(compId)) {
          localStorage.removeItem(key);
        }
      }
    }
  }

  // Parse a KoC number that may be abbreviated with a K/M/B/T suffix.
  // The sidebar shows large gold/safe values abbreviated (e.g. "2,560M" = 2.56 billion),
  // so a plain parseInt("2,560M") would wrongly yield 2560. Returns a number or null.
  function parseKocNumber(str) {
    if (str == null) return null;
    const s = String(str).replace(/,/g, "").trim();
    const m = s.match(/(-?\d+(?:\.\d+)?)\s*([KMBT])?/i);
    if (!m) return null;
    const n = parseFloat(m[1]);
    if (isNaN(n)) return null;
    const suffix = (m[2] || "").toUpperCase();
    const mult = suffix === "K" ? 1e3 : suffix === "M" ? 1e6 : suffix === "B" ? 1e9 : suffix === "T" ? 1e12 : 1;
    return Math.round(n * mult);
  }

  // The number after "<label>:" in the first cell starting with that label
  // (sidebar Gold, Safe, …), abbreviations included, or null.
  function getSidebarValue(label) {
    const el = [...document.querySelectorAll("td")].find(td =>
      td.innerText.trim().startsWith(label)
    );
    if (!el) return null;
    const parts = el.innerText.split(":");
    if (parts.length < 2) return null;
    return parseKocNumber(parts[1]) || null;
  }

  // Stat extraction functions
  function extractAttackMissions() {
    // Look for "Attack Missions" on rewards.php in the "Your Actions" table
    const cells = document.querySelectorAll('td[align="left"]');

    for (const cell of cells) {
      if (cell.textContent.includes('Attack Missions')) {
        const font = cell.querySelector('font[color="goldenrod"]');
        if (font) {
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
        const match = text.match(/Gold Stolen By You This Era\s+([\d,]+)/);
        if (match) {
          return parseInt(match[1].replace(/,/g, ""), 10);
        }
      }
    }
    return null;
  }

  function extractCompCurrentStats(competitionId) {
    const cached = getCompStats(competitionId);

    // Try to get from current page
    let attackMissions = extractAttackMissions();
    let goldStolenEra = extractGoldStolen();

    // If not found on current page, use cached values
    if (attackMissions === null) attackMissions = cached.attackMissions || null;
    if (goldStolenEra === null) goldStolenEra = cached.goldStolenEra || null;

    // Update cache if we found new values (with individual timestamps)
    if (attackMissions !== null || goldStolenEra !== null) {
      const now = Date.now();
      const updated = {
        attackMissions: attackMissions !== null ? attackMissions : cached.attackMissions,
        goldStolenEra: goldStolenEra !== null ? goldStolenEra : cached.goldStolenEra,
        attackMissionsTimestamp: attackMissions !== null ? now : cached.attackMissionsTimestamp,
        goldStolenTimestamp: goldStolenEra !== null ? now : cached.goldStolenTimestamp,
        lastUpdate: now
      };
      saveCompStats(competitionId, updated);
    }

    const experience = getSidebarValue("Experience");
    const turns = getSidebarValue("Turns");
    const gold = getSidebarValue("Gold");

    return { experience, turns, gold, attackMissions, goldStolenEra };
  }

  // Check if both stats are fresh (captured within threshold seconds of each other)
  function areCompStatsFresh(cached, thresholdSeconds = 30) {
    if (!cached.attackMissionsTimestamp || !cached.goldStolenTimestamp) {
      return false;
    }
    const timeDiff = Math.abs(cached.attackMissionsTimestamp - cached.goldStolenTimestamp);
    return timeDiff <= (thresholdSeconds * 1000);
  }

  // Active competitions
  let activeCompetitions = [];
  let myCompEntries = new Map(); // competitionId -> entry data

  async function loadActiveCompetitions() {
    // Fetch all active competitions (API returns array)
    const comps = await auth.apiCall("read", "competitions/active");
    if (!Array.isArray(comps) || comps.length === 0) {
      debugLog("ℹ️ No active competitions");
      return false;
    }

    activeCompetitions = Array.isArray(comps) ? comps : [];

    // Clear old competition data from localStorage
    const activeIds = activeCompetitions.map(c => c.id);
    clearOldCompData(activeIds);

    // Load entries for each competition
    for (const comp of activeCompetitions) {
      const entry = await auth.apiCall("read", `competitions/${comp.id}/my-entry`);
      if (entry) {
        myCompEntries.set(comp.id, entry);
      }
    }

    return activeCompetitions.length > 0;
  }

  // Team management
  async function joinCompTeam(competitionId, teamId) {
    const result = await auth.apiCall("competitions", `competitions/${competitionId}/join-team`, { team_id: teamId });
    if (result) {
      myCompEntries.set(competitionId, result);
      return true;
    }
    return false;
  }

  async function getAvailableCompTeams(competitionId) {
    return await auth.apiCall("read", `competitions/${competitionId}/teams`);
  }

  // Submit stats
  async function submitCompStats(competition) {
    if (!competition) {
      debugLog('⚠️ submitCompStats called with no competition');
      return;
    }

    const settings = getCompSettings(competition.id);

    // Check if we're enabled
    if (settings.enabled === false) {
      debugLog(`ℹ️ Competition "${competition.name}" tracking is disabled`);
      return;
    }

    const stats = extractCompCurrentStats(competition.id);

    // Only require attack missions for submission
    if (stats.attackMissions === null) {
      debugLog(`⚠️ Could not extract Attack Missions for: ${competition.name}`);
      return;
    }

    try {
      debugLog(`📤 Submitting stats for competition "${competition.name}"`, stats);
      const result = await auth.apiCall(
        "competitions",
        `competitions/${competition.id}/entries`,
        stats
      );

      if (result) {
        myCompEntries.set(competition.id, result);
        debugLog(`✅ Stats submitted successfully for "${competition.name}"`);
      } else {
        debugLog(`⚠️ No result returned from API for "${competition.name}"`);
      }
    } catch (error) {
      console.error(`❌ Error submitting stats for "${competition.name}":`, error);
      throw error; // Re-throw so safeExecute can catch it
    }
  }

  // Toggle participation
  async function toggleCompParticipation(competition, enabled) {
    if (!competition) return;

    const settings = getCompSettings(competition.id);
    settings.enabled = enabled;
    saveCompSettings(competition.id, settings);

    // If we have an entry, update it on the server
    const entry = myCompEntries.get(competition.id);
    if (entry) {
      await auth.apiCall(
        "competitions",
        `competitions/${competition.id}/toggle`,
        { enabled }
      );
    }
  }

  // Leaderboard display
  async function showCompLeaderboard(competition) {
    if (!competition) {
      console.error('❌ showCompLeaderboard called with no competition');
      alert("No competition specified");
      return;
    }

    let leaderboard;
    try {
      // Fetch team or individual leaderboard based on competition type
      const endpoint = competition.is_team_competition
        ? `competitions/${competition.id}/team-leaderboard`
        : `competitions/${competition.id}/leaderboard`;

      debugLog(`📊 Fetching leaderboard from: ${endpoint}`);
      leaderboard = await auth.apiCall("read", endpoint);

      if (!leaderboard) {
        console.error(`❌ No leaderboard data returned for competition: ${competition.name}`);
        alert("Failed to load leaderboard - no data returned from API");
        return;
      }

      debugLog(`✅ Leaderboard loaded: ${leaderboard.length} entries`);
    } catch (error) {
      console.error(`❌ Error loading leaderboard for "${competition.name}":`, error);
      alert(`Failed to load leaderboard: ${error.message}`);
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

    let tableHTML = '';

    if (competition.is_team_competition) {
      // Team leaderboard
      tableHTML = `
        <thead>
          <tr style="background:#222; color:#6f6;">
            <th style="padding:8px; border:1px solid #444;">Rank</th>
            <th style="padding:8px; border:1px solid #444;">Team</th>
            <th style="padding:8px; border:1px solid #444;">👥 Members</th>
            <th style="padding:8px; border:1px solid #444;">⚔️ Total Attacks</th>
            <th style="padding:8px; border:1px solid #444;">💰 Total Gold Stolen</th>
            <th style="padding:8px; border:1px solid #444;">📊 Avg Gold/Attack</th>
          </tr>
        </thead>
        <tbody>
      `;

      const myEntry = myCompEntries.get(competition.id);
      const myTeamId = myEntry?.team_id;

      leaderboard.forEach((entry, idx) => {
        const isMyTeam = entry.team_id === myTeamId;
        const bgColor = isMyTeam ? '#2a2a00' : (idx % 2 === 0 ? '#111' : '#1a1a1a');
        const rankColor = idx === 0 ? 'gold' : idx === 1 ? 'silver' : idx === 2 ? '#cd7f32' : '#999';
        const currentMedal = idx === 0 ? ' 🥇' : idx === 1 ? ' 🥈' : idx === 2 ? ' 🥉' : '';

        tableHTML += `
          <tr style="background:${bgColor};">
            <td style="padding:8px; border:1px solid #444; color:${rankColor}; font-weight:bold; text-align:center;">${idx + 1}</td>
            <td style="padding:8px; border:1px solid #444;">
              ${isMyTeam ? '<strong>' : ''}
              ${escapeHtml(entry.team_name || 'Unknown')}${currentMedal}
              ${isMyTeam ? '</strong>' : ''}
            </td>
            <td style="padding:8px; border:1px solid #444; text-align:center;">${entry.member_count || 0}</td>
            <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.total_attacks)}</td>
            <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.total_gold_stolen)}</td>
            <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.avg_gold_per_attack)}</td>
          </tr>
        `;
      });
    } else {
      // Individual leaderboard
      tableHTML = `
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

      const storedAuth = auth.getStoredAuth();
      leaderboard.forEach((entry, idx) => {
        const isMe = entry.player_id === storedAuth?.id;
        const bgColor = isMe ? '#2a2a00' : (idx % 2 === 0 ? '#111' : '#1a1a1a');
        const rankColor = idx === 0 ? 'gold' : idx === 1 ? 'silver' : idx === 2 ? '#cd7f32' : '#999';
        const currentMedal = idx === 0 ? ' 🥇' : idx === 1 ? ' 🥈' : idx === 2 ? ' 🥉' : '';
        const permanentRibbons = entry.ribbons ? ` ${escapeHtml(entry.ribbons)}` : '';

        tableHTML += `
          <tr style="background:${bgColor};">
            <td style="padding:8px; border:1px solid #444; color:${rankColor}; font-weight:bold; text-align:center;">${idx + 1}</td>
            <td style="padding:8px; border:1px solid #444;">
              ${isMe ? '<strong>' : ''}
              ${escapeHtml(entry.player_name || 'Unknown')}${currentMedal}${permanentRibbons}
              ${isMe ? '</strong>' : ''}
              ${!entry.enabled ? ' <span style="color:#999;">(hidden)</span>' : ''}
            </td>
            <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.attacks_completed)}</td>
            <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.gold_stolen)}</td>
            <td style="padding:8px; border:1px solid #444; text-align:right;">${formatNum(entry.avg_gold_per_attack)}</td>
          </tr>
        `;
      });
    }

    tableHTML += '</tbody>';
    table.innerHTML = tableHTML;

    modal.appendChild(closeBtn);
    modal.appendChild(title);
    modal.appendChild(subtitle);
    modal.appendChild(table);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  }

  // UI panel creation
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
          <span style="color:gold; font-size:12px;">🏆 ${escapeHtml(competition.name)}</span>
          <button class="comp-expand-btn" data-comp-id="${escapeHtml(competition.id)}" style="margin-left:auto; padding:4px 12px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px; font-size:11px;">
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
    const hasGoldData = cached.goldStolenEra !== undefined;
    const lastUpdate = cached.lastUpdate ? new Date(cached.lastUpdate).toLocaleTimeString() : 'Never';

    // Check if data is stale (gold updated but attacks haven't been updated recently)
    const dataIsFresh = areCompStatsFresh(cached, 30);
    const goldIsNewer = hasGoldData && hasAttackData &&
                        cached.goldStolenTimestamp > (cached.attackMissionsTimestamp + 60000); // Gold is >1min newer

    // Calculate current progress using FRESH localStorage data
    const myEntry = myCompEntries.get(competition.id);
    let attacksDisplay = '';
    if (myEntry && myEntry.baseline_attack_missions !== null && myEntry.baseline_attack_missions !== undefined) {
      // Use cached (localStorage) attacks if available, otherwise use server data
      const currentAttacks = cached.attackMissions || myEntry.current_attack_missions || 0;
      const attacksGained = currentAttacks - myEntry.baseline_attack_missions;

      let warningText = '';
      if (!hasAttackData) {
        warningText = ' <span style="color:#f44;">⚠️ Visit rewards.php</span>';
      } else if (goldIsNewer) {
        warningText = ' <span style="color:#ff9800;">⚠️ Attack data needs update</span>';
      }

      attacksDisplay = `
        <div style="font-size:10px; color:#6f6;">
          ⚔️ Attacks: +${attacksGained} ${cached.attackMissions ? '📍' : ''}${warningText}
        </div>
        <div style="font-size:9px; color:#666; margin-top:4px;">
          Last captured: ${lastUpdate} ${dataIsFresh ? '✅' : '⚠️'}
        </div>
      `;
    }

    // Team info display
    let teamDisplay = '';
    if (competition.is_team_competition && myEntry) {
      if (myEntry.team_name) {
        teamDisplay = `
          <div style="margin-top:8px; padding:6px; background:#2a2a2a; border-radius:4px;">
            <div style="font-size:10px; color:#6cf;">
              👥 Team: <strong>${escapeHtml(myEntry.team_name)}</strong>
            </div>
          </div>
        `;
      } else {
        teamDisplay = `
          <div style="margin-top:8px; padding:6px; background:#2a2a2a; border-radius:4px;">
            <div style="font-size:10px; color:#f90; margin-bottom:4px;">
              ⚠️ No team selected
            </div>
            <button class="comp-select-team-btn" data-comp-id="${escapeHtml(competition.id)}" style="padding:4px 8px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px; font-size:10px;">
              Select Team
            </button>
          </div>
        `;
      }
    }

    // Scoring type display
    const scoringType = competition.scoring_type === 'gold' ? '💰 Gold' : '⚔️ Attacks';
    const scoringDisplay = `
      <div style="font-size:9px; color:#999; margin-top:4px;">
        Winner by: ${scoringType}
      </div>
    `;

    cell.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
        <div style="color:gold; font-weight:bold;">
          🏆 ${escapeHtml(competition.name)}
        </div>
        <button class="comp-minimize-btn" data-comp-id="${escapeHtml(competition.id)}" style="padding:2px 8px; cursor:pointer; background:#555; color:white; border:none; border-radius:3px; font-size:10px;">
          ▲ Hide
        </button>
      </div>
      <div style="color:#999; font-size:11px; margin-bottom:8px;">
        ${statusText}
        ${scoringDisplay}
      </div>
      <div style="display:flex; gap:8px; margin-bottom:8px;">
        <button class="comp-toggle-btn" data-comp-id="${escapeHtml(competition.id)}" style="flex:1; padding:6px; cursor:pointer; background:${isEnabled ? '#4CAF50' : '#f44336'}; color:white; border:none; border-radius:4px;">
          ${isEnabled ? '▶️ Tracking is ON' : '⏸️ Tracking is OFF'}
        </button>
        <button class="comp-update-btn" data-comp-id="${escapeHtml(competition.id)}" style="flex:1; padding:6px; cursor:pointer; background:#FF9800; color:white; border:none; border-radius:4px;">
          🔄 Update Stats
        </button>
        <button class="comp-leaderboard-btn" data-comp-id="${escapeHtml(competition.id)}" style="flex:1; padding:6px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px;">
          📊 Leaderboard
        </button>
      </div>
      ${attacksDisplay}
      ${teamDisplay}
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
      await toggleCompParticipation(competition, newState);
      location.reload();
    });

    const updateBtn = cell.querySelector(".comp-update-btn");
    updateBtn?.addEventListener("click", () => {
      // Capture gold data from current page (base.php) before leaving
      const goldStolen = extractGoldStolen();
      const now = Date.now();
      if (goldStolen !== null) {
        const cached = getCompStats(competition.id);
        cached.goldStolenEra = goldStolen;
        cached.goldStolenTimestamp = now;
        cached.lastUpdate = now;
        saveCompStats(competition.id, cached);
      }

      // Go to rewards.php to capture attack missions (within ~1 second)
      window.location.href = "rewards.php";
    });

    const leaderboardBtn = cell.querySelector(".comp-leaderboard-btn");
    leaderboardBtn?.addEventListener("click", async () => {
      // Force a fresh submission before showing leaderboard to ensure latest data is shown
      const settings = getCompSettings(competition.id);
      if (settings.enabled !== false) {
        const cached = getCompStats(competition.id);
        if (cached.attackMissions && areCompStatsFresh(cached, 30)) {
          await submitCompStats(competition);
          const submitKey = `${COMP_LAST_SUBMIT_PREFIX}_${competition.id}`;
          localStorage.setItem(submitKey, Date.now().toString());
        }
      }
      await showCompLeaderboard(competition);
    });

    const selectTeamBtn = cell.querySelector(".comp-select-team-btn");
    selectTeamBtn?.addEventListener("click", async () => {
      const teams = await getAvailableCompTeams(competition.id);
      if (!teams || teams.length === 0) {
        alert("No teams available for this competition");
        return;
      }

      // Show team selection dialog
      const teamOptions = teams.map((team, idx) =>
        `${idx + 1}. ${team.name} (${team.member_count || 0} members)`
      ).join('\n');

      const selection = prompt(
        `Select a team for ${competition.name}:\n\n${teamOptions}\n\nEnter team number:`,
        "1"
      );

      if (selection) {
        const teamIdx = parseInt(selection) - 1;
        if (teamIdx >= 0 && teamIdx < teams.length) {
          const success = await joinCompTeam(competition.id, teams[teamIdx].id);
          if (success) {
            alert(`Successfully joined ${teams[teamIdx].name}!`);
            location.reload();
          } else {
            alert("Failed to join team. Please try again.");
          }
        }
      }
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

  // ==================== RECON DATA COLLECTOR ====================

  function getTableByHeader(text) {
    return document.evaluate(
      `.//th[contains(., "${text}")]`,
      document,
      null,
      XPathResult.FIRST_ORDERED_NODE_TYPE,
      null
    ).singleNodeValue?.closest("table") || null;
  }

  // Parse Shared Recon Info table (alliance-shared recon data)
  // Add age column to Shared Recon Info table for easy visibility
  function enhanceSharedReconInfoTable() {
    try {
      // Find "Shared Recon Info" header
      const header = [...document.querySelectorAll("th, td")]
        .find(el => el.textContent.includes("Shared Recon Info"));

      if (!header) return;

      const table = header.closest("table");
      if (!table) return;

      // Get current KoC Server Time for age calculation
      const now = new Date(getKoCServerTimeUTC());

      // Find or create the header row with column names
      let headerRow = null;
      const rows = table.querySelectorAll("tr");
      rows.forEach(row => {
        const cells = row.querySelectorAll("td");
        if (cells.length >= 3) {
          const firstCell = cells[0]?.innerText.trim().toLowerCase();
          // Check if this is the header row (contains "Latest Recon")
          if (firstCell.includes("latest recon")) {
            headerRow = row;
          }
        }
      });

      // Add "Age" header if we found the header row
      if (headerRow) {
        const ageHeader = document.createElement("td");
        ageHeader.style.cssText = "font-weight: bold; text-align: center; padding: 5px;";
        ageHeader.textContent = "Age";
        headerRow.appendChild(ageHeader);
      }

      // Process each data row and add age
      rows.forEach(row => {
        const cells = row.querySelectorAll("td");
        if (cells.length < 3) return;

        const statName = cells[0]?.innerText.trim().toLowerCase();
        const timestamp = cells[2]?.innerText.trim();

        // Skip header row and rows without timestamps
        if (!timestamp || statName.includes("latest recon")) return;

        // Parse timestamp and calculate age
        try {
          const parts = timestamp.match(/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
          if (!parts) return;

          const year = parseInt(parts[1]);
          const month = parseInt(parts[2]) - 1;
          const day = parseInt(parts[3]);
          const hour = parseInt(parts[4]);
          const minute = parseInt(parts[5]);
          const second = parseInt(parts[6]);

          const offset = kocOffsetHours(year, month, day); // 0 for UTC dates
          const reconTime = new Date(Date.UTC(year, month, day, hour + offset, minute, second));

          // Calculate age
          const ageMs = now - reconTime;
          const ageMinutes = Math.floor(ageMs / 60000);
          const ageHours = Math.floor(ageMs / 3600000);
          const ageDays = Math.floor(ageMs / 86400000);

          let ageText = "";
          let ageColor = "#6f6"; // Green for fresh

          if (ageMinutes < 1) {
            ageText = "just now";
            ageColor = "#6f6";
          } else if (ageMinutes < 60) {
            ageText = `${ageMinutes}m ago`;
            ageColor = "#6f6";
          } else if (ageHours < 24) {
            ageText = `${ageHours}h ago`;
            ageColor = ageHours < 6 ? "#6f6" : "#ff6"; // Yellow after 6h
          } else {
            ageText = `${ageDays}d ago`;
            ageColor = ageDays < 3 ? "#f90" : "#f44"; // Orange then red
          }

          // Add age cell
          const ageCell = document.createElement("td");
          ageCell.style.cssText = `color: ${ageColor}; font-weight: bold; text-align: center; padding: 5px;`;
          ageCell.textContent = ageText;
          row.appendChild(ageCell);
        } catch (e) {
          console.warn("⚠️ Failed to calculate age for timestamp:", timestamp, e);
        }
      });

      debugLog("✅ Enhanced Shared Recon Info table with age column");
    } catch (err) {
      console.warn("⚠️ Failed to enhance Shared Recon Info table:", err);
    }
  }

  async function collectFromIntelDetailPage() {
    // Fresh recon page - collect 8 combat stats from Military Stats table

    // Get player ID from stats.php link
    let id = null;
    let link = null;
    const allStatsLinks = document.querySelectorAll('a[href*="stats.php?id="]');

    for (const a of allStatsLinks) {
      // Skip if it's just "stats.php?id=" with no actual ID
      if (!a.href.match(/id=\d+/)) continue;
      // Found a valid player stats link
      link = a;
      break;
    }

    const match = link?.href.match(/id=(\d+)/);
    id = match ? match[1] : null;

    if (!id) {
      debugLog("⚠️ Recon: Could not find player ID on inteldetail page");
      return;
    }

    // Check for Invalid User ID error
    if (document.body.textContent.includes("Invalid User ID")) {
      console.warn(`⚠️ Invalid User ID detected for player ${id} - marking as deleted`);
      await auth.apiCall('recon', `players/${id}/mark-inactive`, {
        status: "deleted",
        error: "Invalid User ID"
      });
      return;
    }

    // Check for failed recon - abort if spy was caught
    const bodyText = document.body.textContent;
    const reconFailed = bodyText.includes("your spy escapes to camp") ||
                        bodyText.includes("sounds the alarm") ||
                        bodyText.includes("will need a more powerful force") ||
                        bodyText.includes("one of the sentries spots");

    if (reconFailed) {
      debugLog(`⚠️ Recon failed for player ${id} - spy was caught, aborting data collection`);
      return;
    }

    const stats = {};
    const now = getKoCServerTimeUTC();

    // === PARSE PLAYER NAME ===
    const statsIdMatch = bodyText.match(/([^\s]+)\s+StatsID\s*=\s*(\d+)/);
    if (statsIdMatch) {
      const parsedName = statsIdMatch[1].trim();
      const parsedId = statsIdMatch[2].trim();

      if (parsedId === id) {
        stats.name = parsedName;
        stats.nameTime = now;
        debugLog(`✅ Parsed player name: ${parsedName}`);
      }
    }

    // Fallback: try page title
    if (!stats.name) {
      const titleMatch = document.title.match(/^([^-]+?)\s*-\s*Kingdoms/i);
      if (titleMatch) {
        stats.name = titleMatch[1].trim();
        stats.nameTime = now;
      }
    }

    // === PARSE RANK AND RACE FROM INFO TABLE ===
    const infoTable = getTableByHeader("Information");
    if (infoTable) {
      const rows = infoTable.querySelectorAll("tr");
      for (const row of rows) {
        const cells = row.querySelectorAll("td");
        if (cells.length >= 2) {
          const label = cells[0]?.innerText.trim().toLowerCase();
          const value = cells[1]?.innerText.trim();

          // Match "Rank:" exactly (not "Previous Era Rank:" or "Highest Rank:")
          if (label === "rank:" && value) {
            stats.rank = value;
            stats.rankTime = now;
          } else if (label === "race:" && value) {
            // Extract just the race name (before the " | " flavor text)
            const raceName = value.split('|')[0].trim();
            stats.race = raceName;
            stats.raceTime = now;
          }
        }
      }
    }

    // === COLLECT 8 STATS FROM MILITARY STATS TABLE ===
    // Find the Military Stats table
    const tables = document.querySelectorAll('table.table_lines');
    let militaryStatsTable = null;

    for (const table of tables) {
      const header = table.querySelector('th');
      if (header && header.textContent.trim() === 'Military Stats') {
        militaryStatsTable = table;
        break;
      }
    }

    if (militaryStatsTable) {
      const rows = militaryStatsTable.querySelectorAll('tr');

      // Stat name mapping
      const statMapping = {
        'Strike Action': 'strikeAction',
        'Defensive Action': 'defensiveAction',
        'Spy Rating': 'spyRating',
        'Sentry Rating': 'sentryRating',
        'Poison Rating': 'poisonRating',
        'Antidote Rating': 'antidoteRating',
        'Theft Rating': 'theftRating',
        'Vigilance Rating': 'vigilanceRating'
      };

      for (const row of rows) {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 2) {
          const statName = cells[0]?.innerText.trim();
          const statValue = cells[1]?.innerText.trim();

          // Check if this is one of our 8 combat stats
          const fieldName = statMapping[statName];
          if (fieldName && statValue && statValue !== '???') {
            // Parse value (remove commas)
            const value = parseInt(statValue.replace(/,/g, ''), 10);
            if (!isNaN(value)) {
              stats[fieldName] = value;
              stats[`${fieldName}Time`] = now;
              debugLog(`✅ Parsed ${statName}: ${value.toLocaleString()}`);
            }
          } else if (fieldName && statValue === '???') {
            debugLog(`ℹ️ Skipping ${statName}: value is ???`);
          }
        }
      }
    } else {
      debugLog("⚠️ Military Stats table not found on page");
    }

    // Count collected stats
    const statCount = Object.keys(stats).filter(key => !key.endsWith('Time')).length;

    if (statCount === 0) {
      debugLog(`ℹ️ No fresh recon data collected for player ${id}`);
      return;
    }

    // Save to localStorage and send to API
    updatePlayerInfo(id, stats, 'recon');
    debugLog(`📊 Fresh recon collected for ${id}: ${statCount} combat stats`);

    // Fill any ??? values with the alliance's last known data
    if (featureEnabled('recon-display')) await fillMilitaryStatsFromAPI(id);
  }

  // Fill ??? values in Military Stats table with last known data from API
  async function fillMilitaryStatsFromAPI(playerId) {
    try {
      // Fetch player data from API
      const playerData = await auth.apiCall('read', `players/${playerId}`);
      if (!playerData || playerData.error) {
        debugLog("⚠️ No API data available for player", playerId);
        return;
      }

      debugLog("🌐 Fetching last known stats from API for ??? values");

      // Find the Military Stats table
      const tables = document.querySelectorAll('table.table_lines');
      let militaryStatsTable = null;

      for (const table of tables) {
        const header = table.querySelector('th');
        if (header && header.textContent.trim() === 'Military Stats') {
          militaryStatsTable = table;
          break;
        }
      }

      if (!militaryStatsTable) return;

      // Map API fields to display names
      const statMapping = {
        strikeAction: { display: "Strike Action", timeField: "strikeActionTime" },
        defensiveAction: { display: "Defensive Action", timeField: "defensiveActionTime" },
        spyRating: { display: "Spy Rating", timeField: "spyRatingTime" },
        sentryRating: { display: "Sentry Rating", timeField: "sentryRatingTime" },
        poisonRating: { display: "Poison Rating", timeField: "poisonRatingTime" },
        antidoteRating: { display: "Antidote Rating", timeField: "antidoteRatingTime" },
        theftRating: { display: "Theft Rating", timeField: "theftRatingTime" },
        vigilanceRating: { display: "Vigilance Rating", timeField: "vigilanceRatingTime" }
      };

      let updatedCount = 0;

      // Process each row in the table
      const rows = militaryStatsTable.querySelectorAll("tr");
      rows.forEach(row => {
        const cells = row.querySelectorAll("td");
        if (cells.length < 2) return;

        const statName = cells[0]?.innerText.trim();
        const currentValue = cells[1]?.innerText.trim();

        // Find matching stat in API data
        for (const [key, mapping] of Object.entries(statMapping)) {
          if (statName === mapping.display) {
            const apiValue = playerData[key];
            const apiTime = playerData[mapping.timeField];

            // If recon shows "???" but we have API data, replace it
            if (currentValue === "???" && apiValue && apiTime) {
              // Calculate age of data
              const date = new Date(apiTime);
              const now = new Date(getKoCServerTimeUTC());
              const ageMs = now - date;
              const ageMinutes = Math.floor(ageMs / 60000);
              const ageHours = Math.floor(ageMs / 3600000);
              const ageDays = Math.floor(ageMs / 86400000);

              let ageText = "";
              if (ageMinutes < 1) {
                ageText = "just now";
              } else if (ageMinutes < 60) {
                ageText = `${ageMinutes}m ago`;
              } else if (ageHours < 24) {
                ageText = `${ageHours}h ago`;
              } else {
                ageText = `${ageDays}d ago`;
              }

              // Update value cell with last known + age
              cells[1].innerHTML = `<font color="#99f">${apiValue.toLocaleString()} <font size="1">(${ageText})</font></font>`;
              updatedCount++;
            }
            break;
          }
        }
      });

      if (updatedCount > 0) {
        debugLog(`✅ Filled ${updatedCount} "???" values with last known data from API`);
      }
    } catch (err) {
      console.warn("⚠️ Failed to fill Military Stats from API:", err);
    }
  }

  // Fill Shared Recon Info table with data from API for "???" values (stats.php only)
  async function fillSharedReconInfoFromAPI(playerId) {
    try {
      // Fetch player data from API
      const playerData = await auth.apiCall('read', `players/${playerId}`);
      if (!playerData || playerData.error) {
        debugLog("⚠️ No API data available for player", playerId, playerData?.error);
        return;
      }

      debugLog("🌐 Recon fallback loaded from API:", playerData);

      // Find "Shared Recon Info" table
      const header = [...document.querySelectorAll("th, td")]
        .find(el => el.textContent.includes("Shared Recon Info"));

      if (!header) return;

      const table = header.closest("table");
      if (!table) return;

      // Map API fields to display names
      const statMapping = {
        strikeAction: { display: "strike action", timeField: "strikeActionTime" },
        defensiveAction: { display: "defensive action", timeField: "defensiveActionTime" },
        spyRating: { display: "spy rating", timeField: "spyRatingTime" },
        sentryRating: { display: "sentry rating", timeField: "sentryRatingTime" },
        poisonRating: { display: "poison rating", timeField: "poisonRatingTime" },
        antidoteRating: { display: "antidote rating", timeField: "antidoteRatingTime" },
        theftRating: { display: "theft rating", timeField: "theftRatingTime" },
        vigilanceRating: { display: "vigilance rating", timeField: "vigilanceRatingTime" }
      };

      let updatedCount = 0;

      // Process each row in the table
      const rows = table.querySelectorAll("tr");
      rows.forEach(row => {
        const cells = row.querySelectorAll("td");
        if (cells.length < 3) return;

        const statName = cells[0]?.innerText.trim().toLowerCase();
        const currentValue = cells[1]?.innerText.trim();
        const timestampCell = cells[2];

        // Find matching stat in API data
        for (const [key, mapping] of Object.entries(statMapping)) {
          if (statName.includes(mapping.display)) {
            const apiValue = playerData[key];
            const apiTime = playerData[mapping.timeField];

            // If shared recon shows "??" or "???" but we have API data, replace it
            if ((currentValue === "??" || currentValue === "???") && apiValue && apiTime) {
              // Update value cell
              cells[1].innerText = apiValue.toLocaleString();
              cells[1].style.color = "#99f"; // Blue for API data (not fresh recon)

              // Update timestamp cell - convert UTC from API to KoC Server Time for display
              const formatted = convertUTCToKoCServerTime(apiTime);
              timestampCell.innerText = formatted;
              timestampCell.style.color = "#99f"; // Blue for API data

              // Create Date object from apiTime for age calculation
              const date = new Date(apiTime);

              // Update age cell if it exists
              const ageCell = cells[3];
              if (ageCell) {
                const now = new Date(getKoCServerTimeUTC());
                const ageMs = now - date;
                const ageMinutes = Math.floor(ageMs / 60000);
                const ageHours = Math.floor(ageMs / 3600000);
                const ageDays = Math.floor(ageMs / 86400000);

                let ageText = "";
                let ageColor = "#99f"; // Blue for API data

                if (ageMinutes < 1) {
                  ageText = "just now";
                } else if (ageMinutes < 60) {
                  ageText = `${ageMinutes}m ago`;
                } else if (ageHours < 24) {
                  ageText = `${ageHours}h ago`;
                } else {
                  ageText = `${ageDays}d ago`;
                }

                ageCell.innerText = ageText;
                ageCell.style.color = ageColor;
              }

              updatedCount++;
            }
            break;
          }
        }
      });

      if (updatedCount > 0) {
        debugLog(`✅ Filled ${updatedCount} "???" values from API data`);
      }
    } catch (err) {
      console.warn("⚠️ Failed to fill Shared Recon Info from API:", err);
    }
  }

  // ==================== RECON AGE FORMATTER ====================

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

  // ==================== SAFE.PHP ATTACK ALTERNATIVE TABLE ====================

  /**
   * Add a table showing what stats would be if XP was spent attacking instead of upgrading tech
   * Only runs on safe.php when the tech upgrade table exists
   */
  function addAttackAlternativeTable() {
    const TABLE_ID = 'koc-attack-alternative-table';
    if (document.getElementById(TABLE_ID)) return; // Prevent duplicates

    // Find the "Stats After Upgrading Tech" table
    const techStatsHeader = [...document.querySelectorAll('th')]
      .find(th => th.textContent.includes('Stats After Upgrading Tech'));

    if (!techStatsHeader) {
      debugLog('[SafePage] No tech upgrade stats table found');
      return;
    }

    const techStatsTable = techStatsHeader.closest('table');
    if (!techStatsTable) return;

    // Get tech XP cost from the Research button (e.g., "1,850 Experience")
    const techButton = document.querySelector('input[value*="Experience"][name="upgradetech"], form[name="upgradetech"] input[type="submit"]');
    if (!techButton) {
      debugLog('[SafePage] No tech upgrade button found');
      return;
    }

    const xpMatch = techButton.value.match(/([\d,]+)\s*Experience/);
    if (!xpMatch) {
      debugLog('[SafePage] Could not parse XP cost from button:', techButton.value);
      return;
    }

    const techXpCost = parseInt(xpMatch[1].replace(/,/g, ''), 10);
    debugLog('[SafePage] Tech XP cost:', techXpCost);

    // Get current stats from Military Effectiveness table
    const currentStats = {};
    const meHeader = [...document.querySelectorAll('th')]
      .find(th => th.textContent.includes('Military Effectiveness'));

    if (meHeader) {
      const meTable = meHeader.closest('table');
      if (meTable) {
        meTable.querySelectorAll('tr').forEach(row => {
          const cells = row.querySelectorAll('td');
          if (cells.length >= 2) {
            const label = cells[0].textContent.trim().toLowerCase();
            const valueText = cells[1].textContent.trim().replace(/,/g, '');
            const value = parseInt(valueText, 10);

            if (label.includes('strike')) currentStats.attack = value;
            else if (label.includes('defense')) currentStats.defense = value;
            else if (label.includes('spy')) currentStats.spy = value;
            else if (label.includes('sentry')) currentStats.sentry = value;
            else if (label.includes('poison')) currentStats.poison = value;
            else if (label.includes('antidote')) currentStats.antidote = value;
            else if (label.includes('theft')) currentStats.theft = value;
            else if (label.includes('vigilance')) currentStats.vigilance = value;
          }
        });
      }
    }

    debugLog('[SafePage] Current stats:', currentStats);

    // Inject the flat tech-upgrade % into the "Stats After Upgrading Tech" header
    // (the upgrade raises every stat by the same ratio). Runs before any early-return
    // so it shows even when the projection below can't be built.
    augmentTechHeader(techStatsHeader, techStatsTable, currentStats);

    // Distribution source: prefer the player's armory SPEND preferences (how they'd
    // actually spend attack-gold); fall back to current-holdings TIV if not cached yet.
    const spendData = SafeStorage.get('KoC_SpendPrefs', null);
    const tivData = SafeStorage.get('KoC_TivDistribution', null);
    const distData = (spendData && spendData.distribution) ? spendData : tivData;
    const usingSpendPrefs = !!(spendData && spendData.distribution);
    if (!distData || !distData.distribution) {
      // Show warning table instead
      const warningTable = document.createElement('table');
      warningTable.id = TABLE_ID;
      warningTable.className = 'table_lines';
      warningTable.style.cssText = 'width: 100%; border: 0; margin-top: 4px;';
      warningTable.innerHTML = `
        <tr>
          <th colspan="2" style="color: #ffcc00;">Stats If You Attacked Instead</th>
        </tr>
        <tr>
          <td colspan="2" align="center" style="color: #ff6666; padding: 10px;">
            Visit the <a href="armory.php" style="color: #66ccff;">Armory</a> to calibrate TIV distribution
          </td>
        </tr>
      `;
      techStatsTable.parentNode.insertBefore(warningTable, techStatsTable.nextSibling);
      debugLog('[SafePage] No TIV distribution found - showing warning');
      return;
    }

    // Same per-stat multiplier as the armory's gold/pt panel (live readings are
    // remembered between visits; pins apply too)
    const gppNow = gppResolve();
    const hasMultipliers = RESHUF_CATS.some(cat => gppNow[cat].mult > 0);

    if (!hasMultipliers) {
      // Show warning table instead
      const warningTable = document.createElement('table');
      warningTable.id = TABLE_ID;
      warningTable.className = 'table_lines';
      warningTable.style.cssText = 'width: 100%; border: 0; margin-top: 4px;';
      warningTable.innerHTML = `
        <tr>
          <th colspan="2" style="color: #ffcc00;">Stats If You Attacked Instead</th>
        </tr>
        <tr>
          <td colspan="2" align="center" style="color: #ff6666; padding: 10px;">
            Visit the <a href="armory.php" style="color: #66ccff;">Armory</a> once to read your gold per stat point
          </td>
        </tr>
      `;
      techStatsTable.parentNode.insertBefore(warningTable, techStatsTable.nextSibling);
      debugLog('[SafePage] No gold/pt readings yet - showing warning');
      return;
    }

    // Best weapon prices for gold→stat calculation
    const bestWeaponPrices = {
      attack: 450000,    // Chariot
      defense: 450000,   // Ebony Platemail
      spy: 1000000,      // Nunchaku
      sentry: 1000000,   // Lookout Tower
      poison: 1000000,   // Plaguebringer Scythe
      antidote: 1000000, // Serpentbane Arbalest
      theft: 1000000,    // Ethereal Grasp
      vigilance: 1000000 // Adamantine Bastion
    };

    // Strength of each best weapon above (parallels bestWeaponPrices). The
    // multiplier is stat per (quantity × strength) — see gppResolve — so the
    // projected gain MUST include the weapon's strength.
    const bestWeaponStrength = {
      attack: 600,     // Chariot
      defense: 600,    // Ebony Platemail
      spy: 1000,       // Nunchaku
      sentry: 1000,    // Lookout Tower
      poison: 1000,    // Plaguebringer Scythe
      antidote: 1000,  // Serpentbane Arbalest
      theft: 1000,     // Ethereal Grasp
      vigilance: 1000  // Adamantine Bastion
    };

    // Calculate attacks possible from tech XP
    const attacks = calculateXPTradeAttacks(techXpCost, 0);
    debugLog('[SafePage] Attacks from XP:', attacks);

    // Get average gold per attack
    const avgGold = SafeStorage.get('xpTool_avgGold', 0);
    if (avgGold <= 0) {
      const warningTable = document.createElement('table');
      warningTable.id = TABLE_ID;
      warningTable.className = 'table_lines';
      warningTable.style.cssText = 'width: 100%; border: 0; margin-top: 4px;';
      warningTable.innerHTML = `
        <tr>
          <th colspan="2" style="color: #ffcc00;">Stats If You Attacked Instead</th>
        </tr>
        <tr>
          <td colspan="2" align="center" style="color: #ff6666; padding: 10px;">
            Visit <a href="attacklog.php" style="color: #66ccff;">Attack Log</a> to calibrate average gold per attack
          </td>
        </tr>
      `;
      techStatsTable.parentNode.insertBefore(warningTable, techStatsTable.nextSibling);
      debugLog('[SafePage] No avg gold data - showing warning');
      return;
    }

    // Total gold from attacks
    const totalGold = attacks * avgGold;
    debugLog('[SafePage] Total gold:', totalGold);

    // Calculate projected stats
    const projectedStats = {};
    const distribution = distData.distribution;

    const statLabels = {
      attack: 'Strike',
      defense: 'Defense',
      spy: 'Spy',
      sentry: 'Sentry',
      poison: 'Poison',
      antidote: 'Antidote',
      theft: 'Theft',
      vigilance: 'Vigilance'
    };

    for (const cat of Object.keys(statLabels)) {
      const goldForStat = totalGold * (distribution[cat] || 0);
      // gppResolve's multiplier — the one the armory shows; a stat with none stays 0.
      const multiplier = gppNow[cat].mult || 0;
      const weaponPrice = bestWeaponPrices[cat];
      const weaponStrength = bestWeaponStrength[cat] || 1;

      // weapons bought = goldForStat / weaponPrice; each weapon adds (strength × multiplier)
      // stat, since multiplier is stat per (qty × strength).
      const statGained = multiplier > 0 ? Math.floor(goldForStat / weaponPrice * weaponStrength * multiplier) : 0;
      projectedStats[cat] = (currentStats[cat] || 0) + statGained;

      debugLog(`[SafePage] ${cat}: gold=${goldForStat.toFixed(0)}, mult=${multiplier}, str=${weaponStrength}, price=${weaponPrice}, gained=${statGained}`);
    }

    // Format gold for display
    function formatGoldShort(num) {
      if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B';
      if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
      if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
      return num.toLocaleString();
    }

    // Build the table
    const newTable = document.createElement('table');
    newTable.id = TABLE_ID;
    newTable.className = 'table_lines';
    newTable.style.cssText = 'width: 100%; border: 0; margin-top: 4px;';
    newTable.cellSpacing = '0';
    newTable.cellPadding = '6';

    // Cell = "Label (projected · ▲ %)" with a tooltip explaining the spend + gain.
    const src = usingSpendPrefs ? 'your armory preferences' : 'your current weapon mix';
    const cell = (cat) => {
      const label = statLabels[cat];
      const curV = currentStats[cat] || 0;
      const projV = projectedStats[cat] || 0;
      const gain = projV - curV;
      const pct = curV > 0 ? (gain / curV * 100) : 0;
      const pctTxt = pct >= 10 ? pct.toFixed(0) : pct.toFixed(1);
      const badge = gain > 0
        ? `<span style="color:#9f9;">▲ ${pctTxt}%</span>`
        : `<span style="color:#888;">—</span>`;
      const goldForStat = totalGold * (distribution[cat] || 0);
      const spendPct = Math.round((distribution[cat] || 0) * 100);
      const tip = gain > 0
        ? `Using ${src}, ${spendPct}% of that gold (~${formatGoldShort(goldForStat)}) buys ${label} weapons — raising ${label} by ${pctTxt}% (+${gain.toLocaleString()}).`
        : `${src.charAt(0).toUpperCase() + src.slice(1)} allocate ${spendPct}% here, so attacking adds nothing to ${label}.`;
      return `<span title="${tip.replace(/"/g, '&quot;')}">${label} (${projV.toLocaleString()} · ${badge})</span>`;
    };
    const headerTip = `If you traded this tech upgrade's experience for turns instead of upgrading, you could make ${attacks.toLocaleString()} attacks. At your current average of ${formatGoldShort(avgGold)} gold per attack, that's about ${formatGoldShort(totalGold)} to spend — split below by ${src}.`;
    newTable.innerHTML = `
      <tr>
        <th colspan="2" style="color: #66ff66;" title="${headerTip.replace(/"/g, '&quot;')}">
          Stats If You Attacked Instead (${attacks.toLocaleString()} atks × ${formatGoldShort(avgGold)} = ${formatGoldShort(totalGold)})
        </th>
      </tr>
      <tr>
        <td align="center" style="color: #66ff66;">${cell('attack')}</td>
        <td align="center" style="color: #66ff66;">${cell('defense')}</td>
      </tr>
      <tr>
        <td align="center" style="color: #66ff66;">${cell('spy')}</td>
        <td align="center" style="color: #66ff66;">${cell('sentry')}</td>
      </tr>
      <tr>
        <td align="center" style="color: #66ff66;">${cell('poison')}</td>
        <td align="center" style="color: #66ff66;">${cell('antidote')}</td>
      </tr>
      <tr>
        <td align="center" style="color: #66ff66;">${cell('theft')}</td>
        <td align="center" style="color: #66ff66;">${cell('vigilance')}</td>
      </tr>
    `;

    // Insert after the tech stats table
    techStatsTable.parentNode.insertBefore(newTable, techStatsTable.nextSibling);
    debugLog('[SafePage] Attack alternative table injected');
  }

  // Append the tech-upgrade % to the "Stats After Upgrading Tech" header. The upgrade
  // raises every stat by the same ratio (new tech bonus ÷ current), so we show one %.
  function augmentTechHeader(headerTh, techTable, currentStats) {
    try {
      if (!headerTh || headerTh.dataset.kocTechPct || !techTable) return;
      const nameKey = { strike:'attack', defense:'defense', spy:'spy', sentry:'sentry', poison:'poison', antidote:'antidote', theft:'theft', vigilance:'vigilance' };
      let pct = null, m;
      const re = /([A-Za-z]+)\s*\(([\d,]+)\)/g, txt = techTable.textContent;
      while ((m = re.exec(txt))) {
        const key = nameKey[m[1].toLowerCase()]; if (!key) continue;
        const after = parseInt(m[2].replace(/,/g, ''), 10), cur = currentStats[key];
        if (cur && after && after > cur) { pct = (after / cur - 1) * 100; break; }
      }
      if (pct == null) return;
      const span = document.createElement('span');
      span.style.cssText = 'color:#66ff66; font-weight:normal;';
      span.title = 'This tech upgrade multiplies every stat by the same ratio (new tech bonus ÷ current stat).';
      span.textContent = ` (every stat ▲ ${pct.toFixed(1)}%)`;
      headerTh.appendChild(span);
      headerTh.dataset.kocTechPct = '1';
    } catch (e) { debugLog('[SafePage] augmentTechHeader failed:', e); }
  }

  // ==================== TECH LEVEL PROJECTOR ====================
  // The game's "Stats After Upgrading Tech X To Y" table only shows the very next
  // level. Add a level picker so any future tech can be selected — the table then
  // shows the multiplier and projected stats at that level, plus the EXP to get there.
  //
  // Static Technological Development ladder (level → cumulative EXP + multiplier),
  // from the game's official User Guide.
  const TECH_LADDER = [
    { level: 0,  name: 'None',           cumExp: 0,      mult: 1.00 },
    { level: 1,  name: 'Spear',          cumExp: 300,    mult: 1.05 },
    { level: 2,  name: 'Fire',           cumExp: 650,    mult: 1.10 },
    { level: 3,  name: 'Oven',           cumExp: 1050,   mult: 1.16 },
    { level: 4,  name: 'Pottery',        cumExp: 1510,   mult: 1.22 },
    { level: 5,  name: 'Domestication',  cumExp: 2030,   mult: 1.28 },
    { level: 6,  name: 'Copper',         cumExp: 2630,   mult: 1.34 },
    { level: 7,  name: 'Wheel',          cumExp: 3320,   mult: 1.41 },
    { level: 8,  name: 'Writing',        cumExp: 4120,   mult: 1.48 },
    { level: 9,  name: 'Bronze',         cumExp: 5040,   mult: 1.55 },
    { level: 10, name: 'Irrigation',     cumExp: 6100,   mult: 1.63 },
    { level: 11, name: 'Woodworking',    cumExp: 7310,   mult: 1.71 },
    { level: 12, name: 'Archery',        cumExp: 8710,   mult: 1.80 },
    { level: 13, name: 'Salt',           cumExp: 10320,  mult: 1.89 },
    { level: 14, name: 'Sailing',        cumExp: 12170,  mult: 1.98 },
    { level: 15, name: 'Masonry',        cumExp: 14290,  mult: 2.08 },
    { level: 16, name: 'Forum',          cumExp: 16730,  mult: 2.18 },
    { level: 17, name: 'Furnace',        cumExp: 19540,  mult: 2.29 },
    { level: 18, name: 'Ironworking',    cumExp: 22770,  mult: 2.41 },
    { level: 19, name: 'Library',        cumExp: 26480,  mult: 2.53 },
    { level: 20, name: 'Medicine',       cumExp: 30750,  mult: 2.65 },
    { level: 21, name: 'Timekeeping',    cumExp: 35660,  mult: 2.79 },
    { level: 22, name: 'Market',         cumExp: 41310,  mult: 2.93 },
    { level: 23, name: 'Monastery',      cumExp: 47800,  mult: 3.07 },
    { level: 24, name: 'Windmill',       cumExp: 55270,  mult: 3.23 },
    { level: 25, name: 'Printing',       cumExp: 63860,  mult: 3.39 },
    { level: 26, name: 'Civil Code',     cumExp: 73740,  mult: 3.56 },
    { level: 27, name: 'Shipbuilding',   cumExp: 85100,  mult: 3.73 },
    { level: 28, name: 'Astronomy',      cumExp: 98160,  mult: 3.92 },
    { level: 29, name: 'Chemistry',      cumExp: 113180, mult: 4.12 },
    { level: 30, name: 'Gunpowder',      cumExp: 130450, mult: 4.32 },
    { level: 31, name: 'Economics',      cumExp: 150310, mult: 4.54 },
    { level: 32, name: 'Cotton Gin',     cumExp: 173150, mult: 4.76 },
    { level: 33, name: 'Ballistics',     cumExp: 199420, mult: 5.00 },
    { level: 34, name: 'Metallurgy',     cumExp: 229630, mult: 5.25 },
    { level: 35, name: 'Laboratory',     cumExp: 264370, mult: 5.52 },
    { level: 36, name: 'Mechanics',      cumExp: 304320, mult: 5.79 },
    { level: 37, name: 'Textiles',       cumExp: 350270, mult: 6.08 },
    { level: 38, name: 'Thermodynamics', cumExp: 403110, mult: 6.39 },
    { level: 39, name: 'Steam Engine',   cumExp: 463870, mult: 6.70 },
    { level: 40, name: 'Assembly Line',  cumExp: 533750, mult: 7.04 },
    { level: 41, name: 'Electricity',    cumExp: 614110, mult: 7.39 },
    { level: 42, name: 'Cooking',        cumExp: 706520, mult: 7.76 },
    { level: 43, name: 'Obi Bon Kenobi', cumExp: 812790, mult: 8.15 }
  ];

  function enhanceTechLevelPicker() {
    const headerTh = [...document.querySelectorAll('th')]
      .find(th => th.textContent.includes('Stats After Upgrading Tech'));
    if (!headerTh || headerTh.dataset.kocTechPicker) return;
    const techTable = headerTh.closest('table');
    if (!techTable) return;

    // Current + next tech names sit in <font class="stattech"> inside the header
    const nameFonts = headerTh.querySelectorAll('font.stattech');
    const curName = nameFonts[0]?.textContent.trim().toLowerCase();
    const nextName = nameFonts[1]?.textContent.trim().toLowerCase();
    const nextIdx = TECH_LADDER.findIndex(t => t.name.toLowerCase() === nextName);
    const curIdx = nextIdx > 0 ? nextIdx - 1
      : TECH_LADDER.findIndex(t => t.name.toLowerCase() === curName);
    if (curIdx < 0 || curIdx >= TECH_LADDER.length - 1) {
      debugLog('[TechProjector] Unknown tech names:', curName, nextName);
      return;
    }
    const cur = TECH_LADDER[curIdx];
    const next = TECH_LADDER[curIdx + 1];

    // Snapshot the stat cells. The displayed numbers are the game's EXACT values
    // for the next level, so a target projection is just: shown × (target ÷ next
    // multiplier) — no rescrape needed, and selecting the next level restores the
    // native numbers verbatim.
    const statNames = /^(strike|defense|spy|sentry|poison|antidote|theft|vigilance)$/i;
    const statCells = [...techTable.querySelectorAll('td')]
      .filter(td => /[A-Za-z]+\s*\([\d,]+\)/.test(td.textContent))
      .map(td => ({ el: td, html: td.innerHTML }));
    if (statCells.length === 0) return;

    // Picker row just under the header
    const pickerRow = document.createElement('tr');
    const pickerTd = document.createElement('td');
    pickerTd.colSpan = headerTh.colSpan || 2;
    pickerTd.align = 'center';
    pickerTd.style.cssText = 'padding: 4px 6px;';

    const select = document.createElement('select');
    select.style.cssText = 'background:#000; color:#66ff66; border:1px solid #444; padding:2px; font-size:12px;';
    for (let i = curIdx + 1; i < TECH_LADDER.length; i++) {
      const t = TECH_LADDER[i];
      const opt = document.createElement('option');
      opt.value = String(i);
      opt.textContent = `Lvl ${t.level} — ${t.name} (x${t.mult.toFixed(2)})`;
      select.appendChild(opt);
    }
    select.value = String(curIdx + 1);

    const summary = document.createElement('span');
    summary.style.cssText = 'color:#66ff66; font-size:12px; margin-left:8px;';

    const applyTarget = (idx) => {
      const target = TECH_LADDER[idx];
      const ratioVsNow = target.mult / cur.mult;
      const ratioVsShown = target.mult / next.mult;
      const expNeeded = target.cumExp - cur.cumExp;
      const upgrades = target.level - cur.level;

      summary.textContent = ` every stat ▲ ${((ratioVsNow - 1) * 100).toFixed(1)}% · ` +
        `${expNeeded.toLocaleString()} EXP (${upgrades} upgrade${upgrades === 1 ? '' : 's'})`;
      summary.title = `From ${cur.name} (x${cur.mult.toFixed(2)}) to ${target.name} (x${target.mult.toFixed(2)}).\n` +
        `Projected stats = the shown next-level values × ${ratioVsShown.toFixed(4)}.\n` +
        `EXP is cumulative across all ${upgrades} upgrade${upgrades === 1 ? '' : 's'}.`;

      statCells.forEach(({ el, html }) => {
        el.innerHTML = idx === curIdx + 1 ? html : html.replace(
          /([A-Za-z]+)(\s*\()([\d,]+)(\))/g,
          (all, name, open, num, close) => {
            if (!statNames.test(name)) return all;
            const projected = Math.round(parseInt(num.replace(/,/g, ''), 10) * ratioVsShown);
            return name + open + projected.toLocaleString() + close;
          }
        );
      });
    };

    select.addEventListener('change', () => applyTarget(parseInt(select.value, 10)));

    const label = document.createElement('span');
    label.textContent = 'Project to: ';
    label.style.cssText = 'color:#ccc; font-size:12px;';
    pickerTd.appendChild(label);
    pickerTd.appendChild(select);
    pickerTd.appendChild(summary);
    pickerRow.appendChild(pickerTd);
    headerTh.closest('tr').after(pickerRow);
    headerTh.dataset.kocTechPicker = '1';

    applyTarget(curIdx + 1);
    debugLog(`[TechProjector] Picker added (${cur.name} → up to ${TECH_LADDER[TECH_LADDER.length - 1].name})`);
  }

  // ==================== TECH UPGRADE: TIME TO UPGRADE + EXP NEEDED ====================

  /**
   * Capture the player's EXP-per-turn rate from upgrades.php and cache it.
   * The "Increase Experience" section shows the current rate as "<Name> | N EXP Per Min".
   * EXP regenerates one turn per minute, so EXP/min == EXP/turn. We skip the
   * "Upgrade to N EXP Per Min" target text and read the current-level rate only.
   */
  function collectExpPerTurn() {
    const expHeader = [...document.querySelectorAll('th')]
      .find(th => /Increase Experience/i.test(th.textContent));
    if (!expHeader) {
      debugLog('[Upgrades] No "Increase Experience" section found');
      return;
    }

    const table = expHeader.closest('table');
    if (!table) return;

    let rate = null;
    table.querySelectorAll('td, th').forEach(cell => {
      const text = cell.textContent.replace(/\s+/g, ' ').trim();
      if (/upgrade\s+to/i.test(text)) return; // skip the next-level target
      const m = text.match(/(\d+)\s*EXP\s*Per\s*Min/i);
      if (m) rate = parseInt(m[1], 10);
    });

    if (rate && rate >= 1 && rate <= 50) {
      SafeStorage.set(EXP_PER_TURN_KEY, rate);
      debugLog('[Upgrades] Captured EXP/turn rate:', rate);
    } else {
      debugLog('[Upgrades] Could not parse EXP/turn rate');
    }
  }

  /** Format a whole number of minutes as "D Days, H Hours, M Minutes" (always plural, matching KoC). */
  function formatDaysHoursMinutes(totalMinutes) {
    const d = Math.floor(totalMinutes / MINUTES_PER_DAY);
    const h = Math.floor((totalMinutes % MINUTES_PER_DAY) / 60);
    const m = totalMinutes % 60;
    return `${d} Days, ${h} Hours, ${m} Minutes`;
  }

  /**
   * Inject "Time to upgrade" + "EXP still needed to be deposited" rows into EVERY EXP-cost
   * upgrade on safe.php — Increase Soldiers, Economic Development, Technological Development,
   * and SAFE Upgrade. They all draw from the single shared Experience Bank.
   *
   * Inputs (all verified against the live page):
   *   - cost      : total EXP required, parsed from each upgrade's submit button ("X Experience")
   *   - onHand    : sidebar "Experience"
   *   - deposited : sidebar "Experience Bank" (shared across all EXP upgrades)
   *   - expPerTurn: cached from upgrades.php (defaults to 6, the max level)
   *
   * "Time to upgrade"  → ceil(max(0, cost - deposited - onHand) / expPerTurn) (on-hand counts;
   *                       "Ready to upgrade now" once on-hand + bank cover the cost).
   * "EXP still needed to be deposited" → max(0, cost - deposited): what must still go into the
   *                       bank, independent of on-hand (on-hand isn't banked until you DEPOSIT).
   * Maxed upgrades have no "X Experience" button and are skipped.
   */
  function addExpUpgradeTimeRows() {
    const ROW_CLASS = 'koc-exp-upgrade-time-row';

    const onHand = getSidebarValue('Experience') || 0;
    const deposited = getSidebarValue('Experience Bank') || 0;

    const storedRate = SafeStorage.get(EXP_PER_TURN_KEY, null);
    const expPerTurn = storedRate || DEFAULT_EXP_PER_TURN;
    const calibrated = !!storedRate;
    const subtitle = calibrated
      ? '(based on EXP on-hand, EXP Deposited and EXP per turn)'
      : `(based on EXP on-hand, EXP Deposited and an assumed ${expPerTurn} EXP/turn — visit Upgrades to calibrate)`;

    const buttons = [...document.querySelectorAll('form input[type="submit"]')]
      .filter(b => /[\d,]+\s*Experience\s*$/i.test(b.value));

    buttons.forEach(btn => {
      const table = btn.closest('table');
      if (!table) return;
      if (table.querySelector('.' + ROW_CLASS)) return; // already injected for this upgrade

      const costMatch = btn.value.match(/([\d,]+)\s*Experience/i);
      if (!costMatch) return;
      const cost = parseInt(costMatch[1].replace(/,/g, ''), 10);

      const shortfall = Math.max(0, cost - deposited - onHand);
      const stillToDeposit = Math.max(0, cost - deposited);
      const minutes = shortfall > 0 ? Math.ceil(shortfall / expPerTurn) : 0;
      const timeStr = shortfall > 0 ? formatDaysHoursMinutes(minutes) : 'Ready to upgrade now';

      // Mirror the button row's column layout so our values right-align like the cost
      // (e.g. the SAFE Upgrade table's value cell is colspan 3, others are 1).
      const btnRow = btn.closest('tr');
      const btnCell = btn.closest('td');
      const valColspan = (btnCell && btnCell.getAttribute('colspan')) || 1;
      const firstCell = btnRow && btnRow.querySelector('td');
      const labelColspan = (firstCell && firstCell.getAttribute('colspan')) || 1;

      const tbody = table.querySelector('tbody') || table;

      const timeRow = document.createElement('tr');
      timeRow.className = ROW_CLASS;
      timeRow.innerHTML =
        '<td colspan="' + labelColspan + '" align="left"><b>Time to upgrade:</b><br>' +
        '<font color="#ff6666" style="font-size: 0.70em;">' + subtitle + '</font></td>' +
        '<td colspan="' + valColspan + '" align="right"><font color="#FFFF00"><b>' + timeStr + '</b></font></td>';

      const needRow = document.createElement('tr');
      needRow.className = ROW_CLASS;
      needRow.innerHTML =
        '<td colspan="' + labelColspan + '" align="left"><b>EXP still needed to be deposited:</b></td>' +
        '<td colspan="' + valColspan + '" align="right"><font color="#FFFF00"><b>' + stillToDeposit.toLocaleString() + '</b></font></td>';

      tbody.appendChild(timeRow);
      tbody.appendChild(needRow);

      debugLog('[SafePage] EXP upgrade rows injected', { section: (table.querySelector('th') || {}).textContent, cost, deposited, onHand, shortfall, stillToDeposit, minutes });
    });
  }

  // ==================== SAFE DEPOSIT RATE + FORECASTS (safe.php), GOLD UPGRADE READINESS (upgrades.php) ====================

  /**
   * Read the current "SAFE Gold Deposited / Every Minute" rate from the safe.php DOM.
   * Reads the rate under the current-level header only (stops before "Next Safe upgrade").
   * Returns the gold/min as a number, or null if not found.
   */
  function parseSafeDepositRate() {
    const depHeader = [...document.querySelectorAll('th')]
      .find(th => /SAFE Gold Deposited/i.test(th.textContent));
    if (!depHeader) return null;

    const table = depHeader.closest('table');
    if (!table) return null;

    const rows = [...table.querySelectorAll('tr')];
    const startIdx = rows.indexOf(depHeader.closest('tr'));
    for (let i = startIdx + 1; i < rows.length; i++) {
      const text = rows[i].textContent.replace(/\s+/g, ' ').trim();
      if (/Next Safe upgrade/i.test(text)) break; // don't read the next-level projection
      const m = text.match(/Every Minute\s*([\d,]+)\s*Gold/i);
      if (m) return parseInt(m[1].replace(/,/g, ''), 10);
    }
    return null;
  }

  /** Capture the safe deposit/min rate from safe.php and cache it for upgrades.php. */
  function collectSafeDepositRate() {
    const rate = parseSafeDepositRate();
    if (rate && rate > 0) {
      SafeStorage.set(SAFE_DEPOSIT_PER_MIN_KEY, rate);
      debugLog('[SafePage] Captured safe deposit/min:', rate);
    }
  }

  /**
   * Inject a "SAFE Forecasts" table above "SAFE Gold Deposited" on safe.php, showing how
   * long until the Safe grows to each milestone (1B/2B/5B/9B/10B), based on the current
   * Safe balance and the live per-minute deposit rate.
   */
  function addSafeForecasts() {
    const TABLE_ID = 'koc-safe-forecasts';
    if (document.getElementById(TABLE_ID)) return; // prevent duplicates

    const depHeader = [...document.querySelectorAll('th')]
      .find(th => /SAFE Gold Deposited/i.test(th.textContent));
    if (!depHeader) return;
    const depTable = depHeader.closest('table');
    if (!depTable || !depTable.parentNode) return;

    // Prefer the full-precision "Gold in Safe = X" on safe.php; the sidebar abbreviates
    // large values (e.g. "2,560M"), which only resolves to the nearest million.
    const exactSafe = (document.body.innerText.match(/Gold in Safe\s*=\s*([\d,]+)/i) || [])[1];
    const safe = (exactSafe ? parseInt(exactSafe.replace(/,/g, ''), 10) : 0) || getSidebarValue('Safe') || 0;
    const rate = parseSafeDepositRate() || SafeStorage.get(SAFE_DEPOSIT_PER_MIN_KEY, null);

    let rowsHtml = '';
    for (const milestone of SAFE_FORECAST_MILESTONES) {
      const isMax = milestone >= SAFE_GOLD_CAP;
      const label = `Safe to ${milestone / 1e9} bil${isMax ? ' (MAX)' : ''} in:`;
      let valHtml;
      if (safe >= milestone) {
        valHtml = '<font color="#66ff66">&#10003; Reached</font>';
      } else if (rate && rate > 0) {
        valHtml = formatDaysHoursMinutes(Math.ceil((milestone - safe) / rate));
      } else {
        valHtml = '<font color="#ff6666">visit Safe to calibrate</font>';
      }
      rowsHtml +=
        '<tr>' +
        '<td colspan="2" style="color:#FFFF00;font-weight:bold;font-size:0.80em;">' + label + '</td>' +
        '<td align="right" colspan="3" style="color:#FFFF00;font-weight:bold;font-size:0.80em;">' + valHtml + '</td>' +
        '</tr>';
    }

    const table = document.createElement('table');
    table.id = TABLE_ID;
    table.className = 'table_lines';
    table.width = '100%';
    table.cellSpacing = '0';
    table.cellPadding = '6';
    table.border = '0';
    table.innerHTML =
      '<tr><th colspan="5">' +
      '<font size="2" color="#FFFF00"><b>SAFE Forecasts</b></font><br>' +
      '<font size="1" color="#cccccc" style="font-weight:normal;">Based on current safe and deposit per minute values</font>' +
      '</th></tr>' + rowsHtml;

    depTable.parentNode.insertBefore(table, depTable);
    debugLog('[SafePage] Safe forecasts injected', { safe, rate });
  }

  /**
   * Inject readiness + time rows into each gold-cost upgrade on upgrades.php
   * (Siege, Fortification, Covert, Sentry, Poison, Antidote, Theft, Vigilance):
   *   1) Upgrade Ready (On-Hand + Vault + Safe) → "Ready" / shortfall + slay estimate
   *   2) Upgrade Ready (Based on Safe + Safe Deposited per Min)    → time for Safe to grow to cost
   *   3) Gold Needed on top of Safe                                → max(0, cost - Safe)
   * Maxed upgrades have no Gold button and are skipped.
   */
  function addUpgradeReadyRows() {
    const ROW_CLASS = 'koc-upgrade-ready-row';
    if (document.querySelector('.' + ROW_CLASS)) return; // prevent duplicates

    const goldOnHand = getSidebarValue('Gold') || 0;
    const vault = getSidebarValue('Vault') || 0;
    const safe = getSidebarValue('Safe') || 0;
    const safePerMin = SafeStorage.get(SAFE_DEPOSIT_PER_MIN_KEY, null);

    const SECTION_RE = /(Siege|Fortification|Covert Skill|Sentry Skill|Poison Skill|Antidote Skill|Theft Skill|Vigilance Skill)/i;

    // Each gold upgrade has its own form whose submit button reads "<cost> Gold".
    const buttons = [...document.querySelectorAll('form input[type="submit"]')]
      .filter(b => /[\d,]+\s*Gold\s*$/i.test(b.value));

    buttons.forEach(btn => {
      const costMatch = btn.value.match(/([\d,]+)\s*Gold/i);
      if (!costMatch) return;

      const table = btn.closest('table');
      if (!table) return;
      // Guard: only the eight skill-upgrade tables (avoids any stray gold buttons)
      const hasSectionHeader = [...table.querySelectorAll('th')].some(th => SECTION_RE.test(th.textContent));
      if (!hasSectionHeader) return;

      const cost = parseInt(costMatch[1].replace(/,/g, ''), 10);
      const tbody = table.querySelector('tbody') || table;

      // Row 1: can we afford it? Counts only gold you hold (on hand, vault, safe), not what
      // selling weapons would raise. The shortfall is what you'd make up by selling some
      // weapons or slaying (shown as a slay estimate from your avg gold/atk).
      const liquid = goldOnHand + vault + safe;
      const ready = liquid >= cost;
      const shortfall = cost - liquid;
      const avgGold = SafeStorage.get('xpTool_avgGold', 0);
      const readyVal = ready ? 'Ready' : ('Short ' + shortfall.toLocaleString() + ' Gold');
      const readyColor = ready ? '#66ff66' : '#ff6666';
      const liquidSubtitle = '(On-Hand + Vault + Safe)';
      const coverLine = ready ? '' :
        '<br><font color="#ffaa66" style="font-size: 0.70em;">' +
        (avgGold > 0 ? 'sell weapons · ≈' + Math.ceil(shortfall / avgGold).toLocaleString() + ' slays' : 'sell weapons or slay to cover') +
        '</font>';

      // Row 2: time for the Safe alone to grow to the cost
      const neededOnTop = Math.max(0, cost - safe);
      let timeVal, timeColor = '#FFFFFF';
      if (neededOnTop === 0) {
        timeVal = 'Ready'; timeColor = '#66ff66';
      } else if (cost > SAFE_GOLD_CAP) {
        timeVal = 'Exceeds 10B safe cap'; timeColor = '#ff6666';
      } else if (safePerMin && safePerMin > 0) {
        timeVal = formatDaysHoursMinutes(Math.ceil(neededOnTop / safePerMin));
      } else {
        timeVal = 'visit Safe to calibrate'; timeColor = '#ff6666';
      }

      const row1 = document.createElement('tr');
      row1.className = ROW_CLASS;
      row1.innerHTML =
        '<td align="left"><b>Upgrade Ready:</b><br>' +
        '<font color="#ff6666" style="font-size: 0.70em;">' + liquidSubtitle + '</font></td>' +
        '<td align="right"><font color="' + readyColor + '"><b>' + readyVal + '</b></font>' + coverLine + '</td>';

      const row2 = document.createElement('tr');
      row2.className = ROW_CLASS;
      row2.innerHTML =
        '<td align="left"><b>Upgrade Ready:</b><br>' +
        '<font color="#ff6666" style="font-size: 0.70em;">(Based on Safe + Safe Deposited per Min)</font></td>' +
        '<td align="right"><font color="' + timeColor + '"><b>' + timeVal + '</b></font></td>';

      const row3 = document.createElement('tr');
      row3.className = ROW_CLASS;
      row3.innerHTML =
        '<td align="left"><b>Gold Needed on top of Safe:</b></td>' +
        '<td align="right"><font color="#FFFFFF"><b>' + neededOnTop.toLocaleString() + '</b></font></td>';

      tbody.appendChild(row1);
      tbody.appendChild(row2);
      tbody.appendChild(row3);
    });

    debugLog('[Upgrades] Upgrade-ready rows injected', { goldOnHand, vault, safe, safePerMin, count: buttons.length });
  }

  // ==================== ESTIMATED FUNDS (armory.php) ====================
  // One box on the Armory, above the game's "Available Funds:" banner, showing
  // an estimate of the gold on hand right now: the last gold amount the game
  // showed you, plus the income earned since then.
  //
  //   estimate = G0 + income·t + ½·g·spm·t²      (1 game turn = 1 minute)
  //     G0     = gold on hand at the last reading (sidebar, Command Centre or Armory)
  //     income = the Command Centre's "Projected Income (in 1 min)"; if that has
  //              never been read, an estimate from soldier counts
  //     g, spm = gold per new soldier per turn, and "Soldier Per Turn"
  //
  // Readings come only from pages the player opened. Nothing is sent anywhere,
  // nothing on the game page is changed or pressed, and the box gives no advice.

  const FUNDS_PREFIX = 'KoC_Banking_';         // storage prefix kept so existing readings carry over
  const FUNDS_TBG_REGULAR = 2.3;               // gold per regular soldier per turn (fallback income)
  const FUNDS_TBG_COVERT = 0.92;               // gold per covert unit per turn (fallback income)
  const FUNDS_GOLD_PER_NEW_SOLDIER = 2.3;      // new soldiers arrive untrained

  function fundsGet(key, def = null) { return SafeStorage.get(FUNDS_PREFIX + key, def); }
  function fundsSet(key, val) { return SafeStorage.set(FUNDS_PREFIX + key, val); }

  function fundsCleanNumber(str) {
    if (str === null || str === undefined) return null;
    const num = parseInt(String(str).replace(/[^\d]/g, ''), 10);
    return isNaN(num) ? null : num;
  }

  function fundsFormatGold(n) {
    if (n === null || n === undefined || isNaN(n)) return '???';
    const abs = Math.abs(n);
    if (abs >= 1e12) return (n / 1e12).toFixed(2) + 'T';
    if (abs >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (abs >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (abs >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return String(Math.round(n));
  }

  function fundsFormatAgo(ts) {
    const min = Math.max(0, Math.round((Date.now() - new Date(ts).getTime()) / 60000));
    if (min < 1) return 'just now';
    if (min < 60) return `${min}m ago`;
    const h = Math.floor(min / 60);
    if (h < 24) return `${h}h ${min % 60}m ago`;
    return `${Math.floor(h / 24)}d ${h % 24}h ago`;
  }

  // The innermost table whose text contains the marker.
  function findInnermostTable(marker) {
    const tables = [...document.querySelectorAll('table')].filter(t => t.textContent.includes(marker));
    return tables.find(t => !tables.some(o => o !== t && t.contains(o))) || null;
  }

  function fundsFindRow(table, labelRegex) {
    return [...table.rows].find(r => r.cells[0] && labelRegex.test(r.cells[0].textContent.trim())) || null;
  }

  // Gold on hand (the vault is kept apart and never added in).
  function fundsSaveReading(gold, source) {
    if (gold === null || gold === undefined) return;
    fundsSet('gold_reading', { gold, ts: new Date().toISOString(), source });
  }

  // Sidebar "Gold:" cell, on any page with the left menu. Large amounts are
  // abbreviated there ("2,560M"), so the K/M/B/T suffix is read too.
  function fundsReadSidebarGold() {
    const side = readOwnSidebar();
    if (side && side.goldN !== undefined) fundsSaveReading(side.goldN, 'sidebar');
  }

  // Regular soldiers and covert units, for the fallback income.
  function fundsReadPersonnel() {
    const table = document.querySelector('table.table_lines.personnel') ||
                  findInnermostTable('Trained Attack Soldiers');
    if (!table) return null;
    const counts = {};
    [...table.rows].forEach(row => {
      if (row.cells.length < 2) return;
      const val = fundsCleanNumber(row.cells[1].textContent);
      if (val !== null) counts[row.cells[0].textContent.trim()] = val;
    });
    const sum = (labels) => labels.reduce((t, l) => t + (counts[l] || 0), 0);
    const regulars = sum(['Trained Attack Soldiers', 'Trained Defense Soldiers', 'Untrained Soldiers']);
    const coverts = sum(['Spies', 'Sentries', 'Venomweavers', 'Serpentwardens', 'Thieves', 'Rangers']);
    return (regulars || coverts) ? { regulars, coverts } : null;
  }

  // Command Centre: gold on hand, Projected Income and Soldier Per Turn.
  function fundsReadCommandCentre() {
    const mo = findInnermostTable('Projected Income');
    if (!mo) return;
    const cell = (re) => { const r = fundsFindRow(mo, re); return r && r.cells[1] ? r.cells[1].textContent : ''; };
    const gold = fundsCleanNumber(cell(/^Available Funds/).match(/([\d,]+)\s+Gold/i)?.[1]);
    const personnel = fundsReadPersonnel();
    fundsSet('calibration', {
      goldPerMin: fundsCleanNumber(cell(/^Projected Income/).match(/([\d,]+)\s+Gold\s+\(in 1 min\)/i)?.[1]),
      spm: fundsCleanNumber(cell(/^Soldier Per Turn/).match(/([\d,]+)\s+Soldiers/i)?.[1]),
      regulars: personnel ? personnel.regulars : null,
      coverts: personnel ? personnel.coverts : null,
      ts: new Date().toISOString()
    });
    fundsSaveReading(gold, 'Command Centre');
  }

  // Armory: the "Available Funds:" banner, and the personnel table for the fallback income.
  function fundsReadArmory() {
    const m = document.body.textContent.match(/Available\s+Funds:\s*([\d,]+)\s*Gold/i);
    if (m) fundsSaveReading(fundsCleanNumber(m[1]), 'Armory');
    const personnel = fundsReadPersonnel();
    if (personnel) fundsSet('calibration', { ...fundsGet('calibration', {}), ...personnel });
  }

  function fundsEstimate(nowMs = Date.now()) {
    const reading = fundsGet('gold_reading', null);
    if (!reading) return null;
    const cal = fundsGet('calibration', null) || {};
    const minutes = Math.max(0, (nowMs - new Date(reading.ts).getTime()) / 60000);
    const spm = cal.spm || 0;

    let income = (cal.goldPerMin !== null && cal.goldPerMin !== undefined) ? cal.goldPerMin
      : (cal.regulars !== null && cal.regulars !== undefined)
        ? FUNDS_TBG_REGULAR * cal.regulars + FUNDS_TBG_COVERT * (cal.coverts || 0)
        : null;
    // The income figure is as old as its Command Centre visit: add the soldiers
    // produced between that visit and the gold reading.
    if (income !== null && cal.ts && spm) {
      const ageMin = Math.max(0, (new Date(reading.ts).getTime() - new Date(cal.ts).getTime()) / 60000);
      income += FUNDS_GOLD_PER_NEW_SOLDIER * spm * ageMin;
    }

    const gold = income === null ? reading.gold
      : reading.gold + income * minutes + 0.5 * FUNDS_GOLD_PER_NEW_SOLDIER * spm * minutes * minutes;
    return { gold: Math.round(gold), income, reading };
  }

  function fundsPaint() {
    const goldEl = document.getElementById('koc-funds-gold');
    const subEl = document.getElementById('koc-funds-sub');
    if (!goldEl || !subEl) return;
    const est = fundsEstimate();
    if (!est) {
      goldEl.textContent = '???';
      subEl.textContent = 'Open your Command Centre once to start the estimate.';
      return;
    }
    goldEl.textContent = fundsFormatGold(est.gold);
    goldEl.title = est.gold.toLocaleString() + ' gold (estimate)';
    subEl.textContent = `${fundsFormatGold(est.reading.gold)} read ${fundsFormatAgo(est.reading.ts)} (${est.reading.source})` +
      (est.income === null ? ' · no income figure yet: open your Command Centre' : ` + ${fundsFormatGold(est.income)}/min income`);
  }

  function fundsShowOnArmory() {
    fundsReadArmory();
    if (document.getElementById('koc-funds-box')) return;
    const banner = [...document.querySelectorAll('b,font,td')]
      .find(el => /Available Funds:/.test(el.textContent) && el.textContent.trim().length < 60);
    const anchor = banner && banner.closest('table');
    if (!anchor) return;

    // The game's own table_lines class, so the box matches the page.
    const box = document.createElement('table');
    box.id = 'koc-funds-box';
    box.className = 'table_lines';
    box.style.cssText = 'width:100%;margin:8px auto;';
    box.innerHTML = '<tbody><tr><th style="text-align:center;padding:6px;">' +
      '<font size="4"><b>Estimated Funds:</b></font> <font size="5"><span id="koc-funds-gold">—</span></font>' +
      '<div id="koc-funds-sub" style="font-weight:normal;font-size:11px;margin-top:3px;"></div>' +
      '</th></tr></tbody>';
    anchor.parentNode.insertBefore(box, anchor);
    fundsPaint();
    setInterval(fundsPaint, 1000);   // repaints the number only; reads and sends nothing
  }

  // ==================== SABOTAGE TRACKER (attack.php) ====================
  // Tracks YOUR OWN sabotage / revenge-sabotage attempts per target (KoC allows
  // 10 sabs + 4 revenge sabs per target in a rolling 24h window) and shows:
  //   • "You last sabbed/poisoned/stole" timestamps as colour-coded ages (stats-page style)
  //   • attempts left in the window + a ticking "Can sab again in …" countdown
  //   • sab damage left before the target is maxed (cap − lost in last 24h)
  // Display + passive recording only. It listens for missions the player fires
  // by hand and reconciles against the counters KoC itself renders. It never
  // submits, clicks or fetches anything. (The target's two cap numbers are sent
  // by a separate step, sendSabCaps, under the "Sabotage caps" share.)

  const SAB_LOG_KEY = "KoC_SabLog";
  const SAB_WINDOW_MS = 24 * 60 * 60 * 1000;
  const SAB_DEFAULT_CAP = 10;      // regular sab attempts per target per 24h
  const REV_DEFAULT_CAP = 4;       // revenge sab attempts per target per 24h

  function getSabLog() {
    const log = SafeStorage.get(SAB_LOG_KEY, {});
    return (log && typeof log === 'object' && !Array.isArray(log)) ? log : {};
  }

  function saveSabLog(log) {
    const now = Date.now();
    const grace = SAB_WINDOW_MS + 60 * 60 * 1000; // keep 1h past the window for reconciling
    for (const [id, rec] of Object.entries(log)) {
      rec.sab = (rec.sab || []).filter(e => e && now - e.t < grace);
      rec.rev = (rec.rev || []).filter(e => e && now - e.t < grace);
      if (!rec.sab.length && !rec.rev.length && (!rec.seen || now - rec.seen > 7 * 86400000)) {
        delete log[id];
      }
    }
    return SafeStorage.set(SAB_LOG_KEY, log);
  }

  // Each tracked attempt is { t, src, est? }. src says where its time came from:
  //   'click' — the member's own clock at the press (pending: the game may refuse it)
  //   'land'  — the report the member landed on after it: that page's Server Time
  //   'file'  — the target's Intelligence file (the game's own time)
  //   'est'   — a pad for an attempt the game counted and the tracker never saw (est)
  // An entry with no src counts as 'click'.
  function recordSabAttempt(targetId, kind, tMs, src = 'click') {
    const log = getSabLog();
    const rec = log[targetId] || (log[targetId] = { sab: [], rev: [] });
    const arr = kind === 'rev' ? (rec.rev = rec.rev || []) : (rec.sab = rec.sab || []);
    arr.push({ t: tMs, src });
    arr.sort((a, b) => a.t - b.t);
    rec.seen = tMs;
    saveSabLog(log);
  }

  /**
   * The report the member just landed on (inteldetail.php) is the sab just
   * fired, and the page's Server Time is its time. Confirm the press that
   * launched it: this target's newest 'click' entry, sab or revenge, within 5
   * minutes of the landing, takes the landing's time and becomes exact
   * ('land'; its kind stays). No such press (fired where the tracker could not
   * see it): the landing is added as a sab.
   */
  function confirmSabLanding(targetId, landMs) {
    const log = getSabLog();
    const rec = log[targetId] || (log[targetId] = { sab: [], rev: [] });
    rec.sab = (rec.sab || []).filter(Boolean);
    rec.rev = (rec.rev || []).filter(Boolean);
    let press = null;
    for (const e of [...rec.sab, ...rec.rev]) {
      if (!e || (e.src || 'click') !== 'click' || typeof e.t !== 'number') continue;
      if (Math.abs(e.t - landMs) > 5 * 60 * 1000) continue;
      if (!press || e.t > press.t) press = e;
    }
    if (press) {
      press.t = landMs;
      press.src = 'land';
      delete press.est;
    } else {
      rec.sab.push({ t: landMs, src: 'land' });
    }
    rec.sab.sort((a, b) => a.t - b.t);
    rec.rev.sort((a, b) => a.t - b.t);
    rec.seen = landMs;
    saveSabLog(log);
    debugLog(`🕵️ Sab Tracker: landing on ${targetId} ${press ? 'confirmed the press' : 'added (no press seen)'}`);
  }

  /**
   * On a sab report (inteldetail.php) the member just landed on — the page the
   * game redirects to after "Sabotage Now" or "… Again!" (covertReportJustLanded)
   * — confirm that sab at the page's own Server Time. A report opened later,
   * reloaded or restored, or a page whose Server Time cannot be read, changes
   * nothing.
   */
  function confirmSabLandingStep() {
    const report = parseSabReportPage();
    if (!report || !report.targetId || report.landed !== true || !report.at) return;
    const landMs = Date.parse(convertKoCServerTimeToUTC(report.at));
    if (isNaN(landMs)) return;
    confirmSabLanding(String(report.targetId), landMs);
  }

  /**
   * The game refused the press just made (the attack page it answered with
   * says "You have used the maximum sabotage attempts …" or "This player has
   * been maxxed …"): that press was no attempt. Remove this target's newest
   * 'click' entry of `kind` made between 5 s after and 2 min before now; true
   * when one was removed.
   */
  function dropRefusedPress(targetId, kind, nowMs) {
    const log = getSabLog();
    const rec = log[targetId];
    const arr = rec && (kind === 'rev' ? rec.rev : rec.sab);
    if (!Array.isArray(arr)) return false;
    let at = -1;
    arr.forEach((e, i) => {
      if (!e || (e.src || 'click') !== 'click' || typeof e.t !== 'number') return;
      const age = nowMs - e.t;
      if (age < -5000 || age > 2 * 60 * 1000) return;
      if (at < 0 || e.t >= arr[at].t) at = i;
    });
    if (at < 0) return false;
    arr.splice(at, 1);
    saveSabLog(log);
    debugLog(`🕵️ Sab Tracker: the game refused the last ${kind === 'rev' ? 'revenge ' : ''}sab press on ${targetId} — not counted`);
    return true;
  }

  /** Age text + colour, matching the Shared Recon Info table tiers */
  function sabAgeInfo(ageMs) {
    const min = Math.floor(ageMs / 60000);
    const hr = Math.floor(ageMs / 3600000);
    const day = Math.floor(ageMs / 86400000);
    if (min < 1) return { text: 'just now', color: '#6f6' };
    if (min < 60) return { text: `${min}m ago`, color: '#6f6' };
    if (hr < 24) return { text: `${hr}h ago`, color: hr < 6 ? '#6f6' : '#ff6' };
    return { text: `${day}d ago`, color: day < 3 ? '#f90' : '#f44' };
  }

  function fmtSabCountdown(ms) {
    if (ms <= 0) return 'now';
    const s = Math.ceil(ms / 1000);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    const p = n => (n < 10 ? '0' + n : '' + n);
    if (h > 0) return `${h}h ${p(m)}m ${p(sec)}s`;
    if (m > 0) return `${m}m ${p(sec)}s`;
    return `${sec}s`;
  }

  /**
   * Replace "You last sabbed/poisoned/stole" + revenge-sab timestamps with
   * colour-coded relative ages (raw server time kept in the hover tooltip).
   */
  function relativizeMissionTimestamps() {
    const labelRe = /You last (sabbed|poisoned|stole)|last successful|First sab/i;
    const dtRe = /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/;
    const nodes = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    let n;
    while ((n = walker.nextNode())) {
      if (!dtRe.test(n.nodeValue || '')) continue;
      const row = n.parentElement && n.parentElement.closest('tr');
      if (!row || !labelRe.test(row.textContent || '')) continue; // sidebar clock etc. have no label
      nodes.push(n);
    }
    for (const node of nodes) {
      try {
        const m = (node.nodeValue || '').match(dtRe);
        if (!m) continue;
        const ms = Date.parse(convertKoCServerTimeToUTC(m[1]));
        if (isNaN(ms)) continue;
        const age = sabAgeInfo(Date.now() - ms);
        const span = document.createElement('span');
        span.textContent = age.text;
        span.style.cssText = `color:${age.color}; font-weight:bold; cursor:help;`;
        span.title = `${m[1]} (server time)`;
        const after = node.splitText(m.index);
        after.nodeValue = after.nodeValue.slice(m[1].length);
        node.parentNode.insertBefore(span, after);
        // tidy the dangling "on" ("538 Nunchaku on 4d ago" → "538 Nunchaku 4d ago")
        if (/\bon\s*$/i.test(node.nodeValue || '')) {
          node.nodeValue = node.nodeValue.replace(/\s*\bon\s*$/i, ' ');
        } else if (!(node.nodeValue || '').trim()) {
          // timestamp sat alone inside its own (coloured) element — look just before it
          const before = span.parentElement && span.parentElement.previousSibling;
          if (before && before.nodeType === 3 && /\bon\s*$/i.test(before.nodeValue || '')) {
            before.nodeValue = before.nodeValue.replace(/\s*\bon\s*$/i, ' ');
          }
        }
      } catch (err) {
        debugLog('⚠️ Sab Tracker: failed to relativize a timestamp', err);
      }
    }
  }

  /** Scrape the sab-related numbers KoC renders on attack.php?id=… */
  function parseSabPageInfo() {
    // Not just the address: the page the game shows after refusing a sab on a
    // maxed target has no ?id= (see attackPageTargetId).
    const targetId = attackPageTargetId();
    if (!targetId) return null;
    const body = document.body.textContent || '';
    if (!/Sabotage Mission/i.test(body)) return null;

    const cellFrac = (re, bodyRe, bodyText) => {
      for (const td of document.querySelectorAll('td, th')) {
        const t = (td.textContent || '').replace(/\s+/g, ' ').trim();
        const m = t.match(re);
        if (m) return { used: parseInt(m[1], 10), cap: parseInt(m[2], 10) };
      }
      // fallback: label and numbers may sit in separate cells
      if (bodyRe) {
        const m = (bodyText != null ? bodyText : body).match(bodyRe);
        if (m) return { used: parseInt(m[1], 10), cap: parseInt(m[2], 10) };
      }
      return null;
    };
    const bodyNum = (re) => {
      const m = body.match(re);
      return m ? parseInt(m[1].replace(/,/g, ''), 10) : null;
    };
    const stampMs = (re) => {
      const m = body.match(re);
      if (!m) return null;
      const ms = Date.parse(convertKoCServerTimeToUTC(m[1]));
      return isNaN(ms) ? null : ms;
    };

    // "^Sabotage Attempts" cannot match the revenge row (that one starts with "Revenge").
    // For the body-text fallback, blank out the revenge phrase first instead of using
    // a lookbehind (older Safari would die parsing a lookbehind literal).
    const bodySansRev = body.replace(/Revenge\s+Sabotage\s+Attempts/gi, '#');
    const sabFrac = cellFrac(/^Sabotage Attempts:?\s*(\d+)\s*\/\s*(\d+)$/i,
                             /Sabotage Attempts:?\s*(\d+)\s*\/\s*(\d+)/i, bodySansRev);
    const revFrac = cellFrac(/^Revenge Sabotage Attempts:?\s*(\d+)\s*\/\s*(\d+)$/i,
                             /Revenge Sabotage Attempts:?\s*(\d+)\s*\/\s*(\d+)/i);
    const nameLink = document.querySelector(`a[href*="stats.php?id=${targetId}"]`);

    const info = {
      targetId,
      name: nameLink ? (nameLink.textContent || '').trim() : null,
      sabAttempts: sabFrac ? sabFrac.used : null,
      sabCap: sabFrac ? sabFrac.cap : SAB_DEFAULT_CAP,
      revAttempts: revFrac ? revFrac.used : null,
      revCap: revFrac ? revFrac.cap : REV_DEFAULT_CAP,
      // KoC prints the cap with decimals when it isn't whole, e.g.
      // (62,522,883,715.60); the fraction is dropped.
      maxLoss: bodyNum(/Maximum Daily Sabotage loss:\s*\(([\d,]+(?:\.\d+)?)\)/i),
      lost24: bodyNum(/Total lost from sabbs in the last 24\s*hours:\s*([\d,]+(?:\.\d+)?)/i),
      lastSabMs: stampMs(/You last sabbed:[^]{0,80}?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/i),
      lastRevMs: stampMs(/last successful Reven\w*ge Sab on this player[^]{0,60}?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/i),
      revSection: /Revenge Sabotage Mission/i.test(body)
    };
    // Maxed = the game says so (revenge section / "maxxed" text), or regular sab
    // losses in the last 24h have reached the daily cap. Revenge losses are
    // tracked separately by KoC and do NOT count toward the cap.
    // The refusal reads "This player has been maxxed, you can no longer sabotage them."
    info.maxed = info.revSection || /(?:is|been)\s+maxx?ed/i.test(body) ||
                 (info.maxLoss != null && info.lost24 != null && info.lost24 >= info.maxLoss);
    return info;
  }

  /**
   * Make the tracked log agree with the counters KoC itself renders (they are
   * authoritative). When the tracker holds MORE attempts than the game counts,
   * entries go in this order, and only as far as the excess:
   *   1. estimated entries, oldest first — a pad is the tracker's own guess,
   *      and the guess is what the game can have aged out while a real
   *      attempt of ours is still counted;
   *   2. a phantom press: one made in the last 2 minutes that the game never
   *      counted (it refused it — an 11th sab, a maxed target), the newest
   *      such 'click' each time;
   *   3. the oldest entries, which the game says have aged out.
   * Guesses before presses, presses before exact times: an exact time
   * ('land', 'file') is dropped only as the last resort. Dropping the
   * earliest entry can only push a countdown later, never sooner.
   * When the game counts attempts the tracker never saw, every shortfall is
   * padded at the page's own moment — never at a stamp the page prints. Those
   * pads show a "≤" (at the latest) countdown until exact times arrive from a
   * report landing or the Intelligence file, so a target whose attempts the
   * tracker never saw reads ~24h from this page. That is the cost, and it is
   * always on the late side.
   */
  function reconcileSabLog(info) {
    const log = getSabLog();
    const rec = log[info.targetId] || (log[info.targetId] = { sab: [], rev: [] });
    const now = Date.now();
    // The page's "First sab (last 24hrs)" stamp is a first success by an
    // unknown member of the alliance, so nothing is timed from it.
    const fit = (arr, pageCount, lastMs) => {
      const inWin = (arr || []).filter(e => e && now - e.t < SAB_WINDOW_MS).sort((a, b) => a.t - b.t);
      if (pageCount != null) {
        // Guesses first: the oldest estimated entry, one at a time. A pad stamped
        // on an earlier page can age out of OUR window while the attempt it stands
        // for is still counted — and then it would be kept in place of a real sab,
        // freeing a slot ~24h early.
        while (inWin.length > pageCount) {
          const est = inWin.findIndex((e) => !!e.est);
          if (est < 0) break;
          inWin.splice(est, 1);
        }
        // Then phantom presses: the newest 'click' under 2 minutes old, one at a time.
        while (inWin.length > pageCount) {
          let phantom = -1;
          inWin.forEach((e, i) => { if ((e.src || 'click') === 'click' && now - e.t <= 2 * 60 * 1000) phantom = i; });
          if (phantom < 0) break;
          inWin.splice(phantom, 1);
        }
        while (inWin.length > pageCount) inWin.shift(); // aged out, per the game
        // A pad stands for an attempt the tracker never saw. The one time known to
        // be at or after it is the page's own moment: the game counted the attempt
        // before it drew these counters. "You last sabbed" is the last SUCCESSFUL
        // sab, so an attempt a pad stands for can be LATER than it (a failed one
        // after the last success — the live page shows 10 attempts, 5 successes),
        // and padding there would free the slot early; it is used only when the
        // page's clock runs ahead of the member's.
        const estT = Math.max(now, (lastMs && now - lastMs < SAB_WINDOW_MS) ? lastMs : 0);
        while (inWin.length < pageCount) inWin.push({ t: estT, est: 1, src: 'est' });
        inWin.sort((a, b) => a.t - b.t);
      }
      return inWin;
    };
    rec.sab = fit(rec.sab, info.sabAttempts, info.lastSabMs);
    rec.rev = fit(rec.rev, info.revAttempts, info.lastRevMs);
    rec.seen = now;
    if (info.name) rec.name = info.name;
    saveSabLog(log);
    return rec;
  }

  /** Tightest <tr> whose collapsed text matches (nested-table safe) */
  function findRowByText(re) {
    let best = null, bestLen = Infinity;
    for (const row of document.querySelectorAll('tr')) {
      const t = (row.textContent || '').replace(/\s+/g, ' ').trim();
      if (!re.test(t)) continue;
      if (t.length < bestLen) { best = row; bestLen = t.length; }
    }
    return best;
  }

  function renderSabSlotsLine(el, rec, kind, cap, info) {
    const now = Date.now();
    const inWin = arr => (arr || []).filter(e => e && now - e.t < SAB_WINDOW_MS).sort((a, b) => a.t - b.t);
    const mine = inWin(kind === 'rev' ? rec.rev : rec.sab);
    const other = inWin(kind === 'rev' ? rec.sab : rec.rev);
    const left = Math.max(cap - mine.length, 0);
    const slotLabel = kind === 'rev' ? 'revenge sabs' : 'sab attempts';
    const verb = kind === 'rev' ? 'revenge sab' : 'sab';
    const grey = 'color:#bbb;';
    const list = arr => arr.map((e, i) =>
      `#${i + 1}: ${convertUTCToKoCServerTime(new Date(e.t).toISOString())}${e.est ? ' (estimated)' : ''}` +
      ` → expires ${convertUTCToKoCServerTime(new Date(e.t + SAB_WINDOW_MS).toISOString())}`).join('\n');
    const mineTitle = mine.length
      ? `Tracked ${slotLabel} (server time):\n${list(mine)}`
      : `No ${slotLabel} tracked in the current 24h window.`;
    let html, title;

    if (other.length) {
      // Sab and revenge sab are mutually exclusive per target per 24h window —
      // this is the state KoC hides (the Revenge section vanishes once un-maxed).
      const unlockMs = other[other.length - 1].t + SAB_WINDOW_MS - now;
      const otherEst = other.some(e => e.est);
      html = `<span style="color:#f90; font-weight:bold;">🔒 ${kind === 'rev' ? 'Revenge locked' : 'Regular sabs locked'} — you ${kind === 'rev' ? 'sabbed' : 'revenge-sabbed'} this target in this 24h window</span>` +
             `<span style="${grey}"> — opens in ${otherEst ? '≤ ' : ''}${fmtSabCountdown(unlockMs)}${kind === 'rev' ? ' (if still maxed)' : ''}</span>`;
      title = `Sab and revenge sab are mutually exclusive per target per 24h window.\n` +
              `Unlock shown = when your last ${kind === 'rev' ? 'sab' : 'revenge sab'} leaves the window.\n` +
              `Your ${kind === 'rev' ? 'sab attempts' : 'revenge sabs'} (server time):\n${list(other)}`;
    } else if (kind === 'sab' && info.maxed) {
      html = `<span style="color:#f66; font-weight:bold;">🚫 Regular sabs will abort while the target is maxed</span>` +
             `<span style="${grey}"> — ${left} of ${cap} ${slotLabel} left</span>`;
      if (!left && mine.length) {
        html += `<span style="${grey}"> · next slot in ${mine[0].est ? '≤ ' : ''}${fmtSabCountdown(mine[0].t + SAB_WINDOW_MS - now)}</span>`;
      }
      title = mineTitle;
    } else if (left > 0) {
      html = `<span style="color:#6f6; font-weight:bold;">✅ Can ${verb} now</span>` +
             `<span style="${grey}"> — ${left} of ${cap} ${slotLabel} left in this 24h window</span>`;
      title = mineTitle;
    } else {
      html = `<span style="color:#ff6; font-weight:bold;">⏳ Can ${verb} again in ${mine[0].est ? '≤ ' : ''}${fmtSabCountdown(mine[0].t + SAB_WINDOW_MS - now)}</span>` +
             `<span style="${grey}"> — ${cap}/${cap} ${slotLabel} used</span>`;
      title = mineTitle;
    }
    el.innerHTML = html;
    el.title = title;
  }

  function buildSabMaxedLineHTML(info) {
    if (info.maxLoss == null || info.lost24 == null) return '';
    const rem = info.maxLoss - info.lost24;
    if (info.maxed || rem <= 0) {
      return `<span style="color:#f66; font-weight:bold;">🔴 TARGET MAXED</span>` +
             `<span style="color:#bbb;"> — lost ${info.lost24.toLocaleString()} of ${info.maxLoss.toLocaleString()} sab cap in the last 24h</span>`;
    }
    return `<span style="color:#ffd700; font-weight:bold;">💥 ${rem.toLocaleString()}</span>` +
           `<span style="color:#bbb;"> sab damage left before maxed (cap ${info.maxLoss.toLocaleString()} − lost ${info.lost24.toLocaleString()} in 24h)</span>`;
  }

  function injectSabPanels(info, rec) {
    const renders = [];
    if (document.getElementById('tdc-sab-panel') || document.getElementById('tdc-rev-panel')) return renders;

    const mkPanel = (id, anchorRow) => {
      if (!anchorRow) return null;
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      let span = 0;
      for (const c of anchorRow.cells) span += c.colSpan || 1;
      td.colSpan = Math.max(span, 1);
      td.style.cssText = 'padding:6px 12px; text-align:center;';
      const div = document.createElement('div');
      div.id = id;
      div.style.cssText = 'font-size:12px; line-height:1.8;';
      td.appendChild(div);
      tr.appendChild(td);
      anchorRow.after(tr);
      return div;
    };

    // Regular sabotage panel
    const sabAnchor = findRowByText(/You last sabbed/i) ||
                      findRowByText(/Total lost from sabbs in the last 24/i) ||
                      findRowByText(/^Sabotage Attempts/i);
    const sabDiv = mkPanel('tdc-sab-panel', sabAnchor);
    if (sabDiv) {
      const slots = document.createElement('div');
      sabDiv.appendChild(slots);
      const maxedHTML = buildSabMaxedLineHTML(info);
      if (maxedHTML) {
        const maxedLine = document.createElement('div');
        maxedLine.innerHTML = maxedHTML;
        sabDiv.appendChild(maxedLine);
      }
      renders.push({ el: slots, fn: () => renderSabSlotsLine(slots, rec, 'sab', info.sabCap, info) });
    }

    // Revenge panel (KoC only renders this section while the target is maxed)
    const revAnchor = findRowByText(/last successful Reven/i) ||
                      findRowByText(/Successful Revenge Sabbs/i) ||
                      findRowByText(/Revenge Sabotage Attempts/i);
    const revDiv = mkPanel('tdc-rev-panel', revAnchor);
    if (revDiv) {
      const slots = document.createElement('div');
      revDiv.appendChild(slots);
      renders.push({ el: slots, fn: () => renderSabSlotsLine(slots, rec, 'rev', info.revCap, info) });
    }
    return renders;
  }

  let __sabTickId = null;
  function startSabTicker(renders) {
    if (__sabTickId) return;
    const tick = () => {
      let alive = false;
      for (const r of renders) {
        if (r.el.isConnected) { alive = true; r.fn(); }
      }
      if (!alive) { clearInterval(__sabTickId); __sabTickId = null; }
    };
    tick();
    __sabTickId = setInterval(tick, 1000);
  }

  function initSabTracker() {
    const info = parseSabPageInfo();
    if (!info) return;
    // A page brought back with Back / Forward shows the counters as they were
    // then: draw from the log as it stands, and neither drop a press nor
    // reconcile against those old numbers.
    const restored = pageNavType() === 'back_forward';
    if (!restored) {
      // The game answered the last press with a refusal — "You have used the
      // maximum sabotage attempts against this player in 24 hours." or "This
      // player has been maxxed …" — so that press was not an attempt.
      const boxes = attackMissionBoxes();
      const maxWord = attackPageMaxAttempts(boxes);
      if ((maxWord && /^sab/.test(maxWord)) || attackPageRefusedMaxed(boxes)) {
        dropRefusedPress(info.targetId, 'sab', Date.now());
      }
    }
    relativizeMissionTimestamps();
    const rec = restored
      ? (getSabLog()[info.targetId] || { sab: [], rev: [] })
      : reconcileSabLog(info);
    const renders = injectSabPanels(info, rec);
    if (renders.length) startSabTicker(renders);
    debugLog('🕵️ Sab Tracker initialised', {
      target: info.targetId, sab: rec.sab.length, rev: rec.rev.length, maxed: info.maxed
    });

  }

  // The target's two cap numbers, sent under the "Sabotage caps" share so the
  // War Room can show how much of each target's daily cap is left. Not sent
  // from a page brought back with Back / Forward: its numbers are old.
  function sendSabCaps() {
    const info = parseSabPageInfo();
    if (!info || info.maxLoss == null || info.lost24 == null) return;
    if (pageNavType() === 'back_forward') return;
    const now = getKoCServerTimeUTC();
    Promise.resolve(auth.apiCall('sab-caps', 'players', {
      id: info.targetId,
      sabLost24h: info.lost24,
      sabLost24hTime: now,
      sabMaxDaily: info.maxLoss,
      sabMaxDailyTime: now
    })).catch(() => { /* a failed send never breaks the page */ });
  }

  /**
   * Passive capture of sab submissions on EVERY page (covert mission reports
   * carry direct "Sabotage Again!"/"Revenge Again!" re-fire buttons too).
   * Listens on both click and submit — KoC's inline onclick handlers call
   * form.submit(), which does not fire a submit event — deduped via a mark.
   */
  function hookSabFormCapture() {
    if (window.__tdcSabHooked) return;
    window.__tdcSabHooked = true;

    const maybeRecord = (form, btn) => {
      if (!form || form.tagName !== 'FORM') return;
      if ((form.method || 'get').toLowerCase() !== 'post') return; // report-page "Sabotage!" nav buttons are GET
      const action = (form.getAttribute('action') || '').toLowerCase();
      if (action && !/attack\.php|inteldetail\.php/.test(action)) return;
      const mtEl = form.querySelector('input[name="mission_type"]');
      const mt = ((mtEl && mtEl.value) || '').toLowerCase();
      const btnVal = ((btn && btn.value) || '').toLowerCase();
      if (!(mt.includes('sab') || (!mt && btnVal.includes('sabotage')))) return;
      if (form.__tdcSabMark && Date.now() - form.__tdcSabMark < 4000) return;

      // Revenge if the field says so, or the form sits under a "Revenge Sabotage" header
      let isRev = mt.includes('revenge');
      if (!isRev) {
        let tbl = (btn || form).closest ? (btn || form).closest('table') : null;
        for (let i = 0; i < 4 && tbl && !isRev; i++) {
          const th = tbl.querySelector('th');
          if (th && /Revenge Sabotage/i.test(th.textContent || '')) isRev = true;
          else if (th && /^\s*Sabotage Mission\s*$/i.test(th.textContent || '')) break;
          tbl = tbl.parentElement ? tbl.parentElement.closest('table') : null;
        }
      }

      const didEl = form.querySelector('input[name="defender_id"]');
      const didVal = didEl && /^\d+$/.test(didEl.value || '') ? didEl.value : null;
      const targetId = didVal || (location.search.match(/[?&]id=(\d+)/) || [])[1];
      if (!targetId) return;

      form.__tdcSabMark = Date.now();
      recordSabAttempt(String(targetId), isRev ? 'rev' : 'sab', Date.now(), 'click');
      debugLog(`🕵️ Sab Tracker: recorded ${isRev ? 'revenge ' : ''}sab attempt on ${targetId}`);
    };

    document.addEventListener('click', (e) => {
      try {
        const btn = e.target && e.target.closest ? e.target.closest('input[type="submit"], button[type="submit"]') : null;
        if (btn && btn.form) maybeRecord(btn.form, btn);
      } catch (err) { /* never interfere with the game's own handlers */ }
    }, true);

    document.addEventListener('submit', (e) => {
      try {
        if (e.target && e.target.tagName === 'FORM') maybeRecord(e.target, e.submitter || null);
      } catch (err) { /* never interfere with the game's own handlers */ }
    }, true);
  }

  /**
   * intelfile.php?asset_id=… lists every mission you've run on that target with
   * exact server timestamps — use it to backfill/correct the tracked window.
   * The page is read by parseIntelFilePage (below), the same read the Mission
   * history log sends to the roster, so the two can never disagree about a row.
   */
  function collectFromIntelFilePage() {
    const page = parseIntelFilePage();
    if (!page || !page.targetId) return;
    const targetId = page.targetId;
    const now = Date.now();
    const found = { sab: [], rev: [] };

    // Mission Type is found by its header: the Time column spans two cells
    // ("6" | "hours ago").
    for (const row of page.rows) {
      const type = (row.missionText || '').trim().toLowerCase();
      let kind = null;
      if (type === 'sabotage') kind = 'sab';
      else if (type.includes('revenge')) kind = 'rev'; // "Revenge_sabotage"
      else continue;
      if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(row.at || '')) continue;
      const t = Date.parse(convertKoCServerTimeToUTC(row.at));
      if (isNaN(t) || now - t >= SAB_WINDOW_MS) continue;
      found[kind].push({ t, src: 'file' }); // aborted attempts still count toward the 10/4 caps
    }
    if (!found.sab.length && !found.rev.length) return;

    const log = getSabLog();
    const rec = log[targetId] || (log[targetId] = { sab: [], rev: [] });
    for (const kind of ['sab', 'rev']) {
      if (!found[kind].length) continue;
      const cur = (rec[kind] || []).filter(e => e && now - e.t < SAB_WINDOW_MS);
      // Server timestamps are authoritative — adopt them when at least as complete
      // (page 1 only shows the 10 newest reports, so never shrink the tracked set)
      if (found[kind].length >= cur.length) rec[kind] = found[kind].sort((a, b) => a.t - b.t);
    }
    rec.seen = now;
    saveSabLog(log);
    debugLog(`🕵️ Sab Tracker: intel-file backfill for ${targetId}`, {
      sab: found.sab.length, rev: found.rev.length
    });
  }

  // ==================== MISSION HISTORY (mission-log) ====================
  //
  // Five game pages list missions with their results, and two more describe
  // one mission in full:
  //   intelfile.php  — YOUR recon and sab missions on one target (Success /
  //                    Aborted, each linked to its report)
  //   poisonlog.php  — poison missions against you and by you
  //   theftlog.php   — theft missions against you and by you, with the weapon
  //                    and how many were taken
  //   intel.php      — recon and sab missions other players ran AGAINST you
  //                    ("Intercepted Intelligence Operations"; no result shown)
  //   attacklog.php  — attacks against you and by you, with gold and losses
  //   inteldetail.php — any sab report you open (the one you just ran, or an
  //                    old one reached from the intel file)
  //   theft_report.php — the report of a theft YOU made: what you stole, or
  //                    that it failed (a report of somebody stealing from you
  //                    is skipped)
  //   detail.php     — the battle report of an attack or raid YOU made (the
  //                    one you land on, or an old one opened from the Attack
  //                    Log); reports of other players hitting you are skipped
  // Together they are every member's mission record: what each of us tried,
  // what worked, and who has been working on us. The War Room turns it into
  // success rates per member and per mission type.
  //
  // Only the page the member opened is read. Nothing here turns a page, opens
  // a report, follows a link or fetches anything — the rules forbid scripts
  // that gather information on their own or load pages in bulk — and the
  // pages are left exactly as the game drew them. One request per page view.
  //
  // What goes to the server is the page's own TEXT, cell by cell: the mission
  // type, the result and the attack-log action exactly as printed. Several of
  // those wordings have never been seen yet (a successful poison, a successful
  // theft report, a raid in the attack log, how the intel file labels a
  // revenge sab), so the script does not guess at them: the server maps text
  // to missions and results in one place, keeps the raw text, and a wording
  // learned later is fixed there — rows already stored get reclassified from
  // what they said. Numbers go as printed too ("1,125"); the server parses them.
  //
  // Tables are found by their TITLE and columns by their HEADER name, never by
  // position: the Time column is two cells on some pages ("6" | "hours ago")
  // under a header that is one cell with a colspan, so a fixed index — or even
  // a header's own index — puts every value one place off. Columns here are
  // matched on where each cell STARTS, counting colspans, which lines the
  // header up with the data on every one of these pages. The attack log is
  // the one exception allowed a fallback: its row layout was validated live
  // (11 cells). A header row there is trusted only once its first row shows
  // it lines up — the player link under Enemy, the battle link under Result;
  // a header that does not is dropped for the validated layout, and rows
  // that fit neither are not sent (shifted values would be stored as fact).
  //
  // Which side a log is on ("Attacks Against You" / "Attacks By You") comes
  // from its title, and a log whose title cannot be read is SKIPPED — never
  // handed the neighbouring log's side. On the poison and theft logs nothing
  // else on a row could catch that mistake, and every mission in the table
  // would be stored the wrong way round.

  /** A row's own TD/TH cells — never the cells of a table nested inside one. */
  function missionRowCells(tr) {
    return tr ? [...tr.children].filter((c) => c.tagName === 'TD' || c.tagName === 'TH') : [];
  }

  /** A table's own rows, in order; rows of a table nested in a cell belong to that table. */
  function missionOwnRows(table) {
    return table ? [...table.querySelectorAll('tr')].filter((tr) => tr.closest('table') === table) : [];
  }

  /**
   * An element's text as it reads on screen, one entry per line: a <br> or
   * the edge of a block (paragraph, div, row) ends a line. textContent alone
   * runs "0<br>0" into "00" and a report's sentences into one another.
   */
  function missionTextLines(el) {
    const lines = [];
    let cur = '';
    const BLOCK = /^(P|DIV|TR|TABLE|TBODY|THEAD|UL|OL|LI|CENTER|BLOCKQUOTE|H[1-6])$/;
    const walk = (node) => {
      if (node.nodeType === 3) { cur += node.textContent || ''; return; }
      if (node.nodeType !== 1) return;
      const tag = node.tagName;
      if (tag === 'SCRIPT' || tag === 'STYLE') return;
      if (tag === 'BR') { lines.push(cur); cur = ''; return; }
      const block = BLOCK.test(tag);
      if (block) { lines.push(cur); cur = ''; }
      for (const child of node.childNodes) walk(child);
      if (block) { lines.push(cur); cur = ''; }
      else if (tag === 'TD' || tag === 'TH') cur += ' ';
    };
    if (el) walk(el);
    lines.push(cur);
    return lines.map((l) => l.replace(/\s+/g, ' ').trim()).filter(Boolean);
  }

  /** A cell's text on one line ("0<br>0" -> "0 0"); an empty or missing cell is null, never "". */
  function missionCellText(el) {
    const t = missionTextLines(el).join(' ').trim();
    return t || null;
  }

  /** Header names compare as lower-case letters and digits: "TimeStamp", "Time Stamp", "Number of<br>Spies". */
  function missionHeadKey(text) {
    return String(text || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  /**
   * Each own cell of a row with the column it starts at, counting colspans.
   * The theft log's header is "Time" spanning two columns over data rows
   * that split it ("43" | "minutes ago"), so the header's third cell (Result)
   * sits over the data's fourth.
   */
  function missionColumns(tr) {
    let col = 0;
    return missionRowCells(tr).map((cell) => {
      const span = Math.max(1, parseInt(cell.getAttribute('colspan') || '1', 10) || 1);
      const out = { cell, start: col };
      col += span;
      return out;
    });
  }

  /** A header row's columns by name: { key: { start, text } }. Blank headers are left out. */
  function missionHeaderMap(tr) {
    const map = {};
    for (const { cell, start } of missionColumns(tr)) {
      const text = missionCellText(cell);
      const key = missionHeadKey(text);
      if (key && !(key in map)) map[key] = { start, text };
    }
    return map;
  }

  /** The cell of a data row that starts at a header's column; null when the header or the cell is missing. */
  function missionCellAt(tr, head) {
    if (!head) return null;
    const hit = missionColumns(tr).find((c) => c.start === head.start);
    return hit ? hit.cell : null;
  }

  /**
   * True when a row's own cells include every one of these header names.
   * Without names: true for ANY row of column names — three or more <th>
   * cells, or a cell reading Enemy, Mission Type or TimeStamp (the intel
   * file writes its headers as <td><b>). A row with a player link or a table
   * inside is never one. The section readers use this to tell where one
   * log's rows end and another's begin.
   */
  function missionIsHeaderRow(tr, keys) {
    const cells = missionRowCells(tr);
    const have = new Set(cells.map((c) => missionHeadKey(missionCellText(c))));
    if (keys) return keys.every((k) => have.has(k));
    if (!cells.length || tr.querySelector('a[href*="stats.php?id="]') || cells.some((c) => c.querySelector('table'))) return false;
    return (cells.length >= 3 && cells.every((c) => c.tagName === 'TH')) ||
      ['enemy', 'missiontype', 'timestamp'].some((k) => have.has(k));
  }

  /** Every header row on the page with all of these header names, in page order. */
  function missionHeaderRows(keys) {
    return [...document.querySelectorAll('tr')].filter((tr) => missionIsHeaderRow(tr, keys));
  }

  /**
   * "Attacks Against You" -> 'against', "Attacks By You" -> 'by', anything
   * else null. Only a cell with no table inside it can be a title, so a layout
   * cell that merely CONTAINS a titled table is never read as one.
   */
  function missionTitleSide(cell) {
    if (!cell || cell.querySelector('table')) return null;
    const m = (missionCellText(cell) || '').match(/^attacks\s+(against|by)\s+you\b/i);
    return m ? m[1].toLowerCase() : null;
  }

  /**
   * Which log a row belongs to — 'against', 'by', or null when that cannot
   * be read for certain. The row is a log's header row (poison and theft
   * logs) or one of its data rows (the attack log decides row by row, since
   * two logs can share one table). The game puts the title in three
   * different places: the poison log in the data table's own first row, the
   * theft log in a <th> of the table AROUND the data table, and the attack
   * log in a separate little table just above it. So: look upward from the
   * row — through its own table, then each enclosing table — for the
   * nearest title; failing that, the last title before the row in page order.
   *
   * A log must never inherit ANOTHER log's side, so anything showing that a
   * different section starts between the row and a title ends the search
   * with null instead of being walked past:
   *   - a heading this script cannot read ("Thefts Made By You", a title
   *     reworded) or a section's edge ("21 attacks total | page 1 of 3") —
   *     <th> cells or one lone cell with text, no player link, no table;
   *   - another log's column names or its player rows (a data row may pass
   *     its OWN log's rows and header on the way up, nothing more);
   *   - titles side by side ("Attacks Against You" | "Attacks By You" over
   *     two columns): only the title that starts in exactly the same column
   *     as the cell holding the row counts — none there, no side.
   * The page-order walk forgets its title at the same signs, and at a
   * column-name row unless that row sits directly above the section (the
   * attack log may keep its column names in its title's table). Callers
   * skip whatever comes back null.
   *
   * One exception: climbing from a HEADER row, a pager row ("21 attacks
   * total | page 1 of 3") is walked past — the game may print it between a
   * log's title and its column names, and the captures do not say which
   * end it sits at. That is safe from a header row because any other log
   * met on the way up shows itself by its own column names first.
   */
  function missionLogSide(el) {
    if (!el) return null;
    const elIsHead = missionIsHeaderRow(el);
    const hasLinks = (tr) => !!tr.querySelector('a[href*="stats.php?id="], a[href*="attack_id="], a[href*="report_id="]');
    const pager = (tr) => /\bpage\s+\d+\s+of\s+\d+\b/i.test(missionCellText(tr) || '');
    const heading = (tr) => {
      const cells = missionRowCells(tr);
      if (!cells.length || hasLinks(tr) || cells.some((c) => c.querySelector('table')) || missionIsHeaderRow(tr)) return false;
      if (cells.length > 1 && !cells.every((c) => c.tagName === 'TH')) return false;
      if (elIsHead && pager(tr)) return false;
      return cells.some((c) => missionCellText(c) !== null);
    };
    const holdsLog = (tr) => !!tr.querySelector('a[href*="stats.php?id="]') ||
      [tr, ...tr.querySelectorAll('tr')].some((r) => missionIsHeaderRow(r));
    // A title row: a lone title cell names the side of everything under it;
    // titles side by side only name the column they start in.
    const titleOf = (row, anchor, node) => {
      const cells = missionRowCells(row);
      if (cells.length === 1) return missionTitleSide(cells[0]);
      const mine = missionColumns(anchor).find((c) => c.cell === node || c.cell.contains(node));
      const over = mine ? missionColumns(row).find((c) => c.start === mine.start) : null;
      return over ? missionTitleSide(over.cell) : null;
    };

    // 1. The row's own table. A data row may climb past rows of its own log
    //    and then its own header row; a header row may climb past nothing.
    const table0 = el.closest('table');
    const rows0 = missionOwnRows(table0);
    let top = el;                         // the highest row of el's own section
    let passedHead = elIsHead;
    for (let i = rows0.indexOf(el) - 1; i >= 0; i--) {
      const row = rows0[i];
      if (missionRowCells(row).some((c) => missionTitleSide(c))) return titleOf(row, el, el);
      if (heading(row)) return null;
      if (missionIsHeaderRow(row)) { if (passedHead) return null; passedHead = true; top = row; continue; }
      if (hasLinks(row) || row.querySelector('table')) { if (passedHead) return null; top = row; continue; }
    }

    // 2. Each enclosing table, from the row that holds the inner table.
    let node = table0;
    let table = node && node.parentElement ? node.parentElement.closest('table') : null;
    while (table) {
      const rows = missionOwnRows(table);
      const anchor = node.closest('tr');
      for (let i = rows.indexOf(anchor) - 1; i >= 0; i--) {
        const row = rows[i];
        if (missionRowCells(row).some((c) => missionTitleSide(c))) return titleOf(row, anchor, node);
        if (heading(row) || holdsLog(row)) return null;
      }
      node = table;
      table = table.parentElement ? table.parentElement.closest('table') : null;
    }

    // 3. Page order: the last title before the section.
    const ownHead = missionIsHeaderRow(top);
    let last = null;
    let pendingHead = false;              // a column-name row just passed: ours only if the section follows at once
    for (const tr of document.querySelectorAll('tr')) {
      if (tr === top) break;
      if (tr.contains(el)) continue;      // layout rows around the section
      const cells = missionRowCells(tr);
      if (cells.some((c) => missionTitleSide(c))) {
        last = cells.length === 1 ? missionTitleSide(cells[0]) : null;
        pendingHead = false;
      } else if (missionIsHeaderRow(tr)) {
        if (ownHead || pendingHead) last = null;
        pendingHead = true;
      } else if (heading(tr) || tr.querySelector('a[href*="stats.php?id="]')) {
        last = null;
        pendingHead = false;
      } else if (pendingHead && missionCellText(tr) !== null) {
        last = null;
        pendingHead = false;
      }
    }
    return last;
  }

  /**
   * The data rows under a header row: its table's own rows after it, up to
   * the next section — a row of <th> cells (any title or header row), a row
   * holding an "Attacks Against/By You" title, or another row of column
   * names — so two logs sharing one table are never run together. Layout
   * rows — the "21 attacks total | page 1 of 3" footer, spacers — come
   * through too; each reader drops rows that carry neither a link id nor a
   * timestamp.
   */
  function missionDataRows(headerRow, keys) {
    const rows = missionOwnRows(headerRow.closest('table'));
    const out = [];
    for (const tr of rows.slice(rows.indexOf(headerRow) + 1)) {
      const cells = missionRowCells(tr);
      if (cells.length && cells.every((c) => c.tagName === 'TH')) break;
      if (cells.some((c) => missionTitleSide(c))) break;
      if (missionIsHeaderRow(tr, keys) || missionIsHeaderRow(tr)) break;
      out.push(tr);
    }
    return out;
  }

  /**
   * The numeric id in a link inside an element — stats.php?id=, report_id=,
   * attack_id= — optionally only from links to one page. null when absent.
   */
  function missionLinkId(el, param, pageRe) {
    if (!el) return null;
    const re = new RegExp('[?&]' + param + '=(\\d+)');
    for (const a of el.querySelectorAll('a[href]')) {
      const href = a.getAttribute('href') || '';
      if (pageRe && !pageRe.test(href)) continue;
      const m = href.match(re);
      if (m) return m[1];
    }
    return null;
  }

  /**
   * A row's KoC timestamp as printed ("2026-09-17 21:00:17", server time; the
   * server converts it). From the TimeStamp column; if that cell holds no
   * stamp, the one cell whose whole text is a stamp; otherwise the TimeStamp
   * cell's text as it is, which the server counts as invalid — that is how a
   * changed format shows up rather than rows silently vanishing.
   */
  function missionStamp(tr, head) {
    const text = missionCellText(missionCellAt(tr, head));
    const m = text && text.match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);
    if (m) return m[0];
    for (const c of missionRowCells(tr)) {
      const t = missionCellText(c);
      if (t && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(t)) return t;
    }
    return text;
  }

  /** True for a printed KoC timestamp. */
  function missionIsStamp(s) {
    return /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s || '');
  }

  /** "Att Sold DA Sold" -> "attSoldDaSold": a poison-log column name as a key. */
  function missionCamelKey(text) {
    const words = String(text || '').split(/[^A-Za-z0-9]+/).filter(Boolean);
    return words.map((w, i) => i === 0 ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join('');
  }

  /**
   * intelfile.php?asset_id=T — "Intelligence on <name>": your recon and sab
   * missions on one target, newest first. Rows sit under the header row that
   * has "Mission Type"; the Result cell links the report (report_id=). The
   * Sab Tracker backfill reads the same rows (collectFromIntelFilePage).
   */
  function parseIntelFilePage() {
    const targetId = (location.search.match(/[?&]asset_id=(\d+)/) || [])[1] || null;
    const keys = ['missiontype', 'result'];
    const headerRow = missionHeaderRows(keys)[0];
    if (!headerRow) return null;
    const head = missionHeaderMap(headerRow);

    let targetName = null;
    for (const cell of document.querySelectorAll('th, td')) {
      if (cell.querySelector('table')) continue;
      const m = (missionCellText(cell) || '').match(/^Intelligence on\s+(.+)$/i);
      if (m) { targetName = m[1].trim(); break; }
    }

    const rows = [];
    for (const tr of missionDataRows(headerRow, keys)) {
      const resultCell = missionCellAt(tr, head.result);
      const row = {
        missionText: missionCellText(missionCellAt(tr, head.missiontype)),
        spies: missionCellText(missionCellAt(tr, head.numberofspies)),
        resultText: missionCellText(resultCell),
        reportId: missionLinkId(resultCell, 'report_id'),
        at: missionStamp(tr, head.timestamp)
      };
      if (!row.reportId && !missionIsStamp(row.at)) continue;   // footer / spacer
      rows.push(row);
    }
    return { targetId, targetName, rows };
  }

  /**
   * poisonlog.php and theftlog.php: an "Attacks Against You" and an "Attacks
   * By You" table, each with a header row holding "Enemy" and "Result". Per
   * row: the enemy (stats.php?id= link; the cell's text as shown, "(not
   * active)" and all — the server strips it), the result and its report id,
   * the timestamp; the theft log adds the weapon and how many, the poison log
   * its unit-loss pairs ("0 0") keyed by their column names. A table whose
   * title cannot be found is skipped: without it, who hit whom is unknown.
   */
  function parseMissionLogPage(source) {
    const keys = ['enemy', 'result'];
    const fixed = new Set(['time', 'enemy', 'result', 'timestamp', 'weaponstolen', 'count']);
    const rows = [];
    for (const headerRow of missionHeaderRows(keys)) {
      const side = missionLogSide(headerRow);
      if (!side) { debugLog(`📜 Mission log: a ${source} table has no "Attacks Against/By You" title — skipped`); continue; }
      const head = missionHeaderMap(headerRow);
      for (const tr of missionDataRows(headerRow, keys)) {
        const enemyCell = missionCellAt(tr, head.enemy);
        const resultCell = missionCellAt(tr, head.result);
        const row = {
          side,
          enemyId: missionLinkId(enemyCell, 'id', /stats\.php/),
          enemyName: missionCellText(enemyCell),
          resultText: missionCellText(resultCell),
          reportId: missionLinkId(resultCell, 'report_id'),
          at: missionStamp(tr, head.timestamp)
        };
        if (!row.enemyId && !row.reportId && !missionIsStamp(row.at)) continue;   // footer / spacer
        if (source === 'theftlog') {
          row.weapon = missionCellText(missionCellAt(tr, head.weaponstolen));
          row.count = missionCellText(missionCellAt(tr, head.count));
        } else {
          row.units = {};
          for (const [key, h] of Object.entries(head)) {
            if (!fixed.has(key)) row.units[missionCamelKey(h.text)] = missionCellText(missionCellAt(tr, h));
          }
        }
        rows.push(row);
      }
    }
    return rows;
  }

  /**
   * intel.php — only the "Intercepted Intelligence Operations" section:
   * recon and sab missions run AGAINST you (Time | Enemy | Alliance | Mission
   * Type | Number of Spies | Spies Caught | TimeStamp). The section is found
   * by its TITLE: the header row is the first one after that title, before
   * any other heading, and its rows end at the next section. The "Outgoing
   * Intelligence Files" list (your own files on other players) is never
   * sent, whether it is its own table, as captured, or shares this one. No
   * title, nothing sent. The page does not say whether a mission succeeded;
   * it does say how many of their spies were caught.
   */
  function parseInterceptedOpsPage() {
    const keys = ['enemy', 'missiontype', 'spiescaught'];
    const outgoing = (tr) => missionRowCells(tr).some((c) => /^outgoing intelligence files\b/i.test(missionCellText(c) || ''));
    const all = [...document.querySelectorAll('tr')];
    const titleRow = all.find((tr) => missionRowCells(tr).some((c) =>
      !c.querySelector('table') && /^intercepted intelligence operations\b/i.test(missionCellText(c) || '')));
    if (!titleRow) { debugLog('📜 Mission log: no "Intercepted Intelligence Operations" title on intel.php — nothing read'); return []; }
    let headerRow = null;
    for (const tr of all.slice(all.indexOf(titleRow) + 1)) {
      if (missionIsHeaderRow(tr, keys)) { headerRow = tr; break; }
      const cells = missionRowCells(tr);
      if (outgoing(tr) || (cells.length && cells.every((c) => c.tagName === 'TH'))) break;   // another section first
    }
    if (!headerRow) return [];
    const head = missionHeaderMap(headerRow);
    const rows = [];
    for (const tr of missionDataRows(headerRow, keys)) {
      if (outgoing(tr)) break;
      const enemyCell = missionCellAt(tr, head.enemy);
      const row = {
        enemyId: missionLinkId(enemyCell, 'id', /stats\.php/),
        enemyName: missionCellText(enemyCell),
        alliance: missionCellText(missionCellAt(tr, head.alliance)),
        missionText: missionCellText(missionCellAt(tr, head.missiontype)),
        spies: missionCellText(missionCellAt(tr, head.numberofspies)),
        caught: missionCellText(missionCellAt(tr, head.spiescaught)),
        at: missionStamp(tr, head.timestamp)
      };
      if (!row.enemyId && !missionIsStamp(row.at)) continue;   // "142 operations total | page 1 of 15"
      rows.push(row);
    }
    return rows;
  }

  /**
   * attacklog.php — the "Attacks Against You" and "Attacks By You" row tables
   * (not the 24-hour summary tables above them). Validated live: each row is
   * 11 cells — time number, time unit, action ("you attacked" / "attacked
   * by"), enemy (stats.php?id=), result (detail.php?attack_id=, "N Gold
   * stolen" / "Attack defended"), enemy losses, your losses, hostages, damage
   * by the enemy, damage by you, timestamp.
   *
   * Columns: a table is read in sections, each starting at a row of column
   * names (rows above the first have none). A section's header is trusted
   * only if its FIRST row — the first with both a player link and a battle
   * link — has the player link under Enemy and the battle link under
   * Result. If it does not (KoC is not consistent: "Time" is one cell over
   * three on some pages), the validated 11-cell layout is used instead when
   * that row fits it ([3] player link, [4] battle link); a section that
   * fits neither is skipped with a debug line rather than sent with every
   * value shifted. Under a trusted header, the position map still fills in
   * columns the header does not name, but only when the header agrees with
   * it on Enemy and Result.
   *
   * Side: decided per row, from the title over that row's own run — two
   * logs can share one table. A readable title decides. The wording ("you
   * attacked" / "attacked by"; a raid is expected to read
   * the same way) is used only when there is no title; when it disagrees
   * with the title the row goes with the title's side and a debug line.
   * Wording nobody has seen never drops a row: with no title either, the
   * row is sent without a side and the server reads the wording it keeps.
   *
   * The summary enhancer (enhanceAttackLog) reads the same page on its own,
   * untouched by this.
   */
  function parseAttackLogRows() {
    const POS = { action: 2, enemy: 3, result: 4, enemyLosses: 5, yourLosses: 6, hostages: 7, dmgByEnemy: 8, dmgByYou: 9, timestamp: 10 };
    const statsLink = (el) => !!(el && el.querySelector('a[href*="stats.php?id="]'));
    const battleLink = (el) => !!(el && el.querySelector('a[href*="attack_id="]'));
    const wordingSide = (t) => !t ? null
      : /\bby you\b/i.test(t) || /^you\b/i.test(t) ? 'by' : /\bby\b/i.test(t) ? 'against' : null;
    const tables = [];
    for (const tr of document.querySelectorAll('tr')) {
      const cells = missionRowCells(tr);
      if (cells.length < 8 || !cells.some((c) => battleLink(c))) continue;
      const t = tr.closest('table');
      if (t && !tables.includes(t)) tables.push(t);
    }

    const rows = [];
    for (const table of tables) {
      const sections = [{ headerRow: null, body: [] }];
      for (const tr of missionOwnRows(table)) {
        if (missionIsHeaderRow(tr)) sections.push({ headerRow: tr, body: [] });
        else sections[sections.length - 1].body.push(tr);
      }

      for (const { headerRow, body } of sections) {
        const probe = body.find((tr) => statsLink(tr) && battleLink(tr));
        if (!probe) continue;
        let head = null;
        if (headerRow) {
          const map = missionHeaderMap(headerRow);
          const pick = (re) => { const k = Object.keys(map).find((key) => re.test(key)); return k ? map[k] : null; };
          head = {
            action: pick(/^(action|type|attacktype)$/),
            enemy: map.enemy || null,
            result: map.result || null,
            enemyLosses: pick(/^enemy.*(loss|casualt|killed)/),
            yourLosses: pick(/^(your|you).*(loss|casualt|killed)/),
            hostages: pick(/hostage/),
            dmgByEnemy: pick(/(damage|dmg).*enemy|^enemy.*(damage|dmg)/),
            dmgByYou: pick(/(damage|dmg).*you|^(your|you).*(damage|dmg)/),
            timestamp: map.timestamp || null
          };
          if (!statsLink(missionCellAt(probe, head.enemy)) || !battleLink(missionCellAt(probe, head.result))) head = null;
        }
        const probeCells = missionRowCells(probe);
        const fitsPositions = probeCells.length === 11 && statsLink(probeCells[POS.enemy]) && battleLink(probeCells[POS.result]);
        if (!head && !fitsPositions) {
          debugLog('📜 Mission log: attack-log columns do not line up with the rows — section skipped',
            { header: headerRow ? missionCellText(headerRow) : null, cells: probeCells.length });
          continue;
        }
        if (headerRow && !head) {
          debugLog('📜 Mission log: attack-log header does not match its rows — read by the validated 11-cell layout',
            { header: missionCellText(headerRow) });
        }

        for (const tr of body) {
          const cells = missionRowCells(tr);
          const positional = cells.length === 11 &&
            (!head || (head.enemy.start === POS.enemy && head.result.start === POS.result));
          const col = (f) => (head && head[f]) || (positional ? { start: POS[f] } : null);
          const text = (f) => missionCellText(missionCellAt(tr, col(f)));
          const enemyCell = missionCellAt(tr, col('enemy'));
          const resultCell = missionCellAt(tr, col('result'));
          const actionText = text('action');
          const row = {
            side: null,
            enemyId: missionLinkId(enemyCell, 'id', /stats\.php/),
            enemyName: missionCellText(enemyCell),
            actionText,
            resultText: missionCellText(resultCell),
            attackId: missionLinkId(resultCell, 'attack_id') || missionLinkId(tr, 'attack_id'),
            enemyLosses: text('enemyLosses'),
            yourLosses: text('yourLosses'),
            hostages: text('hostages'),
            dmgByEnemy: text('dmgByEnemy'),
            dmgByYou: text('dmgByYou'),
            at: missionStamp(tr, col('timestamp'))
          };
          if (!row.attackId && !row.enemyId && !missionIsStamp(row.at)) continue;   // footer / spacer
          if (!head && !positional) {
            debugLog('📜 Mission log: attack-log row is not in the 11-cell layout — skipped', { cells: cells.length });
            continue;
          }
          const titled = missionLogSide(tr);
          const worded = wordingSide(actionText);
          if (titled && worded && worded !== titled) {
            debugLog('📜 Mission log: attack-log wording disagrees with its title — sent with the title\'s side', { title: titled, actionText });
          }
          row.side = titled || worded;
          if (!row.side) debugLog('📜 Mission log: attack-log row with no title and unknown wording — sent for the server to read', { actionText });
          rows.push(row);
        }
      }
    }
    return rows;
  }

  /**
   * The id of whoever this member most recently fired a sab or revenge sab
   * at, if that was within windowMs — from the Sab Tracker's own log
   * (KoC_SabLog), which hookSabFormCapture writes the moment the button is
   * pressed. A report page lands a second or two later, so a short window
   * ties the report to the mission; anything older is not trusted. Pure.
   *
   * A guess (est) is not a press: reconcileSabLog's pads stand at the moment
   * the page was opened, which would otherwise read as "just fired at".
   */
  function recentSabTargetId(log, nowMs, windowMs) {
    let best = null;
    for (const [id, rec] of Object.entries(log && typeof log === 'object' ? log : {})) {
      for (const e of [...((rec && rec.sab) || []), ...((rec && rec.rev) || [])]) {
        if (!e || e.est || typeof e.t !== 'number' || nowMs - e.t > windowMs || e.t - nowMs > 5000) continue;
        if (!best || e.t > best.t) best = { id, t: e.t };
      }
    }
    return best ? best.id : null;
  }

  /**
   * The whole page as it reads on screen, in order, one entry per line (<br>
   * and block edges end a line; a link inside a sentence stays part of it),
   * with null wherever a table starts or ends. The report pages below find
   * their report in this by its wording and end it at a table edge.
   *
   * Report pages cannot simply be read by one element: on the live pages the
   * report's title table holds only its title and closes at once, and the
   * report sentences sit loose in the page's own content cell (sab reports)
   * or in a table of their own after the button tables (battle reports) —
   * next to the era notice, the footer links and the copyright lines. The
   * walk starts at the document root, not document.body: the live pages open
   * an <a name="top"> before their <body> tag, which some parsers answer
   * with a second, empty body element.
   */
  function missionPageLines() {
    const out = [];
    let cur = '';
    const endLine = () => { const l = cur.replace(/\s+/g, ' ').trim(); if (l) out.push(l); cur = ''; };
    const BLOCK = /^(P|DIV|TR|TD|TH|TBODY|THEAD|UL|OL|LI|CENTER|BLOCKQUOTE|FORM|H[1-6])$/;
    const walk = (node) => {
      if (node.nodeType === 3) { cur += node.textContent || ''; return; }
      if (node.nodeType !== 1) return;
      const tag = node.tagName;
      if (tag === 'SCRIPT' || tag === 'STYLE') return;
      if (tag === 'BR') { endLine(); return; }
      const table = tag === 'TABLE';
      const block = table || BLOCK.test(tag);
      if (block) endLine();
      if (table) out.push(null);
      for (const child of node.childNodes) walk(child);
      if (block) endLine();
      if (table) out.push(null);
    };
    walk(document.documentElement);
    endLine();
    return out;
  }

  /**
   * The text lines of a sab report (inteldetail.php) — the report and
   * nothing else. On the live page the "Covert Mission Report" table holds
   * only its title and closes at once; the report sentences sit loose in the
   * page's own content cell, after the Attack / Raid / Recon button tables,
   * split by <p>, and are followed by the "Return to Top" table and the
   * footer. So the report is the line with "attempt to sabotage" (the
   * dispatch line) and every line after it up to the first table edge — the
   * "Return to Top" table on the live page, or the end of the table cell
   * when a report sits inside one. Nothing before the dispatch line is part
   * of it.
   */
  function sabReportLines() {
    const out = missionPageLines();
    const start = out.findIndex((l) => l !== null && /attempt to sabotage/i.test(l));
    if (start < 0) return [];
    const lines = [];
    for (const l of out.slice(start)) {
      if (l === null) break;
      lines.push(l);
    }
    return lines.slice(0, 60).map((l) => l.slice(0, 500));
  }

  /**
   * inteldetail.php?report_id=R when it is a SAB report ("… to attempt to
   * sabotage 1125 Nunchakus."). Recon reports share the page and are left to
   * collectFromIntelDetailPage. The lines go to the server as printed; it
   * reads weapons destroyed, spies and sentries executed, gold and XP from
   * them, and only "You were successful in destroying" counts as a success.
   * The target: the page's own "Sabotage Again!" form names them
   * (defender_id) when it is there; otherwise the sab this member fired in
   * the last 2 minutes; otherwise unknown — the report id still ties the row
   * to the same mission in the intel file.
   * The name: "While inside <name>'s armory" (a success) or "Your spies are
   * spotted inside <name>'s armory" (a failure).
   * The time: a sab report prints none. The report the member LANDED on,
   * straight after "Sabotage Now" or "… Again!" (covertReportJustLanded), is
   * the sab just fired, so the Server Time that page rendered (PAGE_KOC_TIME,
   * as printed; the server converts it) is its time: `at` and `landed: true`.
   * A report opened later, reloaded or restored, or one whose page time could
   * not be read, carries neither — its intel-file row brings the time.
   */
  function parseSabReportPage() {
    const reportId = (location.search.match(/[?&]report_id=(\d+)/) || [])[1] || null;
    if (!reportId) return null;
    const lines = sabReportLines();
    const dispatch = lines.find((l) => /attempt to sabotage/i.test(l));
    if (!dispatch) return null;
    const inside = lines.map((l) => l.match(/\binside (.+?)(?:'s|’s|'|’) armory/i)).find(Boolean);
    const form = document.querySelector('input[name="defender_id"]');
    const targetId = form && /^\d+$/.test(form.value || '')
      ? form.value
      : recentSabTargetId(getSabLog(), Date.now(), 2 * 60 * 1000);
    const landed = covertReportJustLanded(reportId, 'inteldetail.php') === true && !!PAGE_KOC_TIME;
    return {
      source: 'report',
      family: 'intel',
      reportId,
      targetId,
      targetName: inside ? inside[1].trim() : null,
      missionText: dispatch,
      lines,
      ...(landed ? { at: PAGE_KOC_TIME, landed: true } : {})
    };
  }

  /**
   * The text lines of a battle report (detail.php) — [] when the page holds
   * none. The live page: a first
   * table holds, on a win, "You stole N gold while raiding <name>'s camp and
   * made off with H hostages (…)." over a "Battle Report" title (a lost
   * battle shows no such line; the defender's own message may sit there
   * instead); then the Attack / Raid / Recon and Sabotage / Poison / Steal
   * button tables; then the battle itself in one table cell, from "Your
   * soldiers march onto the battlefield" to the outcome ("You trounced the
   * enemy!" … / "<name>'s forces overpowered your army!"); then an empty
   * table and the footer.
   *
   * "Your soldiers march onto the battlefield" is how the battle is FOUND,
   * nothing more: the report of someone attacking the member opens with the
   * same words ("<name> took ya N gold while attacking you …" above the
   * title instead). Whose attack it was is battleReportIsOwnAttack's call,
   * made on these lines. The battle is the LAST line that IS that sentence
   * (it starts the line): a defender's message sits in the title's table,
   * above the buttons and the battle, and may quote the sentence — even as a
   * line of its own.
   *
   * The lines are the report's own, and nothing a player wrote: its first
   * line, the title, then the battle up to the first table edge after it
   * (the end of the battle's own cell, or the next table when the text sits
   * loose in the page). The first line is looked for in the title's own
   * table (everywhere above the battle if there is no title): the "You
   * stole N gold while … <name>'s camp" line that agrees with the battle
   * (battleReportStoleLine), else a "<name> took ya …" line whose <name>
   * the battle names as the one who attacked ("<name>'s forces attack and
   * inflict …") — each only at the very start of a line — else there is
   * none. A defender's message in that table is left out, even one that
   * starts with the game's words: a message line "nuke took ya 5 gold …"
   * over the member's own lost raid is not the report's first line, because
   * that battle has nuke counter-attacking, not attacking.
   * At most 80 lines.
   */
  function battleReportLines() {
    const out = missionPageLines();
    let march = -1;
    for (let i = out.length - 1; i >= 0 && march < 0; i--) {
      if (out[i] !== null && /^your soldiers march onto the battlefield\b/i.test(out[i])) march = i;
    }
    if (march < 0) return [];
    const battle = [];
    for (const l of out.slice(march)) {
      if (l === null) break;
      battle.push(l);
    }
    let title = march - 1;
    while (title >= 0 && !(out[title] !== null && /^battle\s+report$/i.test(out[title]))) title--;
    let top = title;
    while (top > 0 && out[top - 1] !== null) top--;
    const above = (title >= 0 ? out.slice(top, title) : out.slice(0, march)).filter((l) => l !== null);
    const stole = battleReportStoleLine([
      ...above.filter((l) => /^You stole [\d,]+ gold while (?:attacking|raiding) .+?'s camp/i.test(l)), ...battle]);
    const hitBy = battle.map((l) => l.match(/^(\S+?)'s forces attack and inflict\b/i)).find(Boolean);
    const tookYa = (l) => {
      const m = l.match(/^(\S+) took ya\b/i);
      return !!m && !!hitBy && m[1].toLowerCase() === hitBy[1].toLowerCase();
    };
    const first = stole ? stole.input : above.find(tookYa);
    const lines = [...(first ? [first] : []), ...(title >= 0 ? [out[title]] : []), ...battle];
    return lines.slice(0, 80).map((l) => l.slice(0, 500));
  }

  /**
   * The label of the button the game renamed for the mission just fought —
   * "Raid Again!" / "Attack Again!" in the battle report's button row — or
   * null. As printed (the value attribute), not as a
   * click may have relabelled it since.
   */
  function battleReportAgainButton() {
    for (const el of document.querySelectorAll('input[type="submit"], input[type="button"], button')) {
      const label = String((el.tagName === 'BUTTON' ? el.textContent : el.getAttribute('value')) || '').replace(/\s+/g, ' ').trim();
      if (/again!?$/i.test(label)) return label;
    }
    return null;
  }

  /**
   * Whether this battle report is the battle just fought — the page the game
   * put the member on when they launched it — so the page's Server Time is
   * the battle's time. true, false, or null when the browser cannot say.
   *
   * Launching a battle posts a form — attack.php's Attack / Raid buttons, the
   * ones on a recon, theft or poison report, a battle report's "Raid Again!"
   * / "Attack Again!" — and the game answers with a REDIRECT to this report.
   * Attacks launched from recon reports land with Navigation Timing type
   * 'navigate', redirectCount 1 and the recon report (inteldetail.php) as
   * the referrer, so the redirect count decides, not the referrer. On the
   * navigation entry:
   *   - type not 'navigate' (a reload, Back / Forward, a prerender): false —
   *     a revisit keeps the old referrer, but its Server Time is the
   *     revisit's;
   *   - 'navigate' through at least one redirect: true, whichever page
   *     launched the battle;
   *   - 'navigate' with no redirect: a plain link — a report opened later
   *     from the Attack Log, say (redirectCount 0, referrer attacklog.php)
   *     — false; but null when the referrer is attack.php or another
   *     battle's report (a landing whose redirect the browser did not count
   *     must never read as old). One exception: the game's report addresses
   *     carry "suspense" (the
   *     Attack Log links &suspense=0). If landing goes through a suspense
   *     view of the battle first and then on to the plain report of that
   *     same battle, the referrer is the same report with a non-zero
   *     suspense and this page's differs — still the landing, seconds after
   *     the battle. (Taken on trust: the Attack Log's links say suspense=0,
   *     so a suspense view is assumed to be the landing's own.)
   * An entry of type 'navigate' that does not count redirects falls back to
   * the referrer rule: from attack.php, from another battle report (a chain of
   * "… Again!"), or the suspense hop — true; anything else null. No
   * navigation entry (or no type) at all is null. Null, not false: not
   * knowing how the page was reached does not make it a report opened
   * later. A known reload or Back / Forward is false whether or not
   * redirects are counted.
   * Logs how the page was reached (debug mode).
   */
  function battleReportJustFought(reportId) {
    let type = null;
    let redirects = null;
    try {
      const nav = performance.getEntriesByType('navigation')[0];
      type = nav && typeof nav.type === 'string' ? nav.type : null;
      redirects = nav && typeof nav.redirectCount === 'number' && Number.isFinite(nav.redirectCount) ? nav.redirectCount : null;
    } catch (e) {
      type = null;
      redirects = null;
    }
    const ref = String(document.referrer || '');
    debugLog('📜 Mission log: battle report reached', { page: `${location.pathname || ''}${location.search || ''}`, referrer: ref, navigation: type, redirectCount: redirects });
    const prev = ref.match(/\/detail\.php\?(?:[^#]*&)?attack_id=(\d+)/i);
    const sameBattle = !!prev && prev[1] === String(reportId);
    const suspense = (q) => (String(q || '').match(/[?&]suspense=([^&#]*)/i) || [])[1];
    const was = sameBattle ? suspense(ref) : undefined;
    const suspenseHop = was !== undefined && was !== '' && was !== '0' && was !== suspense(location.search);
    if (type !== null && type !== 'navigate') return false;
    if (type === 'navigate' && redirects !== null) {
      if (redirects >= 1 || suspenseHop) return true;
      // No redirect counted, but reached from a page that launches battles
      // (attack.php, or another battle's report): the referrer rule says
      // landing. A real landing looks like this only if the browser missed
      // the redirect (a cross-origin hop in the chain, a privacy mode) — and
      // false there would stop the theft coming off the target for good. So
      // say "cannot tell" (null: the server subtracts the gold).
      // The Attack Log (redirectCount 0, referrer attacklog.php) and every
      // other plain link stay false.
      if (/\/attack\.php(?:[?#]|$)/i.test(ref) || (prev && !sameBattle)) return null;
      return false;
    }
    // The browser does not say (enough): the referrer rule, its "no" a null.
    if (type !== 'navigate') return null;
    if (/\/attack\.php(?:[?#]|$)/i.test(ref)) return true;
    if (prev && !sameBattle) return true;
    return suspenseHop ? true : null;
  }

  /**
   * Whether this sab report (page 'inteldetail.php') or theft report
   * ('theft_report.php') is the mission just run — the page the game put the
   * member on after "Sabotage Now", "Steal" or an "… Again!" button — so the
   * Server Time it rendered is that mission's time. true, false, or null when
   * the browser cannot say. Both land like battle reports, a fresh load
   * ('navigate') through ONE redirect from attack.php.
   *   - a reload, Back / Forward or a prerender: false (the Server Time is the
   *     revisit's);
   *   - 'navigate' through a redirect: true;
   *   - 'navigate' with no redirect: from the Intelligence file, the Theft Log
   *     or any other link, false; from attack.php or ANOTHER report on the
   *     same page (an "… Again!" chain), null — a landing whose redirect the
   *     browser did not count must never read as old;
   *   - 'navigate' but the browser does not count redirects: from attack.php
   *     or another report, true; otherwise null;
   *   - no navigation entry (or no type): null.
   * battleReportJustFought is the battle report's own rule and stays apart.
   */
  function covertReportJustLanded(reportId, page) {
    const entry = pageNavEntry();
    const kind = entry.type;
    const count = entry.redirects;
    const ref = String(document.referrer || '');
    debugLog('📜 Mission log: report reached', { page, referrer: ref, navigation: kind, redirectCount: count });
    const file = String(page || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const prev = ref.match(new RegExp('/' + file + '\\?(?:[^#]*&)?report_id=(\\d+)', 'i'));
    const otherReport = !!prev && prev[1] !== String(reportId);
    const fromAttack = /\/attack\.php(?:[?#]|$)/i.test(ref);
    if (kind !== null && kind !== 'navigate') return false;
    if (kind === 'navigate' && count !== null) {
      if (count >= 1) return true;
      return (fromAttack || otherReport) ? null : false;
    }
    if (kind === 'navigate') return (fromAttack || otherReport) ? true : null;
    return null;
  }

  /**
   * detail.php?attack_id=A — the battle report of an attack or raid the
   * member made (battleReportIsOwnAttack decides; a report of another
   * player's attack on the member, or anything else, sends nothing).
   *
   * Only a WON raid says "raid" in its text ("… while raiding <name>'s
   * camp"); a lost raid and a lost attack read the same. The page's button
   * row does say: the game relabels the button for the mission just fought
   * "Raid Again!" / "Attack Again!" — but not always (some pages show plain
   * "Attack!" / "Raid!"). So each field is what the page states, or
   * null — never a guess:
   *   missionText — the "… Again!" button's label; else the "while raiding"
   *                 / "while attacking" phrase of the "You stole" line; else
   *                 null (the Attack Log row with the same attack id names
   *                 the mission; the server keeps whichever it gets).
   *   resultText  — the "You stole N gold while … <name>'s camp …" line (a
   *                 win), else the "<name>'s forces overpowered your army!"
   *                 sentence (a loss), else null — each only at the start of
   *                 a line, so a defender's message cannot supply it. As
   *                 printed; the server interprets.
   *   at          — the report has no timestamp of its own. Landed on
   *                 straight after launching the battle — from attack.php, a
   *                 recon / theft / poison report or the previous report's
   *                 "… Again!" button (battleReportJustFought says true) —
   *                 this page IS the battle just fought, and the page's
   *                 Server Time is its time. Opened any other way — later,
   *                 from the Attack Log, or by a reload — or when the
   *                 browser cannot say (null), that clock could date it by
   *                 the re-read, so null: the Attack Log row with the same
   *                 attack id has the time.
   *   targetId    — the player collectAttackLog files the battle against.
   * A report whose battle text links the member's OWN stats page shows the
   * member as the defender, whatever its wording, and is skipped too: the
   * server keeps the first attacker it is told, so one misread report would
   * file an enemy's hit on us as our own attack for good.
   */
  function parseBattleReportPage() {
    const reportId = (location.search.match(/[?&]attack_id=(\d+)/) || [])[1] || null;
    if (!reportId) return null;
    const lines = battleReportLines();
    if (!lines.length) return null;
    if (!battleReportIsOwnAttack(lines)) {
      debugLog('📜 Mission log: not a report of your own attack or raid (another player\'s attack on you, or not drawn yet) — not recorded');
      return null;
    }

    const myId = SafeStorage.get('KoC_MyId', null);
    const marchCells = [...document.querySelectorAll('td')]
      .filter((c) => /your soldiers march onto the battlefield/i.test(c.textContent || ''));
    const battleCell = marchCells[marchCells.length - 1];   // the innermost: a nested cell comes after the cells around it
    const namesMe = !!(myId && battleCell) && [...battleCell.querySelectorAll('a[href*="stats.php?id="]')]
      .some((a) => ((a.getAttribute('href') || '').match(/[?&]id=(\d+)/) || [])[1] === String(myId));
    if (namesMe) {
      debugLog('📜 Mission log: this battle report has you as the defender — not recorded as your attack');
      return null;
    }

    const stole = battleReportStoleLine(lines);
    const phrase = stole ? (stole[0].match(/\bwhile\s+(?:raiding|attacking)\b/i) || [])[0] || null : null;
    const lost = lines.map((l) => l.match(/^\s*\S+?'s forces overpowered your army\b!?/i)).find(Boolean);
    return {
      source: 'report',
      family: 'battle',
      reportId,
      targetId: battleReportTargetId(myId),
      targetName: battleReportTargetName(lines),
      missionText: battleReportAgainButton() || phrase,
      resultText: stole ? stole.input.trim() : (lost ? lost[0].trim() : null),
      at: battleReportJustFought(reportId) === true ? getKoCServerTimeUTC() : null,
      lines
    };
  }

  /**
   * Whose theft a theft report (theft_report.php) shows: the member's own,
   * or the view the game gives the player who was stolen FROM. Both sides
   * get the same page — the member's own theft and the defender's view of
   * another player's theft on the member (opened from the Theft Log's
   * "Attacks Against You") share the title "Kings of Chaos :: Battle
   * Report", the header "Theft Battle Report" and the same buttons, "Steal
   * Again!" among them; and on the defender's view every form carries the
   * ATTACKER's id as defender_id, so the victim can steal back. So neither
   * the buttons nor the ids can tell the views apart. Only the wording can,
   * as with battle reports (battleReportIsOwnAttack).
   *
   * Ours = a line STARTS with one of the member's own two sentences ("You
   * successfully stole N <weapon> from <name>'s camp." / "You failed to
   * steal any <weapon> from <name>'s camp.") and NO line carries a
   * defender's mark. The marks are the game's stopped wording ("You
   * stopped <name>'s plan and saved your armory."), "your armory" and a
   * theft "from your camp" — a lost defence is still unseen, so the
   * wordings it would most likely use are refused too.
   *
   * The own sentence is held to the start of a line, so a message quoting
   * the game cannot pass for the report; and a defender's mark anywhere on
   * the page vetoes it, so a message CRAFTED to read like the member's own
   * theft cannot turn the victim's view into an attack of theirs. A theft
   * misfiled that way would stay wrong for good (the roster keeps the first
   * attacker it is told); a theft skipped is not lost — the Theft Log
   * carries the row.
   */
  function theftReportIsOwnTheft(lines) {
    const list = (lines || []).filter((l) => typeof l === 'string').map((l) => l.trim());
    const has = (re) => list.some((l) => re.test(l));
    const defender = has(/^You stopped\b[^]{0,120}?(?:'s|’s|'|’) plan\b/i) ||
      has(/\byour armou?ry\b/i) ||
      has(/\bfrom your camp\b/i) ||
      has(/^(?!You\b)\S+ (?:successfully )?stole\b/i);
    if (defender) return false;
    return has(/^You (?:successfully stole [\d,]+ |failed to steal any )/i);
  }

  /**
   * theft_report.php?report_id=R — the report of a theft the MEMBER made
   * (page title "Battle Report", header "Theft Battle Report"): "You
   * successfully stole 183 Chariot from <name>'s camp." (the name links the
   * target's stats page); a failure reads "You failed to steal any Chariot
   * from <name>'s camp.". Every button form
   * on it ("Steal Again!", Attack!, Raid!, Poison! …) carries the target as
   * defender_id.
   *
   * Whose theft it is is theftReportIsOwnTheft's call, from the wording
   * alone; a report that is not certainly the member's own sends nothing.
   * The report itself is the first line that STARTS with one of those two
   * sentences, up to the next table edge (at most 20 lines) — never a
   * message that quotes one. And it is recorded only when the camp is
   * somebody else's. Nothing is sent when the camp is the member's own (the
   * view of somebody stealing from the member), when the page's ids include
   * the member's own, or when the page names two different players — whose
   * theft it was cannot then be told, and the roster keeps the first
   * attacker it is told.
   *   targetName  — the camp's owner, as printed
   *   targetId    — the owner's stats link and every form's defender_id, all
   *                 agreeing; null when the page has neither
   *   missionText — the "Steal Again!" button's label as printed, else null
   *   resultText  — the sentence, as printed; the server reads it
   *   at, landed  — as on the sab report: the report LANDED on straight after
   *                 "Steal" or "Steal Again!" (covertReportJustLanded) carries
   *                 the Server Time that page rendered; any other does not,
   *                 and its Theft Log row brings the time
   * Reads only; the page is left exactly as the game drew it.
   */
  function parseTheftReportPage() {
    const reportId = (location.search.match(/[?&]report_id=(\d+)/) || [])[1] || null;
    if (!reportId) return null;
    const all = missionPageLines();
    if (!theftReportIsOwnTheft(all)) {
      debugLog('📜 Mission log: not a report of your own theft (the view of somebody stealing from you, or not drawn yet) — not recorded');
      return null;
    }
    const start = all.findIndex((l) => l !== null && /^You (?:successfully stole [\d,]+ |failed to steal any )/i.test(l));
    if (start < 0) return null;
    const lines = [];
    for (const l of all.slice(start)) {
      if (l === null || lines.length >= 20) break;
      lines.push(l.slice(0, 500));
    }
    const sentence = lines[0];
    const said = sentence.match(/^You (?:successfully stole [\d,]+ .+?|failed to steal any .+?) from (.+?)(?:'s|’s|'|’) camp\b/i);
    if (!said) return null;
    const owner = said[1].trim();
    const myId = SafeStorage.get('KoC_MyId', null);
    const myName = SafeStorage.get('KoC_MyName', null);
    if (myName && owner.toLowerCase() === String(myName).trim().toLowerCase()) {
      debugLog('📜 Mission log: a theft report of your own camp (somebody stealing from you) — not recorded');
      return null;
    }
    // The owner's stats link (its text may carry the "'s") and every form's defender_id.
    const bare = (t) => String(t || '').replace(/\s+/g, ' ').trim().replace(/(?:'s|’s|'|’)$/i, '');
    const ids = new Set();
    for (const a of document.querySelectorAll('a[href*="stats.php?id="]')) {
      const id = ((a.getAttribute('href') || '').match(/[?&]id=(\d+)/) || [])[1];
      if (id && bare(a.textContent).toLowerCase() === owner.toLowerCase()) ids.add(id);
    }
    for (const input of document.querySelectorAll('form input[name="defender_id"]')) {
      if (/^\d+$/.test(input.value || '')) ids.add(input.value);
    }
    if (myId && ids.has(String(myId))) {
      debugLog('📜 Mission log: this theft report points at your own id — not recorded');
      return null;
    }
    if (ids.size > 1) {
      debugLog('📜 Mission log: this theft report names two different players — not recorded', [...ids]);
      return null;
    }
    let missionText = null;
    for (const el of document.querySelectorAll('input[type="submit"], input[type="button"], button')) {
      const label = String((el.tagName === 'BUTTON' ? el.textContent : el.getAttribute('value')) || '').replace(/\s+/g, ' ').trim();
      if (/^steal again!?$/i.test(label)) { missionText = label; break; }
    }
    const landed = covertReportJustLanded(reportId, 'theft_report.php') === true && !!PAGE_KOC_TIME;
    return {
      source: 'report',
      family: 'theft',
      reportId,
      targetId: ids.size === 1 ? [...ids][0] : null,
      targetName: owner,
      missionText,
      resultText: sentence,
      lines,
      ...(landed ? { at: PAGE_KOC_TIME, landed: true } : {})
    };
  }

  /**
   * Which mission page this is, from the address; null on every other page.
   * 'battle' is a battle report (detail.php — only with an attack_id, the
   * same guard collectAttackLog uses); 'report' is the sab report page;
   * 'theftreport' is the theft report page.
   */
  function missionLogSource() {
    const page = (location.pathname.split('/').pop() || '').toLowerCase();
    if (page === 'detail.php') return /[?&]attack_id=\d/.test(location.search) ? 'battle' : null;
    return ({
      'intelfile.php': 'intelfile',
      'poisonlog.php': 'poisonlog',
      'theftlog.php': 'theftlog',
      'intel.php': 'intel',
      'attacklog.php': 'attacklog',
      'inteldetail.php': 'report',
      'theft_report.php': 'theftreport'
    })[page] || null;
  }

  /**
   * The request body for POST api/war-room/missions (utils/missions.js reads
   * it), or null when the page holds nothing to record. At most 200 rows —
   * the server's cap; a page shows 10 per table.
   */
  function buildMissionPayload(source) {
    const cap = (rows) => rows.slice(0, 200);
    if (source === 'intelfile') {
      const page = parseIntelFilePage();
      return page && page.rows.length
        ? { source, targetId: page.targetId, targetName: page.targetName, rows: cap(page.rows) } : null;
    }
    if (source === 'poisonlog' || source === 'theftlog') {
      const rows = parseMissionLogPage(source);
      return rows.length ? { source, rows: cap(rows) } : null;
    }
    if (source === 'intel') {
      const rows = parseInterceptedOpsPage();
      return rows.length ? { source, rows: cap(rows) } : null;
    }
    if (source === 'attacklog') {
      const rows = parseAttackLogRows();
      return rows.length ? { source, rows: cap(rows) } : null;
    }
    if (source === 'report') return parseSabReportPage();
    if (source === 'theftreport') return parseTheftReportPage();
    if (source === 'battle') return parseBattleReportPage();
    return null;
  }

  // Set once this page view's COMPLETE request has gone out. A battle report
  // is read twice (at once, and again ATTACK_LOG_DELAY_MS later, like
  // collectAttackLog, in case its text was not there yet). Only a read of
  // the WHOLE battle (battleReportWhole — the same test collectAttackLog
  // uses; a won report's outcome is its first line, drawn before the
  // battle, so the outcome alone is not enough) sets it: an earlier read
  // must not stop the later one from sending the whole report. Every other
  // page is read once, complete as it stands.
  let missionLogSent = false;

  /**
   * One request per page view, fire-and-forget: nothing on the page waits on
   * it or changes because of it, and a failure is only ever a debug line.
   * The server dedupes (by report id where the page links one), so a reload
   * or the same mission seen from both sides never counts twice.
   *
   * readAgain: another read of this page follows (the battle report's first
   * read). A battle report not yet drawn to its closing lines is then held
   * back for that read rather than sent half-drawn — the server keeps the
   * first copy's text of a report and would not take the whole one after
   * it. The last read sends what it finds.
   */
  function sendMissionLog({ readAgain = false } = {}) {
    if (missionLogSent) return null;
    let body = null;
    try {
      const source = missionLogSource();
      body = source ? buildMissionPayload(source) : null;
    } catch (e) {
      debugLog('📜 Mission log: page not read', e);
      return null;
    }
    if (!body) { debugLog('📜 Mission log: nothing to record on this page'); return null; }
    const complete = body.family !== 'battle' || (!!body.resultText && battleReportWhole(body.lines));
    if (!complete && readAgain) {
      debugLog('📜 Mission log: battle report not all drawn yet — left for the next read');
      return null;
    }
    if (complete) missionLogSent = true;
    return Promise.resolve()
      .then(() => auth.apiCall('missions', 'api/war-room/missions', body))
      .then((res) => debugLog(`📜 Mission log (${body.source}): ${body.rows ? body.rows.length + ' rows' : 'report ' + body.reportId} sent`, res))
      .catch(() => { /* never break the page */ });
  }

  // ==================== ATTACK PAGE: MISSION BOXES ====================
  //
  // attack.php draws one box per mission — "Reconaissance Mission" (the game's
  // spelling), Attack, Poison, Theft, Sabotage and, only while the target is
  // maxed, "Revenge Sabotage Mission". Each box is its own table whose first
  // <th> is that title, and every number the game prints about YOUR side of
  // the fight is inside it: attempts used on this target in the rolling 24h,
  // successes, and the ceiling your own rating reaches ("can sab up to X
  // Sentry", "retreat if DA above X").
  //
  // Those ceilings are the game's own arithmetic (spy x1.5 for sab, x3 for
  // recon, poison x2, theft x2/3 floored, SA x40 for the retreat line). They
  // are used exactly as printed and never recomputed here, so a rule change on
  // the game's side cannot quietly put every warning out by a factor.
  //
  // Rows are read by text inside ONE box at a time, never from the page as a
  // whole: Poison and Theft both print "Successful Attempts", and a page-wide
  // search could only ever find the first of them. Rows this script inserted
  // itself (Sab Tracker panels, range warnings) are skipped, so reading the
  // page again after they are drawn gives the same answer.

  /**
   * "9,732,251,114,020.50" -> 9732251114020. KoC prints ceilings and caps with
   * decimals whenever they are not whole; gold and ratings are whole units, so
   * the fraction is dropped by string, not by float, and the integer part
   * stays exact. Anything that is not a plain number is null — never 0.
   */
  function parseAttackNum(s) {
    if (s == null) return null;
    const t = String(s).replace(/[,\s]/g, '');
    if (!/^\d+(?:\.\d+)?$/.test(t)) return null;
    return parseInt(t.split('.')[0], 10);
  }

  /**
   * The mission boxes on this page, by mission: { recon, attack, poison,
   * theft, sab, revenge } -> <table>, each present only if the page has it.
   * A box is the table directly around a <th> whose whole text is the mission
   * title — the innermost table holding it — and that <th> must be the
   * table's first, so a layout table further out is never mistaken for a box.
   * The correctly spelled "Reconnaissance" is accepted too, in case the game
   * ever fixes its typo.
   */
  function attackMissionBoxes() {
    const titles = {
      'reconaissance mission': 'recon',
      'reconnaissance mission': 'recon',
      'attack mission': 'attack',
      'poison mission': 'poison',
      'theft mission': 'theft',
      'sabotage mission': 'sab',
      'revenge sabotage mission': 'revenge'
    };
    const boxes = {};
    for (const th of document.querySelectorAll('th')) {
      const key = titles[(th.textContent || '').replace(/\s+/g, ' ').trim().toLowerCase()];
      if (!key || boxes[key]) continue;
      const table = th.closest('table');
      if (table && table.querySelector('th') === th) boxes[key] = table;
    }
    return boxes;
  }

  /**
   * One box's own rows as { tr, text }: its cells' text joined with spaces
   * (so "Theft Attempts: 0 / 10" and "Successful Attempts: 0 / 10" in two
   * cells cannot run together), whitespace collapsed. Rows of a table nested
   * inside the box belong to that table, not to the box, and rows this script
   * drew (marked data-kdc, or holding a Sab Tracker "tdc-" panel) are left out.
   */
  function missionBoxRows(box) {
    const out = [];
    if (!box) return out;
    for (const tr of box.querySelectorAll('tr')) {
      if (tr.closest('table') !== box) continue;
      if (tr.hasAttribute('data-kdc') || tr.querySelector('[data-kdc], [id^="tdc-"]')) continue;
      const cells = [...tr.children].filter((c) => c.tagName === 'TD' || c.tagName === 'TH');
      const text = cells.map((c) => c.textContent || '').join(' ').replace(/\s+/g, ' ').trim();
      if (text) out.push({ tr, text, cells: cells.length });
    }
    return out;
  }

  /**
   * The red line the game puts above the mission boxes when it refuses a sab:
   * "This player has been maxxed, you can no longer sabotage them. …" (its
   * spelling). Only text OUTSIDE the mission boxes counts — the Revenge box
   * says "although X is maxxed" on every maxed view, which is not a refusal.
   * The line may be a bare text node in the content cell that also holds the
   * boxes, so an element holding a box is judged by its own text nodes only.
   */
  function attackPageRefusedMaxed(boxes) {
    return !!attackPageTopMatch(boxes, /has been maxx?ed/i);
  }

  /**
   * The first match of `re` in the text OUTSIDE the mission boxes — where the
   * game puts its red refusal lines — or null. Rows and panels this script
   * drew are skipped; an element holding a box is judged by its own text
   * nodes only (the line may be a bare text node beside the boxes).
   */
  function attackPageTopMatch(boxes, re) {
    if (!re.test(document.body.textContent || '')) return null;   // the usual page, cheaply
    const list = Object.values(boxes || {});
    for (const el of [document.body, ...document.body.querySelectorAll('*')]) {
      if (list.some((b) => b.contains(el))) continue;
      if (el.closest('[data-kdc], [id^="tdc-"]')) continue;
      const holdsBox = list.some((b) => el.contains(b));
      const text = holdsBox
        ? [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent || '').join(' ')
        : (el.textContent || '');
      const m = text.match(re);
      if (m) return m;
    }
    return null;
  }

  /**
   * The red line the game shows when the member presses once more after
   * using every attempt of a mission on this target: "You have used the
   * maximum sabotage attempts against this player in 24 hours." (a theft or
   * poison line is expected to read the same way).
   * The mission's word as printed, lower-cased ('sabotage'), or null. It is
   * proof that the MEMBER's attempts on this target are all in use — not
   * that the target is maxed.
   */
  function attackPageMaxAttempts(boxes) {
    const m = attackPageTopMatch(boxes, /You have used the maximum (\w+) attempts against this player/i);
    return m ? m[1].toLowerCase() : null;
  }

  /**
   * The KoC time ('YYYY-MM-DD HH:MM:SS', as printed) on the first of a box's
   * own rows (missionBoxRows) whose text matches labelRe — "You last sabbed:
   * 2513 Nunchaku on 2026-09-19 02:25:43" — or, once the Sab Tracker has
   * turned that stamp into an age ("… 2m ago"), the one it keeps in the
   * age's tooltip. null when the box has no such row or the row no stamp
   * ("Never"). Only ever the rows of the box asked about: a stamp is never
   * taken from anywhere else on the page.
   */
  function missionBoxStamp(rows, labelRe) {
    const stamp = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/;
    const row = (rows || []).find((r) => labelRe.test(r.text));
    if (!row) return null;
    const inText = row.text.match(stamp);
    if (inText) return inText[0];
    for (const el of row.tr.querySelectorAll('[title]')) {
      const m = (el.getAttribute('title') || '').match(stamp);
      if (m) return m[0];
    }
    return null;
  }

  /**
   * Everything the attack page says about this target and about your own
   * standing against it, read from the mission boxes (see above). Returns
   * null when this is not a readable attack page (no target, no boxes — an
   * "Invalid User ID" page, say). Every number the page does not show is
   * null, never 0; the one deliberate 0 is the game's empty "()" brackets,
   * (a target sabbed down to nothing prints empty brackets).
   *
   *   sab.limit      the sentry your spy rating can reach ("can sab up to")
   *   recon.limit    same for recon (x3 rather than x1.5)
   *   poison.limit   the antidote your poison rating can reach
   *   theft.limit    the vigilance your theft rating can reach
   *   attack.retreatDa  the DA above which your forces retreat
   *   sab / theft / poison .firstAt, .lastAt  the KoC times printed for your
   *                  first (in the last 24h) and last SUCCESSFUL mission of
   *                  that kind on the target, as printed; null when none
   *   refusedMaxAttempts  the mission word of the game's "You have used the
   *                  maximum … attempts" line ('sabotage'), or null
   */
  function parseAttackPage() {
    const targetId = attackPageTargetId();
    const boxes = attackMissionBoxes();
    if (!targetId || !Object.keys(boxes).length) return null;

    const rowsOf = {};
    for (const key of Object.keys(boxes)) rowsOf[key] = missionBoxRows(boxes[key]);
    const find = (key, re) => {
      for (const r of rowsOf[key] || []) {
        const m = r.text.match(re);
        if (m) return m;
      }
      return null;
    };
    const num = (key, re, i) => {
      const m = find(key, re);
      return m ? parseAttackNum(m[i || 1]) : null;
    };
    const frac = (key, re) => {
      const m = find(key, re);
      return m ? { used: parseAttackNum(m[1]), cap: parseAttackNum(m[2]) } : { used: null, cap: null };
    };
    const bracket = (key, re) => {
      const m = find(key, re);
      if (!m) return null;
      return m[1] === '' ? 0 : parseAttackNum(m[1]);
    };

    const reconTries = frac('recon', /Mission Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const reconReach = /Spy Rating:?\s*(\d[\d,]*(?:\.\d+)?)\s*can recon up to\s*(\d[\d,]*(?:\.\d+)?)/i;

    const attackTries = frac('attack', /Attack Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const raidTries = frac('attack', /Raid Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);

    const poisonTries = frac('poison', /Poison Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const poisonWins = frac('poison', /Successful Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const poisonReach = /Poison Rating:?\s*(\d[\d,]*(?:\.\d+)?)\s*can poison up to\s*(\d[\d,]*(?:\.\d+)?)/i;

    const theftTries = frac('theft', /Theft Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const theftWins = frac('theft', /Successful Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const theftReach = /Theft Rating:?\s*(\d[\d,]*(?:\.\d+)?)\s*can steal from up to\s*(\d[\d,]*(?:\.\d+)?)/i;

    // Anchored at the start of the row: "Revenge Sabotage Attempts" must never
    // be read as the regular counter, whichever box it turns up in.
    const sabTries = frac('sab', /^Sabotage Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const sabWins = frac('sab', /Successful Sabotage Missions:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const sabReach = /Spy Rating:?\s*(\d[\d,]*(?:\.\d+)?)\s*can sab up to\s*(\d[\d,]*(?:\.\d+)?)/i;

    const revTries = frac('revenge', /Revenge Sabotage Attempts:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);
    const revWins = frac('revenge', /Successful Revenge Sabbs:?\s*(\d[\d,]*)\s*\/\s*(\d[\d,]*)/i);

    // The times the game prints about the member's own SUCCESSFUL missions on
    // this target (a failed sab changes neither sab stamp), each read only in
    // its own box: "First sab (last 24hrs)" and "You
    // last sabbed" in the Sabotage box, "You last stole" in the Theft box, "You
    // last poisoned" in the Poison box, and a first-row time for theft or
    // poison should the game ever print one (it does not today).
    const firstRe = /^First\s+\w+\s*\(last 24\s*hrs?\)/i;
    const stamps = {
      sab: { firstAt: missionBoxStamp(rowsOf.sab, /^First\s+sab\b[^:]*\(last 24\s*hrs?\)/i), lastAt: missionBoxStamp(rowsOf.sab, /^You last sabbed\b/i) },
      theft: { firstAt: missionBoxStamp(rowsOf.theft, firstRe), lastAt: missionBoxStamp(rowsOf.theft, /^You last stole\b/i) },
      poison: { firstAt: missionBoxStamp(rowsOf.poison, firstRe), lastAt: missionBoxStamp(rowsOf.poison, /^You last poisoned\b/i) }
    };

    // The Attack box's first row under its title is the target's name on its
    // own ("<name>"). A stats.php link to this id is the fallback — never
    // just any stats link, which injected leaderboards can supply.
    let targetName = null;
    const nameRow = (rowsOf.attack || [])[1];
    if (nameRow && nameRow.cells === 1 && !/Attempts|Rating|retreat|:/i.test(nameRow.text)) {
      targetName = nameRow.text;
    } else {
      const link = document.querySelector(`a[href*="stats.php?id=${targetId}"]`);
      targetName = link && (link.textContent || '').trim() ? link.textContent.trim() : null;
    }

    return {
      targetId,
      targetName,
      refusedMaxed: attackPageRefusedMaxed(boxes),
      refusedMaxAttempts: attackPageMaxAttempts(boxes),
      recon: {
        attempts: reconTries.used, cap: reconTries.cap,
        rating: num('recon', reconReach, 1), limit: num('recon', reconReach, 2)
      },
      attack: {
        attempts: attackTries.used, cap: attackTries.cap,
        raidAttempts: raidTries.used, raidCap: raidTries.cap,
        rating: num('attack', /Attack Rating:?\s*(\d[\d,]*(?:\.\d+)?)/i),
        retreatDa: num('attack', /retreat if DA above:?\s*(\d[\d,]*(?:\.\d+)?)/i)
      },
      poison: {
        attempts: poisonTries.used, cap: poisonTries.cap, successes: poisonWins.used,
        rating: num('poison', poisonReach, 1), limit: num('poison', poisonReach, 2),
        firstAt: stamps.poison.firstAt, lastAt: stamps.poison.lastAt
      },
      theft: {
        attempts: theftTries.used, cap: theftTries.cap, successes: theftWins.used,
        tiv: bracket('theft', /Total Invested Value:?\s*\(([\d,.]*)\)/i),
        maxDaily: bracket('theft', /Maximum Daily Theft loss:?\s*\(([\d,.]*)\)/i),
        lost24h: num('theft', /Total lost from theft in the last 24\s*hours:?\s*(\d[\d,]*(?:\.\d+)?)/i),
        rating: num('theft', theftReach, 1), limit: num('theft', theftReach, 2),
        firstAt: stamps.theft.firstAt, lastAt: stamps.theft.lastAt
      },
      sab: {
        attempts: sabTries.used, cap: sabTries.cap, successes: sabWins.used,
        tiv: bracket('sab', /Total Invested Value:?\s*\(([\d,.]*)\)/i),
        maxDaily: bracket('sab', /Maximum Daily Sabotage loss:?\s*\(([\d,.]*)\)/i),
        lost24h: num('sab', /Total lost from sabbs in the last 24\s*hours:?\s*(\d[\d,]*(?:\.\d+)?)/i),
        revLost24h: num('sab', /Total lost from revenge sabbs in the last 24\s*hours:?\s*(\d[\d,]*(?:\.\d+)?)/i),
        rating: num('sab', sabReach, 1), limit: num('sab', sabReach, 2),
        firstAt: stamps.sab.firstAt, lastAt: stamps.sab.lastAt
      },
      revenge: {
        present: !!boxes.revenge,
        attempts: revTries.used, cap: revTries.cap, successes: revWins.used
      }
    };
  }

  // ==================== ATTACK PAGE: RANGE WARNINGS ====================
  //
  // The game does not stop a mission that cannot land. It lets a theft on a
  // target whose vigilance is above your reach fire and fail. So under each
  // mission's "can … up to …" line the page says whether the target is
  // actually in reach: their rating as last recorded in the alliance roster, against the
  // ceiling the game printed for you, with how old that reading is. Display
  // only — the game's forms and buttons are never touched or blocked.

  /** 249256356 -> "249.3M" — the short T/B/M form the rest of the script uses. */
  function fmtShortNum(n) {
    if (n == null || !Number.isFinite(Number(n))) return '?';
    const v = Number(n), a = Math.abs(v);
    if (a >= 1e12) return (v / 1e12).toFixed(1) + 'T';
    if (a >= 1e9) return (v / 1e9).toFixed(1) + 'B';
    if (a >= 1e6) return (v / 1e6).toFixed(1) + 'M';
    if (a >= 1e3) return (v / 1e3).toFixed(1) + 'K';
    return String(Math.round(v));
  }

  /**
   * Can this mission reach them? Pure: their rating from the roster (value +
   * its ISO time), your ceiling as printed, and the clock. Returns null when
   * the page printed no ceiling, else { state, color, head, detail } with
   * state 'in' | 'borderline' | 'out' | 'unknown'.
   *
   * Borderline = within 5% of your ceiling either side AND the reading is at
   * least an hour old (or undated). That is the only case where "may have
   * changed since" is honest: a reading taken minutes ago is simply right, so
   * a value 4.8% over says out of range, not maybe. Older than 24h the age
   * reads "old reading".
   */
  function attackRangeVerdict(mission, theirValue, theirTime, myLimit, nowMs) {
    const words = {
      sab: { stat: 'sentry', what: 'sab', fail: 'This sab will fail.' },
      poison: { stat: 'antidote', what: 'poison', fail: 'This poison will fail.' },
      theft: { stat: 'vigilance', what: 'theft', fail: 'This steal will fail.' },
      attack: { stat: 'DA', what: 'attack', fail: 'Your forces will retreat.' }
    }[mission];
    if (!words || myLimit == null || !Number.isFinite(Number(myLimit))) return null;
    const limit = Number(myLimit);
    const value = (theirValue == null || theirValue === '') ? NaN : Number(theirValue);
    if (!Number.isFinite(value)) {
      return { state: 'unknown', color: '#bbb', head: `❔ No ${words.stat} on record`, detail: ' — recon first' };
    }

    const t = theirTime ? Date.parse(theirTime) : NaN;
    const ageMs = Number.isFinite(t) ? Math.max(0, nowMs - t) : null;
    const age = ageMs == null ? 'read at an unknown time'
      : ageMs >= 24 * 3600000 ? `old reading, ${sabAgeInfo(ageMs).text}`
      : `read ${sabAgeInfo(ageMs).text}`;

    // Two numbers that shorten to the same text would say nothing — show them in full.
    let theirs = fmtShortNum(value), mine = fmtShortNum(limit);
    if (theirs === mine && value !== limit) {
      theirs = value.toLocaleString();
      mine = limit.toLocaleString();
    }
    const subject = `their ${words.stat} ${theirs} (${age})`;

    const near = Math.abs(value - limit) <= limit * 0.05;
    const settled = ageMs != null && ageMs < 3600000;
    if (near && !settled) {
      return {
        state: 'borderline', color: '#ff6', head: '⚠ Borderline',
        detail: ` — ${subject} is just ${value <= limit ? 'within' : 'above'} your ${mine}, may have changed since`
      };
    }
    if (value <= limit) {
      return { state: 'in', color: '#6f6', head: '✅ In range', detail: ` — ${subject} is within your ${mine}` };
    }
    return {
      state: 'out', color: '#f66', head: `⛔ Out of ${words.what} range`,
      detail: ` — ${subject} is above your ${mine}. ${words.fail}`
    };
  }

  /**
   * The Theft box's cap line, like the Sab Tracker's: theft losses per target
   * are capped at 7% of TIV per rolling 24h, and the page prints both the cap
   * and what has gone already. Pure; null when either number is missing.
   */
  function theftCapLine(lost24h, maxDaily) {
    if (lost24h == null || maxDaily == null) return null;
    if (lost24h >= maxDaily) {
      return {
        state: 'maxed', color: '#f66', head: '🔴 THEFT MAXED',
        detail: ` — lost ${fmtShortNum(lost24h)} of ${fmtShortNum(maxDaily)} theft cap in the last 24h`
      };
    }
    const pct = lost24h / maxDaily * 100;
    const used = pct > 0 && pct < 1 ? '<1' : String(Math.floor(pct));
    return {
      state: 'open', color: '#ffd700', head: `Theft cap: ${fmtShortNum(maxDaily - lost24h)} left`,
      detail: ` (${used}% used)`
    };
  }

  /**
   * One row straight after anchorRow, styled like the Sab Tracker's rows: a
   * bold coloured head and grey detail, centred, spanning the anchor row's
   * columns. Marked data-kdc=<kind> so it is drawn once per box and so the
   * page parser skips it. Text only (textContent) — the roster's values never
   * go through innerHTML.
   */
  function insertMissionNoteRow(anchorRow, line, title, kind) {
    if (!anchorRow || !line) return null;
    const box = anchorRow.closest('table');
    if (box && box.querySelector(`tr[data-kdc="${kind}"]`)) return null;
    let span = 0;
    for (const c of anchorRow.children) {
      if (c.tagName === 'TD' || c.tagName === 'TH') span += parseInt(c.getAttribute('colspan') || '1', 10) || 1;
    }
    const tr = document.createElement('tr');
    tr.setAttribute('data-kdc', kind);
    const td = document.createElement('td');
    td.setAttribute('colspan', String(Math.max(span, 1)));
    td.style.cssText = 'padding:6px 12px; text-align:center;';
    // An out-of-range line is a stop sign — the mission it sits above will
    // fail — so it gets a tinted band; every other line stays as quiet as the
    // Sab Tracker's.
    if (line.state === 'out') {
      td.style.background = 'rgba(255,80,80,0.14)';
      td.style.borderLeft = '3px solid #f66';
    }
    const div = document.createElement('div');
    div.style.cssText = 'font-size:12px; line-height:1.8;';
    const head = document.createElement('span');
    head.style.cssText = `color:${line.color}; font-weight:bold;`;
    head.textContent = line.head;
    const detail = document.createElement('span');
    detail.style.cssText = 'color:#bbb;';
    detail.textContent = line.detail;
    div.appendChild(head);
    div.appendChild(detail);
    if (title) div.title = title;
    td.appendChild(div);
    tr.appendChild(td);
    anchorRow.after(tr);
    return tr;
  }

  async function initAttackWarnings() {
    const page = parseAttackPage();
    if (!page) return;
    const boxes = attackMissionBoxes();
    const anchor = (key, re) => {
      for (const r of missionBoxRows(boxes[key])) if (re.test(r.text)) return r.tr;
      return null;
    };

    // Theft cap first: it is the page's own numbers, so it needs no roster call.
    const cap = theftCapLine(page.theft.lost24h, page.theft.maxDaily);
    if (cap) {
      insertMissionNoteRow(
        anchor('theft', /Total lost from theft in the last 24/i) || anchor('theft', /Maximum Daily Theft loss/i),
        cap,
        `Maximum Daily Theft loss (7% of TIV, per rolling 24h): ${page.theft.maxDaily.toLocaleString()}\n` +
        `Lost to theft in the last 24h: ${page.theft.lost24h.toLocaleString()}`,
        'theft-cap');
    }

    // Their ratings, as last recorded by anyone in the alliance. A failed
    // call shows nothing at all; "not found" just means nobody has read them
    // yet, which is worth saying ("recon first").
    let player = null;
    try { player = await auth.apiCall('read', `players/${page.targetId}`); } catch (e) { player = null; }
    if (!player) return;
    if (player.error && !/not found/i.test(String(player.error))) return;
    const rec = player.error ? {} : player;

    const now = Date.now();
    const plan = [
      { mission: 'sab', key: 'sentryRating', label: 'sentry', limit: page.sab.limit, re: /can sab up to/i },
      { mission: 'poison', key: 'antidoteRating', label: 'antidote', limit: page.poison.limit, re: /can poison up to/i },
      { mission: 'theft', key: 'vigilanceRating', label: 'vigilance', limit: page.theft.limit, re: /can steal from up to/i },
      { mission: 'attack', key: 'defensiveAction', label: 'defensive action', limit: page.attack.retreatDa, re: /retreat if DA above/i }
    ];
    let drawn = 0;
    for (const p of plan) {
      const verdict = attackRangeVerdict(p.mission, rec[p.key], rec[p.key + 'Time'], p.limit, now);
      if (!verdict) continue;
      const time = rec[p.key + 'Time'];
      const by = rec[p.key + 'UpdatedBy'];
      const title = verdict.state === 'unknown'
        ? `The alliance roster has no ${p.label} reading for this player. A recon records one for everybody.`
        : `Their ${p.label}: ${Number(rec[p.key]).toLocaleString()}` +
          (time ? ` — recorded ${convertUTCToKoCServerTime(time)} (server time)` : '') +
          (by ? ` by ${by}` : '') +
          `\nYour ceiling, as the game prints it: ${Number(p.limit).toLocaleString()}` +
          `\nThe game does not stop a mission that is out of range — it fires and fails.`;
      if (insertMissionNoteRow(anchor(p.mission, p.re), verdict, title, 'range-' + p.mission)) drawn++;
    }
    debugLog(`🎯 Range warnings for ${page.targetId}: ${drawn} drawn`);
  }

  // ==================== ATTACK PAGE: TARGET CHECKS ====================
  //
  // Every attack-page view is logged as a "check" on that target: who looked
  // and when, whether the game showed them maxed, how much of their daily sab
  // and theft caps is gone, the viewer's own attempt and success counters on
  // them, and the ceilings the game printed for the viewer. The War Room turns
  // it into "seen maxed 4m ago by NAME" — the difference between a target
  // that WAS maxed at some point and one somebody just confirmed. Automatic
  // only: there is no mark button, and opening the page is the only thing
  // that records anything.
  // A check also carries the times the page prints for the member's
  // own first and last SUCCESSFUL sab, theft and poison on the target, the
  // game's "You have used the maximum … attempts" line, and the page's own
  // navigation and Server Time — the War List tab counts down from them when
  // the member's own attempts come back. A page restored with Back / Forward
  // is not sent: its counters are old.

  const TARGET_CHECK_SENT_KEY = 'KoC_TargetCheckSent';

  /**
   * The check as the server takes it (see utils/target-checks.js). Pure but
   * for `page`, which says how this page view was reached and the Server
   * Time it was drawn with (pageInfo).
   * sab.maxed: the game says so (revenge box up, or the "has been maxxed"
   * refusal), or the losses have reached the cap; null — not false — when the
   * page showed none of that, so an unreadable box never reads as "open".
   * refusedMaxAttempts: the word of the game's "You have used the maximum …
   * attempts" line, raw ('sabotage'); the server normalises it.
   * firstAt / lastAt: the KoC times the page printed for the member's own
   * first and last SUCCESSFUL sab, theft and poison, as printed; the server
   * converts them.
   */
  function buildTargetCheckPayload(page) {
    const both = (a, b) => a != null && b != null;
    const sabMaxed = (page.revenge.present || page.refusedMaxed) ? true
      : both(page.sab.lost24h, page.sab.maxDaily) ? page.sab.lost24h >= page.sab.maxDaily
      : null;
    const theftMaxed = both(page.theft.lost24h, page.theft.maxDaily)
      ? page.theft.lost24h >= page.theft.maxDaily : null;
    return {
      targetId: page.targetId,
      refusedMaxed: page.refusedMaxed,
      refusedMaxAttempts: page.refusedMaxAttempts,
      sab: {
        attempts: page.sab.attempts, cap: page.sab.cap, successes: page.sab.successes,
        lost24h: page.sab.lost24h, maxDaily: page.sab.maxDaily, maxed: sabMaxed,
        firstAt: page.sab.firstAt, lastAt: page.sab.lastAt
      },
      revenge: {
        available: page.revenge.present,
        attempts: page.revenge.attempts, cap: page.revenge.cap, successes: page.revenge.successes
      },
      theft: {
        attempts: page.theft.attempts, cap: page.theft.cap, successes: page.theft.successes,
        lost24h: page.theft.lost24h, maxDaily: page.theft.maxDaily, maxed: theftMaxed,
        firstAt: page.theft.firstAt, lastAt: page.theft.lastAt
      },
      poison: {
        attempts: page.poison.attempts, cap: page.poison.cap, successes: page.poison.successes,
        firstAt: page.poison.firstAt, lastAt: page.poison.lastAt
      },
      attack: { attempts: page.attack.attempts, cap: page.attack.cap },
      raid: { attempts: page.attack.raidAttempts, cap: page.attack.raidCap },
      recon: { attempts: page.recon.attempts, cap: page.recon.cap },
      limits: {
        sabSentry: page.sab.limit,
        reconSentry: page.recon.limit,
        poisonAntidote: page.poison.limit,
        theftVigilance: page.theft.limit,
        attackRetreatDa: page.attack.retreatDa,
        spy: page.sab.rating != null ? page.sab.rating : page.recon.rating,
        poison: page.poison.rating,
        theft: page.theft.rating,
        attack: page.attack.rating
      },
      page: pageInfo()
    };
  }

  /**
   * What a check says about the target and the member's own counters — the
   * whole payload except the printed limits, which drift by a few points as
   * ratings tick, and the page's own time and navigation, which change on
   * every load: either would make every reload look new. The printed stamps
   * ARE part of it, so a reload showing the same stamps is still a repeat,
   * and the refusal page (its own line) is always new.
   */
  function targetCheckKey(payload) {
    const { limits, page, ...rest } = payload;
    return JSON.stringify(rest);
  }

  /**
   * True only when this exact check went out under a minute ago. A reload is
   * not news; anything else is and goes straight through — a theft, poison or
   * revenge attempt, a changed cap, and above all the page the game shows
   * after refusing a sab ("has been maxxed"), which is the one moment the
   * target is known to be maxed and must never be dropped as a repeat.
   */
  function targetCheckIsRepeat(sent, payload, nowMs) {
    const prev = sent && typeof sent === 'object' ? sent[payload.targetId] : null;
    return !!prev && nowMs - prev.t < 60000 && prev.key === targetCheckKey(payload);
  }

  function sendTargetCheck() {
    // A page brought back with Back / Forward shows the counters as they were
    // then — not a new look (the roster refuses one anyway).
    if (pageNavType() === 'back_forward') { debugLog('🎯 Target check skipped — page restored with Back/Forward'); return; }
    const page = parseAttackPage();
    if (!page) return;
    const payload = buildTargetCheckPayload(page);
    const now = Date.now();
    if (targetCheckIsRepeat(SafeStorage.get(TARGET_CHECK_SENT_KEY, {}), payload, now)) {
      debugLog(`🎯 Target check for ${payload.targetId} skipped — same as the one sent under a minute ago`);
      return;
    }
    // Not awaited: the range warnings after this step should not wait on it.
    Promise.resolve(auth.apiCall('target-checks', 'api/war-room/checks', payload)).then((res) => {
      if (!res || !res.ok) { debugLog('🎯 Target check not recorded', res); return; }
      const sent = SafeStorage.get(TARGET_CHECK_SENT_KEY, {});
      const keep = (sent && typeof sent === 'object' && !Array.isArray(sent)) ? sent : {};
      for (const [id, v] of Object.entries(keep)) {
        if (!v || now - v.t > 10 * 60000) delete keep[id];
      }
      keep[payload.targetId] = { t: now, key: targetCheckKey(payload) };
      SafeStorage.set(TARGET_CHECK_SENT_KEY, keep);
      debugLog(`🎯 Target check sent for ${payload.targetId}`, res);
    }).catch(function () { /* never break the page */ });
  }

  // ==================== FEATURE REGISTRY & SETTINGS ====================
  //
  // Every display feature is declared once in FEATURES (name, plain-English
  // description, where it runs) and run by the FEATURE_STEPS list below. The
  // ⚙ Data Centre panel draws its switches from FEATURES and SYNCS, so every
  // display feature and every share has a switch; the login, the ⚙ link and
  // reading your own id and name on the Command Centre always run.
  //
  // Switches live in localStorage[FEATURES_KEY]: {featureId: false} for a
  // display feature that is off, {'sync:id': false} for a share that is off,
  // and 'net:send' / 'net:read' for the two hard switches.

  // Every entry only changes what you see. What a feature reads from or sends
  // to the Sweet Revenge server is switched separately (SYNCS, NETWORK GATE).
  const FEATURES = [
    // — Everywhere —
    {
      id: 'server-clock', group: 'Everywhere',
      name: 'Live Server Time clock',
      desc: 'Makes the Server Time shown on every page tick forward each second instead of staying frozen at the moment the page loaded.'
    },
    {
      id: 'era-elapsed', group: 'Everywhere',
      name: 'Era day counter',
      desc: 'Adds a line under the sidebar Game Time countdown saying which day of the era it is and how long the era has been running (days, hours, minutes, seconds), ticking live.'
    },
    {
      id: 'vault-tax-warning', group: 'Everywhere',
      name: 'Vault tax warning',
      desc: 'When your sidebar Vault holds gold, a warning appears in the "Era ends in" banner from 15 minutes before each vault tax (5% every 6 hours, at 00:00, 06:00, 12:00 and 18:00 server time), with a live countdown and how much gold you will lose if you don\'t spend your vault.'
    },
    {
      id: 'sidebar-calculator', group: 'Everywhere',
      name: 'Sidebar XP→Turns calculator',
      desc: 'The calculator box under the sidebar: how many attacks your Experience and Attack Turns are worth, projected gold from them, your banked-% pill with trend graph (📈), the ✏️ manual average-gold override, and the SR logo (click it for the feature-settings popup) with the Login/Logout button. Clicking the box title opens a pop-up calculator.',
      note: 'Uses the average gold calibrated by the Attack log enhancer, and attack-log visits for gold lost. The 📈 trend graph needs Read from the server; your own snapshots are sent only while the "Banked % snapshots" share is on.'
    },
    {
      id: 'rank-neighbor-links', group: 'Everywhere',
      name: 'Rank-neighbour recon links',
      desc: 'Turns the "Rating For Previous/Next Rank Gain" numbers into links to the player we believe holds that rank, with a tooltip showing who they are and how fresh our data on them is.',
      note: 'Needs Read from the server.'
    },
    {
      id: 'sab-tracker', group: 'Everywhere',
      name: 'Sabotage Tracker',
      desc: 'On attack pages: sab and revenge-sab attempts left on the target in the rolling 24h window, a countdown until your next slot opens, damage left before the target is maxed, and colour-coded ages on "You last sabbed" timestamps. Quietly records sab missions you fire by hand, takes each one\'s exact time from the sab report you land on, and reads the target\'s Intelligence file for exact times. A press the game refuses (\'maximum sabotage attempts\', or a maxed target) is not counted as an attempt. An attempt it never saw counts from the moment you opened the page, so that countdown reads "≤" (at the latest) — late rather than early; the page\'s "First sab" time is a first successful sab and the page never says whose, so nothing is timed from it.',
      note: 'Your log of sab attempts stays in your own browser. The target\'s two cap numbers are sent only while the "Sabotage caps" share is on.'
    },

    // — Command Centre —
    {
      id: 'top-stats-panel', group: 'Command Centre',
      name: 'Sweet Revenge Top Stats panel',
      desc: 'The alliance dashboard on your Command Centre: mini leaderboards (TIV, Strike, Spy, Defense and more) built from the shared roster, plus who still has recon attempts left (members who have finished their 1,000 Unsuccessful Recons show their own Recon Missions count for the era instead, as a goldenrod 🎯 number). Each column can be shown or hidden.',
      note: 'Needs Read from the server.'
    },
    {
      id: 'slaying-comp', group: 'Command Centre',
      name: 'Slaying competitions',
      desc: 'Competition panels on the Command Centre with team leaderboards. Notes your attack missions (Rewards page) and gold stolen (Command Centre) for every running competition.',
      note: 'Your entries are sent only while the "Competitions" share is on: at most once every 5 minutes per competition, after a Rewards visit and then a Command Centre visit within 30 seconds, and right away when you press 📊 Leaderboard. The panels and leaderboards need Read from the server.'
    },

    // — Armory —
    {
      id: 'estimated-funds', group: 'Armory',
      name: 'Estimated Funds',
      desc: 'One box on the Armory, above the game’s "Available Funds", estimating the gold you hold right now: the last gold amount the game showed you (sidebar, Command Centre or Armory) plus the income earned since, from your Command Centre’s Projected Income. It says when and where that gold was read. It gives no advice, sends nothing and changes nothing on the page.'
    },
    {
      id: 'armory-sliders', group: 'Armory',
      name: 'Armory preference sliders',
      desc: 'Replaces the armory percentage boxes with auto-balancing sliders, plus one-tap presets: Cheapest first, Optimizer (uses alliance data to pick the best stat per gold), All spy, All defense, and your own saved presets.',
      note: 'The "Cheapest first" preset needs Rank-up cost display switched on. The Optimizer preset takes its gold budget from the sidebar XP calculator and asks the alliance server for the allocation, sending your gold budget, gold per point and ratings; it needs Read from the server.'
    },
    {
      id: 'stat-reshuffler', group: 'Armory',
      name: 'Stat Reshuffler',
      desc: 'The 🔀 Stat Reshuffler banner above the Armory Preferences section opens a what-if calculator: pick weapons (or whole categories) to sell, optionally switch race, and pour the proceeds — plus gold on hand if you tick it — into other stats. Projects the gold recovered, weapons you could buy, your new ratings and your new TIV after the 50% sell tax. Set a Goal (a target rating for one stat) and it also shows the gold still needed to reach it, updating live as you tweak the plan. Pure calculator: it never sells, buys or presses anything.',
      note: 'Uses the same per-stat multipliers as the Gold per Stat Point panel under the Rank Gain table (read from your rating and held weapons on every visit, or pinned by you). Warns when a stat\'s figure dates from before a skill upgrade. Weapons your units can\'t carry count as adding nothing — unless you tick "Ignore carrier caps" because you\'ll train units as needed.'
    },
    {
      id: 'rank-up-costs', group: 'Armory',
      name: 'Rank-up cost display',
      desc: 'Shows how much gold of weapons you would need to buy to claim the next rank in each stat (the "Next Rank Gain" number), and how many weapons are unheld there and what they would add if held.',
      note: 'Uses the gold per stat point from the Gold per Stat Point panel (your pins still apply with the panel switched off). Its numbers also power the armory sliders\' "Cheapest first" preset.'
    },
    {
      id: 'gpp-panel', group: 'Armory',
      name: 'Gold per Stat Point panel',
      desc: 'A collapsible table under the Rank Gain table (closed by default — click its header to open): each stat\'s gold per point, where it came from (Live, Remembered, Paired or Pinned), how much is unheld and what it would add if held, and a box to pin your own gold/pt. Its "Plan as held" tick works the rank-up costs and the Optimizer out as if every weapon you own were held — for the end-of-era push.',
      note: 'Live readings come from your rating and the weapons the game says are held, on every visit — no purchase needed. A stat you keep unheld keeps its last reading. Poison/Antidote and Theft/Vigilance borrow from each other only at equal skill levels, read when you open the Upgrades page. Pins, the tick and open/closed stay on this device.'
    },
    {
      id: 'purchase-alerts', group: 'Armory',
      name: 'Purchase check alerts',
      desc: 'After you buy weapons, reads the "You Purchased..." message and notes, without alarm, when a purchase went unheld (no units to hold it yet) — often on purpose.',
      note: 'Purchases are not used for gold per stat point (a buy that displaces weapons you already hold reads low); the Gold per Stat Point panel reads it from the page.'
    },

    // — Attack & Intel —
    {
      id: 'attack-warnings', group: 'Attack & Intel',
      name: 'Attack page range warnings',
      desc: 'On attack pages, under each mission\'s "can … up to …" line: whether the target is actually in reach — their sentry (sab), antidote (poison), vigilance (theft) and defensive action (attack) as last recorded in the alliance roster, against the limit the game prints for you — with how old that reading is. ✅ in range, ⚠ borderline (close to your limit and not freshly read), ⛔ out of range (the mission will fail; the game lets it fire anyway), ❔ no reading yet (recon first). Also adds a theft-cap line to the Theft box: how much of the target\'s daily theft cap is left, or THEFT MAXED.',
      note: 'Reads the target\'s last known ratings from the alliance roster; the read sends only the target\'s id, and needs Read from the server. If the roster cannot be reached only the theft-cap line is shown (it uses the page\'s own numbers). It never blocks or changes the game\'s forms or buttons.'
    },
    {
      id: 'attack-log-enhancer', group: 'Attack & Intel',
      name: 'Attack log enhancer',
      desc: 'Adds your average gold per attack to the attack log\'s 24-hour summary headers, and quietly notes how much gold attackers stole from you. Both numbers are saved only on your device.',
      note: 'The sidebar calculator, Optimizer preset, Safe-page comparison and Upgrades-page slay estimates all build on the average-gold number. The gold-lost figure feeds the sidebar calculator\'s banked-% trend, which does upload snapshots to the alliance server.'
    },
    {
      id: 'recon-display', group: 'Attack & Intel',
      name: 'Recon display extras',
      desc: 'Fills "???" values on stats pages and recon reports from the alliance database, adds the freshness age column to Shared Recon Info, and a "max attacks" row on recon reports.',
      note: 'Filling "???" needs Read from the server.'
    },
    {
      id: 'alt-watch-badges', group: 'Attack & Intel',
      name: 'Alt Watch badges',
      desc: 'Shows the alliance\'s Alt Watch list where you meet the player: on a stats page, a line in the Information table (🚩 RL OOC · Suspect or Confirmed for flagged accounts, 👥 for accounts on a watched alliance in a past era or this one, 🆕 for accounts made this era), and on the battlefield a 🚩 in the Icons column for accounts flagged Suspect or Confirmed. The stats page also gets an "Alt Watch" dropdown with a Save to Alt Watch button so you can flag the account yourself.',
      note: 'The badges need Read from the server (at most every 10 minutes). The Save to Alt Watch control is shown only while the "Alt Watch flags" share is on. It is the script\'s own control: the game\'s "Recognize player as" form is never touched. A flag is a member\'s call, not proof.'
    },

    // — Safe & Upgrades —
    {
      id: 'safe-forecasts', group: 'Safe & Upgrades',
      name: 'SAFE forecasts',
      desc: 'On the Safe page: how long until your safe reaches 1B / 2B / 5B / 9B / 10B (MAX) at your current deposit rate.'
    },
    {
      id: 'upgrade-timers', group: 'Safe & Upgrades',
      name: 'Upgrade timers & readiness',
      desc: '"Time to upgrade" and "EXP still needed to be deposited" under every EXP upgrade on the Safe page, and "Upgrade Ready" time and shortfall rows under the gold upgrades on the Upgrades page.',
      note: 'Uses your EXP rate captured on the Upgrades page, your safe deposit rate captured on the Safe page, and the Attack log enhancer\'s average gold for the slay estimate.'
    },
    {
      id: 'attack-alternative', group: 'Safe & Upgrades',
      name: '"Attacked Instead" comparison',
      desc: 'On the Safe page: what your stats would look like if you traded the tech upgrade\'s EXP for turns and spent the stolen gold on weapons instead, split by your actual spend preferences.',
      note: 'Needs the Attack log enhancer, and one Armory visit (for your weapons, spend preferences and gold per stat point) before it can show numbers.'
    },
    {
      id: 'tech-projector', group: 'Safe & Upgrades',
      name: 'Tech Level Projector',
      desc: 'Adds a "Project to" dropdown to the tech-upgrade table so you can preview your stats at ANY future tech level, with the total ▲% versus now and the cumulative EXP cost to get there.'
    },

    // — Other pages —
    {
      id: 'training-warnings', group: 'Other pages',
      name: 'Training page warnings',
      desc: 'A warning box at the top of the Training page: weapons or tools sitting unheld, more SA/DA weapons than trained soldiers to hold them (those drop to half effectiveness), and a missing mercenary buffer that lets your real soldiers die in combat.'
    }
  ];

  function getFeatureFlags() {
    const flags = SafeStorage.get(FEATURES_KEY, {});
    return (flags && typeof flags === 'object') ? flags : {};
  }

  function featureEnabled(id) {
    return getFeatureFlags()[id] !== false;
  }

  // A step's owner is a feature id, 'sync:<SYNCS id>' (runs while that share
  // is allowed), or 'core' (your own id and name, which every feature needs).
  // A step with several owners runs while ANY of them is on.
  function stepEnabled(f) {
    const on = (id) => id === 'core' || (id.startsWith('sync:') ? netAllowed(id.slice(5)) : featureEnabled(id));
    return Array.isArray(f) ? f.some(on) : on(f);
  }

  function setFeatureFlag(id, enabled) {
    const flags = getFeatureFlags();
    if (enabled) {
      delete flags[id];
    } else {
      flags[id] = false;
    }
    SafeStorage.set(FEATURES_KEY, flags);
  }

  function buildFeatureRow(feat) {
    const row = document.createElement('label');
    row.style.cssText = 'display:block;padding:8px 12px;border-bottom:1px solid #262c38;cursor:pointer;';

    const top = document.createElement('div');
    top.style.cssText = 'display:flex;align-items:center;gap:8px;';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = featureEnabled(feat.id);
    cb.dataset.featureId = feat.id;
    cb.className = 'kdc-feature-toggle';
    cb.style.cssText = 'width:15px;height:15px;flex:0 0 auto;margin:0;';

    const name = document.createElement('span');
    name.textContent = feat.name;
    name.style.cssText = 'font-weight:bold;color:#e8edf5;';

    top.appendChild(cb);
    top.appendChild(name);
    row.appendChild(top);

    const desc = document.createElement('div');
    desc.textContent = feat.desc;
    desc.style.cssText = 'margin:4px 0 0 23px;color:#a7b0c0;line-height:1.45;';
    row.appendChild(desc);

    if (feat.note) {
      const note = document.createElement('div');
      note.textContent = '⚠ ' + feat.note;
      note.style.cssText = 'margin:3px 0 0 23px;color:#c9a35a;font-size:11px;line-height:1.4;';
      row.appendChild(note);
    }

    return row;
  }

  function openFeatureSettings() {
    if (document.getElementById('kdc-settings-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'kdc-settings-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:1000000;display:flex;align-items:center;justify-content:center;';

    const panel = document.createElement('div');
    panel.style.cssText = 'background:linear-gradient(160deg,#1d222b,#12151b);color:#d8dee9;border:1px solid #3a4150;border-radius:10px;width:min(560px,94vw);max-height:86vh;display:flex;flex-direction:column;font-family:Verdana,Arial,sans-serif;font-size:12px;box-shadow:0 8px 30px rgba(0,0,0,0.6);';

    // Header
    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid #3a4150;';
    const title = document.createElement('div');
    // Version, and the update link when the public release is newer.
    const u = scriptUpdate;
    const behind = u && !u.isLatest;
    title.innerHTML = '<b style="color:#e8edf5;">⚙ KoC Data Centre — Features</b> ' +
      '<span style="color:#8b94a7;font-size:10px;" title="' + (u ? (behind ? 'The public release is v' + escapeHtml(u.latestVersion) : 'Up to date') : 'Could not reach the API to check for updates') + '">v' + escapeHtml(SCRIPT_VERSION) + '</span>' +
      (behind
        ? ' <a href="' + escapeHtml(u.updateUrl) + '" target="_blank" rel="noopener" title="Opens the script in your userscript manager, which will ask you to confirm the update" style="font-size:10px;font-weight:bold;color:#2a2008;background:#f0c674;border-radius:4px;padding:2px 7px;text-decoration:none;">⬆️ v' + escapeHtml(u.latestVersion) + ' available · Update</a>'
        : ' <a href="' + escapeHtml((u && u.updateUrl) || SCRIPT_UPDATE_URL) + '" target="_blank" rel="noopener" title="Opens the script in your userscript manager, which offers to reinstall it" style="font-size:10px;color:#8b94a7;text-decoration:underline;">' + (u ? 'up to date' : 'check for updates') + '</a>');
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    closeBtn.title = 'Close';
    closeBtn.style.cssText = 'margin-left:auto;background:none;border:none;color:#8b94a7;font-size:14px;cursor:pointer;padding:2px 6px;';
    header.appendChild(title);
    header.appendChild(closeBtn);
    panel.appendChild(header);

    // Scrollable body
    const body = document.createElement('div');
    body.style.cssText = 'overflow-y:auto;flex:1 1 auto;';

    // Master toggle
    const masterRow = document.createElement('label');
    masterRow.style.cssText = 'display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:2px solid #3a4150;cursor:pointer;background:rgba(255,255,255,0.03);';
    const masterCb = document.createElement('input');
    masterCb.type = 'checkbox';
    masterCb.style.cssText = 'width:16px;height:16px;flex:0 0 auto;margin:0;';
    const masterLabel = document.createElement('span');
    masterLabel.innerHTML = '<b style="color:#e8edf5;">All display features</b> <span style="color:#8b94a7;">— master switch</span>';
    masterRow.appendChild(masterCb);
    masterRow.appendChild(masterLabel);
    body.appendChild(masterRow);

    // Script login: where it is, and what it sends
    const loginInfo = document.createElement('div');
    loginInfo.style.cssText = 'padding:8px 12px;border-bottom:1px solid #3a4150;font-size:11px;line-height:1.5;';
    const loginHead = document.createElement('div');
    loginHead.innerHTML = '<b style="color:#e8edf5;">Script login</b>';
    const loginNow = document.createElement('span');
    loginNow.style.cssText = 'color:#8b94a7;';
    loginNow.textContent = ' — ' + srLoginStatusText();
    loginHead.appendChild(loginNow);
    const loginWhat = document.createElement('div');
    loginWhat.style.cssText = 'color:#8b94a7;';
    loginWhat.textContent = 'Log in and out from the box under User Info in your Command Center. ' + SR_LOGIN_SENDS +
      ' The server answers with a code that you send to ' + SR_APPROVERS_TEXT + ' in an in-game message yourself; the script never sends it for you.';
    loginInfo.appendChild(loginHead);
    loginInfo.appendChild(loginWhat);
    body.appendChild(loginInfo);

    // Feature groups
    const groups = [];
    for (const feat of FEATURES) {
      if (!groups.includes(feat.group)) groups.push(feat.group);
    }
    const groupHead = (text) => {
      const gh = document.createElement('div');
      gh.textContent = text;
      gh.style.cssText = 'padding:8px 12px 4px 12px;color:#7ea0c9;font-size:10px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;';
      return gh;
    };
    for (const group of groups) {
      body.appendChild(groupHead(group));
      for (const feat of FEATURES) {
        if (feat.group === group) body.appendChild(buildFeatureRow(feat));
      }
    }

    body.appendChild(buildNetworkSection(groupHead));
    panel.appendChild(body);

    // Reload notice (revealed on first change)
    const reloadBar = document.createElement('div');
    reloadBar.style.cssText = 'display:none;align-items:center;gap:8px;padding:8px 12px;background:#3d2f13;color:#f0c674;border-top:1px solid #57431d;font-size:11px;';
    const reloadMsg = document.createElement('span');
    reloadMsg.textContent = 'Changes take effect after the page reloads.';
    const reloadBtn = document.createElement('button');
    reloadBtn.textContent = 'Reload now';
    reloadBtn.style.cssText = 'margin-left:auto;background:#f0c674;color:#2a2008;border:none;border-radius:4px;padding:4px 10px;font-weight:bold;cursor:pointer;';
    reloadBtn.addEventListener('click', () => location.reload());
    reloadBar.appendChild(reloadMsg);
    reloadBar.appendChild(reloadBtn);
    panel.appendChild(reloadBar);

    function refreshMaster() {
      const boxes = [...body.querySelectorAll('.kdc-feature-toggle')];
      const onCount = boxes.filter(b => b.checked).length;
      masterCb.checked = onCount === boxes.length;
      masterCb.indeterminate = onCount > 0 && onCount < boxes.length;
    }
    refreshMaster();

    body.addEventListener('change', (e) => {
      const cb = e.target;
      if (!(cb instanceof HTMLInputElement) || cb.type !== 'checkbox') return;
      if (cb === masterCb) {
        const on = masterCb.checked;
        body.querySelectorAll('.kdc-feature-toggle').forEach(b => {
          b.checked = on;
          setFeatureFlag(b.dataset.featureId, on);
        });
      } else if (cb.classList.contains('kdc-feature-toggle')) {
        setFeatureFlag(cb.dataset.featureId, cb.checked);
      } else if (cb.dataset.netKey) {
        setNetSwitch(cb.dataset.netKey, cb.checked);
        refreshNetworkSection(body);
        reloadBar.style.display = 'flex';
        return;
      } else {
        return;
      }
      refreshMaster();
      reloadBar.style.display = 'flex';
    });

    const close = () => overlay.remove();
    closeBtn.addEventListener('click', close);
    // Close only when the press STARTED on the backdrop — a text-selection drag
    // ending over the backdrop composes a click that targets the overlay too.
    let pressOnOverlay = false;
    overlay.addEventListener('pointerdown', (e) => { pressOnOverlay = e.target === overlay; });
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay && pressOnOverlay) close();
    });

    overlay.appendChild(panel);
    document.body.appendChild(overlay);
  }

  // ---- ⚙ panel: what the script reads from and sends to the server ----

  function setNetSwitch(key, on) {
    const flags = getFeatureFlags();
    if (key.startsWith('sync:') && on) delete flags[key];
    else flags[key] = on;     // net:send / net:read are stored either way
    SafeStorage.set(FEATURES_KEY, flags);
  }

  function netRow(key, checked, title, text) {
    const row = document.createElement('label');
    row.style.cssText = 'display:block;padding:8px 12px;border-bottom:1px solid #262c38;cursor:pointer;';
    const top = document.createElement('div');
    top.style.cssText = 'display:flex;align-items:center;gap:8px;';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = checked;
    cb.dataset.netKey = key;
    cb.style.cssText = 'width:15px;height:15px;flex:0 0 auto;margin:0;';
    const name = document.createElement('span');
    name.textContent = title;
    name.style.cssText = 'font-weight:bold;color:#e8edf5;';
    top.appendChild(cb);
    top.appendChild(name);
    row.appendChild(top);
    const desc = document.createElement('div');
    desc.textContent = text;
    desc.style.cssText = 'margin:4px 0 0 23px;color:#a7b0c0;line-height:1.45;';
    row.appendChild(desc);
    return row;
  }

  function buildNetworkSection(groupHead) {
    const wrap = document.createElement('div');
    wrap.id = 'kdc-net-section';

    wrap.appendChild(groupHead('Read from the Sweet Revenge server'));
    wrap.appendChild(netRow('net:read', netReadOn(), 'Read alliance data',
      'Lets the display features fetch what they show from the alliance roster: the Top Stats panel, rank-neighbour links, attack range warnings, "???" backfill, Alt Watch badges, competition panels and leaderboard, the armory Optimizer preset and the 📈 trend. A read sends your login and what it asks for (for example the player whose page you opened). Off: none of these are fetched and those parts stay empty.'));

    wrap.appendChild(groupHead('Data sent to the Sweet Revenge server'));
    wrap.appendChild(netRow('net:send', netSendOn(), 'Send data (hard switch)',
      'Off: nothing below is sent, whatever its own switch says, and the script only shows things on your pages. Each share is sent only from a page you opened yourself.'));
    for (const sync of SYNCS) {
      const row = netRow('sync:' + sync.id, syncOn(sync.id), sync.name, sync.desc);
      row.classList.add('kdc-sync-row');
      wrap.appendChild(row);
    }

    const always = document.createElement('div');
    always.style.cssText = 'padding:8px 12px;color:#8b94a7;font-size:11px;line-height:1.45;';
    always.textContent = 'Always on: the Script login above, and the version check, which sends only the script name and version and answers whether this version may run and whether a newer one exists.';
    wrap.appendChild(always);

    refreshNetworkSection(wrap);
    return wrap;
  }

  // Grey out the share rows while the hard switch is off.
  function refreshNetworkSection(root) {
    const sendOn = netSendOn();
    root.querySelectorAll('.kdc-sync-row').forEach(row => {
      row.style.opacity = sendOn ? '1' : '0.45';
    });
  }

  // The "⚙ Data Centre" sidebar link is the settings entry point. It is NOT a
  // registry feature: it must stay reachable even with every feature disabled.
  function injectSettingsLink() {
    if (document.getElementById('kdc-settings-link')) return;
    const menu = document.querySelector('td.menu_cell');
    if (!menu) return;
    const wrap = document.createElement('div');
    wrap.style.cssText = 'margin:6px 0 4px 0;text-align:center;';
    const link = document.createElement('a');
    link.id = 'kdc-settings-link';
    link.href = '#';
    link.textContent = '⚙ Data Centre';
    link.title = 'Turn Data Centre features on/off and see what each one does';
    link.addEventListener('click', (e) => {
      e.preventDefault();
      openFeatureSettings();
    });
    wrap.appendChild(link);
    menu.appendChild(wrap);
  }


  // ==================== STEP HELPERS ====================

  /**
   * Safely execute a feature function with error handling
   * Handles both sync and async functions
   */
  async function safeExecute(featureName, fn) {
    try {
      const result = fn();
      // If it's a promise, await it
      if (result instanceof Promise) {
        await result;
      }
    } catch (error) {
      ErrorHandler.log(
        ErrorHandler.LOG_LEVELS.ERROR,
        `Feature "${featureName}" failed`,
        error,
        { page: location.pathname }
      );
      // Don't show user notification for non-critical feature failures
    }
  }

  // Command Centre leg of competition tracking: capture gold stolen, add the
  // panels, and auto-submit fresh stats (throttled per competition).
  async function captureCompetitionStatsOnBase() {
    if (activeCompetitions.length === 0) return;

    const goldStolen = extractGoldStolen();
    if (goldStolen !== null) {
      const now = Date.now();
      // Update gold stolen for ALL active competitions
      for (const comp of activeCompetitions) {
        const cached = getCompStats(comp.id);
        cached.goldStolenEra = goldStolen;
        cached.goldStolenTimestamp = now;
        cached.lastUpdate = now;
        saveCompStats(comp.id, cached);
      }
    }

    await safeExecute('addAllCompetitionPanels', () => addAllCompetitionPanels());

    // Submit stats for each competition if enabled and we have the required data
    for (const comp of activeCompetitions) {
      const settings = getCompSettings(comp.id);
      if (settings.enabled !== false) {
        const cached = getCompStats(comp.id);

        // Only submit if we have attack missions data and stats are fresh
        if (cached.attackMissions) {
          const isFresh = areCompStatsFresh(cached, 30);
          if (!isFresh) {
            debugLog(`⚠️ Stats for ${comp.name} are not fresh (captured >30s apart). Skipping auto-submit.`);
            continue;
          }

          // Throttle submissions (max once per 5 minutes per competition)
          const submitKey = `${COMP_LAST_SUBMIT_PREFIX}_${comp.id}`;
          const lastSubmit = parseInt(localStorage.getItem(submitKey) || "0");
          const now = Date.now();
          if (now - lastSubmit > 5 * 60 * 1000) {
            await safeExecute(`submitCompStats-${comp.id}`, async () => {
              await submitCompStats(comp);
              localStorage.setItem(submitKey, now.toString());
            });
          }
        } else {
          debugLog(`ℹ️ Visit rewards.php to capture Attack Missions data for ${comp.name}`);
        }
      }
    }
  }

  // Rewards-page leg: capture Attack Missions for every active competition.
  function captureCompetitionStatsOnRewards() {
    if (activeCompetitions.length === 0) return;

    const attackMissions = extractAttackMissions();
    if (attackMissions !== null) {
      const now = Date.now();
      for (const comp of activeCompetitions) {
        const cached = getCompStats(comp.id);
        cached.attackMissions = attackMissions;
        cached.attackMissionsTimestamp = now;
        cached.lastUpdate = now;
        saveCompStats(comp.id, cached);
      }
      debugLog(`✅ Captured Attack Missions: ${attackMissions} for ${activeCompetitions.length} competitions`);
    }
  }

  // ==================== ALT WATCH BADGES ====================
  //
  // The alliance's Alt Watch list (the /roster tab) shown where you meet the
  // player: a line in a stats page's Information table, and a 🚩 in the
  // battlefield's Icons column for accounts flagged suspect or confirmed.
  // The stats page also gets a small "Alt Watch" control to flag the account
  // yourself. That control is the script's own and saves only to the alliance
  // server: it never touches the game's own "Recognize player as" form or its
  // Change Status button, which post to the game.
  // Badge data: GET api/war-room/alt-watch/badges, cached for 10 minutes.

  const AW_BADGES_KEY = 'KoC_AltWatchBadges';
  const AW_BADGES_TTL_MS = 10 * 60 * 1000;
  const AW_VERDICT_WORD = { suspect: 'Suspect', confirmed: 'Confirmed', cleared: 'Cleared' };

  async function loadAltWatchBadges(force = false) {
    const cached = SafeStorage.get(AW_BADGES_KEY, null);
    if (!force && cached && cached.at && Date.now() - cached.at < AW_BADGES_TTL_MS) return cached.data;
    const res = await auth.apiCall('read', 'api/war-room/alt-watch/badges');
    if (res && res.flags && res.side) {
      SafeStorage.set(AW_BADGES_KEY, { at: Date.now(), data: res });
      return res;
    }
    return cached ? cached.data : null;
  }

  /** Badge pills for one account; '' when the list says nothing about it. */
  function altWatchPills(b, id) {
    const pills = [];
    const pill = (text, bg, fg, title) =>
      `<span title="${escapeHtml(title)}" style="display:inline-block;margin:2px 3px;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;background:${bg};color:${fg};white-space:nowrap;">${text}</span>`;
    const f = b.flags[id];
    if (f && f.v !== 'cleared') {
      const hot = f.v === 'confirmed';
      pills.push(pill(`🚩 ${escapeHtml(b.label)} · ${AW_VERDICT_WORD[f.v]}${f.linkedName ? ' (thought to be ' + escapeHtml(f.linkedName) + ')' : ''}`,
        hot ? '#7a1020' : '#6b4400', hot ? '#ffd0d8' : '#ffe0a8',
        `Flagged ${f.v} on the Alt Watch list${f.by ? ' by ' + f.by : ''}. A member's call, not proof.`));
    } else if (f && f.v === 'cleared') {
      pills.push(pill(`✓ Cleared on Alt Watch`, '#2a2a2a', '#aaa', `Looked at and cleared${f.by ? ' by ' + f.by : ''}`));
    }
    const s = b.side[id];
    if (s) {
      const bits = (s.eras || []).map((e) => 'E' + e);
      if (s.thisEra) bits.push('this era');
      if (bits.length) pills.push(pill(`👥 ${escapeHtml(s.alliance || (b.sideAlliances || [])[0] || 'Watched side')} · ${bits.join(' ')}`,
        '#3a3300', '#ffd700', 'On a watched alliance in these eras (alliance roster archives and history)'));
    }
    if (/^\d+$/.test(String(id)) && Number(id) > Number(b.newAfterId || Infinity)) {
      pills.push(pill('🆕 New this era', '#0f3460', '#9fd8ff', `Account ID above ${b.newAfterId}: created after the last era ended`));
    }
    return pills.join('');
  }

  async function showAltWatchOnStatsPage() {
    const id = new URLSearchParams(location.search).get('id');
    if (!id || !/^\d+$/.test(id)) return;
    const myId = SafeStorage.get('KoC_MyId', null);
    const table = getTableByHeader('Information');
    if (!table || table.querySelector('#dc-altwatch-row')) return;
    const b = await loadAltWatchBadges();
    if (!b) return;

    // Under the Buddy List rows, or at the bottom of the table
    const rows = [...table.querySelectorAll('tr')];
    const buddyForm = rows.find((r) => r.querySelector("form[action*='addbuddy']"));
    const anchor = buddyForm || rows[rows.length - 1];
    const tr = document.createElement('tr');
    tr.id = 'dc-altwatch-row';
    const td = document.createElement('td');
    td.colSpan = 2;
    td.setAttribute('align', 'center');
    td.style.cssText = 'padding:6px;border-top:1px solid #444;';
    tr.appendChild(td);
    anchor.after(tr);

    const render = (data) => {
      const pills = altWatchPills(data, id);
      const own = String(myId) === String(id);
      const f = data.flags[id];
      const sel = f ? f.v : '';
      let h = pills ? `<div style="margin-bottom:4px;">${pills}</div>` : '';
      if (!own && netAllowed('alt-watch-flags')) {
        h += `<span style="font-size:12px;color:#ccc;">Alt Watch: </span>`
          + `<select id="dc-aw-verdict" style="font-size:12px;">`
          + `<option value=""${sel ? '' : ' selected'}>${f ? 'keep' : 'not flagged'}</option>`
          + `<option value="suspect"${sel === 'suspect' ? ' selected' : ''}>Suspect ${escapeHtml(data.label)}</option>`
          + `<option value="confirmed"${sel === 'confirmed' ? ' selected' : ''}>Confirmed ${escapeHtml(data.label)}</option>`
          + `<option value="cleared"${sel === 'cleared' ? ' selected' : ''}>Cleared</option>`
          + `</select> `
          + `<input id="dc-aw-note" type="text" maxlength="200" placeholder="why (optional)" style="font-size:12px;width:130px;"> `
          + `<button type="button" id="dc-aw-save" style="font-size:12px;cursor:pointer;">Save to Alt Watch</button>`
          + `<div id="dc-aw-msg" style="font-size:11px;color:#9cf;margin-top:3px;">Saves to the alliance's Alt Watch list only, not to the game.</div>`;
      }
      td.innerHTML = h;
      const btn = td.querySelector('#dc-aw-save');
      if (btn) btn.addEventListener('click', async () => {
        const verdict = td.querySelector('#dc-aw-verdict').value;
        const msg = td.querySelector('#dc-aw-msg');
        if (!verdict) { msg.textContent = 'Pick Suspect, Confirmed or Cleared first.'; return; }
        const note = td.querySelector('#dc-aw-note').value.trim();
        btn.disabled = true;
        msg.textContent = 'Saving…';
        const body = { playerId: id, verdict };
        if (note) body.note = note;
        const res = await auth.apiCall('alt-watch-flags', 'api/war-room/alt-watch/flags', body, 1);
        btn.disabled = false;
        if (res && res.ok) {
          const fresh = await loadAltWatchBadges(true);
          render(fresh || data);
          const m2 = td.querySelector('#dc-aw-msg');
          if (m2) m2.textContent = `Saved as ${AW_VERDICT_WORD[verdict]}. Shown on the /roster Alt Watch tab.`;
        } else {
          msg.textContent = 'Could not save: ' + ((res && res.error) || 'no answer from the server');
        }
      });
    };
    render(b);
  }

  /** 🚩 in the battlefield Icons column for accounts flagged suspect or confirmed. */
  async function showAltWatchOnBattlefield() {
    const b = await loadAltWatchBadges();
    if (!b) return;
    const flagged = Object.keys(b.flags).filter((k) => b.flags[k].v === 'suspect' || b.flags[k].v === 'confirmed');
    if (!flagged.length) return;
    const set = new Set(flagged);
    const mark = () => {
      for (const row of document.querySelectorAll('tr[user_id]')) {
        const id = row.getAttribute('user_id');
        if (!set.has(id) || row.querySelector('.dc-aw-flag')) continue;
        const headers = [...(row.closest('table')?.querySelectorAll('th') || [])];
        const iconIdx = headers.findIndex((th) => th.innerText.trim().toLowerCase() === 'icons');
        const cells = row.querySelectorAll('td');
        const cell = cells[iconIdx >= 0 && cells.length === headers.length ? iconIdx : 0];
        if (!cell) continue;
        const f = b.flags[id];
        const span = document.createElement('span');
        span.className = 'dc-aw-flag';
        span.textContent = '🚩';
        span.title = `${b.label} · ${AW_VERDICT_WORD[f.v]}${f.linkedName ? ' (thought to be ' + f.linkedName + ')' : ''} — Alt Watch`;
        span.style.cssText = `font-size:16px;margin:0 3px;cursor:help;${f.v === 'confirmed' ? '' : 'opacity:.75;'}`;
        cell.appendChild(span);
      }
    };
    mark();
    // Watch the table's parent: paging can swap the whole table out
    const host = document.querySelector('tr[user_id]')?.closest('table')?.parentElement || document.body;
    new MutationObserver(debounce(mark, 300)).observe(host, { childList: true, subtree: true });
  }

  // Battlefield pages redraw as you scroll; re-collect (debounced) on DOM churn.
  function startBattlefieldObserver() {
    const table = document.querySelector("table.battlefield") || document.querySelector("table.table_lines");
    if (!table) return;

    const debouncedCollect = debounce(async () => {
      await safeExecute('collectFromBattlefield (observer)', () => collectFromBattlefield());
    }, BATTLEFIELD_DEBOUNCE_MS);

    const observer = new MutationObserver((mutations) => {
      if (mutations.length > 1) {
        debouncedCollect();
      }
    });
    observer.observe(table, { childList: true, subtree: true });
    debugLog("[DataCentre] Battlefield observer active (debounced)");
  }

  const onPage = (sub) => location.pathname.includes(sub);
  const hasSidebar = () => !!document.querySelector("td.menu_cell");

  // Steps run top to bottom and the order matters: e.g. the Estimated Funds
  // box is drawn before the armory network steps so it never waits, and
  // competitions load before their capture and panel steps.
  // `f` names the owning FEATURES entry; an array means the step is a shared
  // feeder that runs while ANY of the listed features is enabled.
  const FEATURE_STEPS = [
    // Own-account tracking reads the page FIRST, as the game drew it — before
    // any step below draws on it (the clock included). Not awaited: the read
    // is synchronous and the upload waits for nothing.
    { f: 'sync:own-history', label: 'sendOwnSnapshot', when: hasSidebar, run: () => { sendOwnSnapshot(); } },
    { f: 'sync:own-history', label: 'watchConquestResults', when: () => onPage('conquestv2.php'), run: () => { watchConquestResults(); } },
    // Conquest attempts left queued by a page closed before its upload
    { f: 'sync:own-history', label: 'flushConquestQueue', when: hasSidebar, run: () => { flushConquestQueue(); } },
    { f: 'server-clock', label: 'startServerClock', when: () => true, run: () => startServerClock() },
    { f: 'era-elapsed', label: 'startEraElapsed', when: () => true, run: () => startEraElapsed() },
    { f: 'vault-tax-warning', label: 'startVaultTaxWarning', when: () => true, run: () => startVaultTaxWarning() },
    // Covert mission reports carry "Sabotage Again!" buttons, so capture everywhere
    { f: 'sab-tracker', label: 'hookSabFormCapture', when: () => true, run: () => hookSabFormCapture() },
    // Every attack-page view is logged as a check, the address-less page the
    // game shows after refusing a sab on a maxed target included. First on
    // attack.php and fire-and-forget: the check says what the page showed
    // when it was drawn, so it must not wait behind the TIV round trip — a
    // mission fired meanwhile would reach the roster before the look that
    // came before it.
    { f: 'sync:target-checks', label: 'sendTargetCheck', when: () => onPage("attack.php"), run: () => sendTargetCheck() },
    // Sab and theft reports post FIRST, before any sidebar step: a report
    // reaches the roster ~2.5 s after the mission, and a member re-firing
    // with "… Again!" 1–2 s after landing would otherwise leave before it
    // went. Not awaited; missionLogSent makes the late step below a no-op.
    { f: 'sync:missions', label: 'sendMissionLog (report pages, first)', when: () => ['report', 'theftreport'].includes(missionLogSource()), run: () => { sendMissionLog(); } },
    // The sab report just landed on gives the Sab Tracker that sab's exact time.
    { f: 'sab-tracker', label: 'confirmSabLanding', when: () => onPage('inteldetail.php'), run: () => confirmSabLandingStep() },
    { f: 'slaying-comp', label: 'loadActiveCompetitions', when: () => onPage("base.php") || onPage("rewards.php"), run: async () => {
        const hasComps = await loadActiveCompetitions();
        if (hasComps) {
          debugLog(`✅ Loaded ${activeCompetitions.length} active competitions`);
        }
      } },
    { f: 'top-stats-panel', label: 'insertTopStatsPanel', when: () => onPage("base.php"), run: () => insertTopStatsPanel() },
    { f: 'core', label: 'collectFromBasePage', when: () => onPage("base.php"), run: () => collectFromBasePage() },
    { f: 'estimated-funds', label: 'fundsReadCommandCentre', when: () => onPage("base.php"), run: () => fundsReadCommandCentre() },
    { f: 'slaying-comp', label: 'captureCompetitionStatsOnBase', when: () => onPage("base.php"), run: () => captureCompetitionStatsOnBase() },
    { f: 'sidebar-calculator', label: 'initSidebarCalculator (sidebar)', when: hasSidebar, run: () => initSidebarCalculator() },
    { f: 'sidebar-calculator', label: 'hookSidebarPopup', when: hasSidebar, run: () => hookSidebarPopup() },
    { f: 'estimated-funds', label: 'fundsReadSidebarGold', when: hasSidebar, run: () => fundsReadSidebarGold() },
    // No-ops fast on pages without the "Rating For Previous/Next Rank Gain" table
    { f: 'rank-neighbor-links', label: 'enhanceRankNeighborLinks', when: () => true, run: () => enhanceRankNeighborLinks() },
    { f: 'attack-log-enhancer', label: 'enhanceAttackLog', when: () => onPage("attacklog.php"), run: () => enhanceAttackLog() },
    { f: ['sync:recon', 'top-stats-panel'], label: 'collectFromRewardsPage', when: () => onPage("rewards.php"), run: () => collectFromRewardsPage() },
    { f: 'slaying-comp', label: 'captureCompetitionStatsOnRewards', when: () => onPage("rewards.php"), run: () => captureCompetitionStatsOnRewards() },
    { f: 'recon-display', label: 'addMaxAttacksRecon', when: () => onPage("inteldetail.php"), run: () => addMaxAttacksRecon() },
    { f: ['sync:recon', 'recon-display'], label: 'collectFromIntelDetailPage', when: () => onPage("inteldetail.php"), run: () => collectFromIntelDetailPage() },
    // Collect visible stats first (before filling ??? from API)
    { f: 'sync:recon', label: 'collectFromStatsPage', when: () => onPage("stats.php"), run: () => collectFromStatsPage() },
    { f: 'recon-display', label: 'enhanceSharedReconInfoTable', when: () => onPage("stats.php"), run: () => enhanceSharedReconInfoTable() },
    { f: 'recon-display', label: 'fillSharedReconInfoFromAPI', when: () => onPage("stats.php") && !!new URLSearchParams(location.search).get('id'),
      run: () => fillSharedReconInfoFromAPI(new URLSearchParams(location.search).get('id')) },
    { f: 'alt-watch-badges', label: 'showAltWatchOnStatsPage', when: () => onPage("stats.php") && !!new URLSearchParams(location.search).get('id'), run: () => showAltWatchOnStatsPage() },
    { f: 'sync:battlefield', label: 'collectFromBattlefield', when: () => onPage("battlefield.php"), run: () => collectFromBattlefield() },
    { f: 'alt-watch-badges', label: 'showAltWatchOnBattlefield', when: () => onPage("battlefield.php"), run: () => showAltWatchOnBattlefield() },
    // One War List visit refreshes sentry + AAT for the whole list at once.
    // readOnly: the only step allowed to run on the War List (see runFeatures)
    // — it reads the page and never touches it. Deliberately not run on
    // warlistv4.php: its columns differ and this reader would send nulls.
    { f: 'sync:war-list', label: 'collectFromWarList', readOnly: true, when: () => onPage("warlist.php"), run: () => collectFromWarList() },
    // The game's own list of who is on vacation, and since exactly when.
    // loggedOut: the one step that also runs without a session (see runFeatures).
    { f: 'sync:inactives', label: 'collectFromInactives', loggedOut: true, when: () => onPage("inactives.php"), run: () => collectFromInactives() },
    { f: 'sync:battlefield', label: 'battlefieldObserver', when: () => onPage("battlefield.php"), run: () => startBattlefieldObserver() },
    { f: 'sync:attack-pages', label: 'collectTIVFromAttackPage', when: () => onPage("attack.php"), run: () => collectTIVFromAttackPage() },
    { f: 'sab-tracker', label: 'initSabTracker', when: () => onPage("attack.php"), run: () => initSabTracker() },
    { f: 'sync:sab-caps', label: 'sendSabCaps', when: () => onPage("attack.php"), run: () => sendSabCaps() },
    // (sendTargetCheck runs first on attack.php — see the top of this list.)
    // Last on attack.php: the range rows wait on the roster for the target's ratings
    { f: 'attack-warnings', label: 'initAttackWarnings', when: () => onPage("attack.php"), run: () => initAttackWarnings() },
    // Intel file (per-target mission log) backfills the Sab Tracker with exact server times
    { f: 'sab-tracker', label: 'collectFromIntelFilePage', when: () => onPage("intelfile.php"), run: () => collectFromIntelFilePage() },
    // Mission history: the intel file, Intelligence, Poison / Theft / Attack
    // Log and battle-report pages, each read as the member opened it and sent
    // as ONE request. After every other step on those pages (the Sab
    // Tracker's intel-file read) and not awaited: nothing waits on it. A battle
    // report is read on the same two passes as collectAttackLog below; the
    // second read sends only if the first did not send the whole report —
    // it found nothing, or found the report before its outcome line
    // (sendMissionLog's readAgain). Sab and theft reports are not read here:
    // they post first (the step near the top of this list).
    { f: 'sync:missions', label: 'sendMissionLog', when: () => missionLogSource() !== null && !['report', 'theftreport'].includes(missionLogSource()), run: () => {
        const battle = missionLogSource() === 'battle';
        sendMissionLog({ readAgain: battle });
        if (battle) setTimeout(() => { sendMissionLog(); }, ATTACK_LOG_DELAY_MS);
      } },
    // detail.php also substring-matches inteldetail.php — the attack_id guard is what keeps this attack-only.
    // The delayed read is handed the first read's promise: once that one sent
    // the whole report and the server took it, the delayed read sends nothing
    // (collectAttackLog's after).
    { f: 'sync:attack-pages', label: 'collectAttackLog', when: () => onPage("detail.php") && /attack_id=/.test(location.search), run: async () => {
        const first = collectAttackLog();
        setTimeout(async () => await safeExecute('collectAttackLog (delayed)', () => collectAttackLog({ after: first })), ATTACK_LOG_DELAY_MS);
      } },
    // First on the Armory: reads only the page, so it never waits behind the network steps below.
    { f: 'estimated-funds', label: 'fundsShowOnArmory', when: () => onPage("armory.php"), run: () => fundsShowOnArmory() },
    { f: 'purchase-alerts', label: 'scrapePurchaseConfirmation', when: () => onPage("armory.php"), run: () => scrapePurchaseConfirmation() },
    // DOM-only UI steps run before the roster-API collector so they never wait on the network
    { f: ['rank-up-costs', 'gpp-panel'], label: 'renderRankUpAndGpp', when: () => onPage("armory.php"), run: () => renderRankUpAndGpp() },
    { f: 'armory-sliders', label: 'enhanceArmoryPrefsUI', when: () => onPage("armory.php"), run: () => enhanceArmoryPrefsUI() },
    { f: 'stat-reshuffler', label: 'initStatReshuffler', when: () => onPage("armory.php"), run: () => initStatReshuffler() },
    { f: ['sync:armory', 'attack-alternative'], label: 'collectTIVAndStatsFromArmory', when: () => onPage("armory.php"), run: () => collectTIVAndStatsFromArmory() },
    { f: 'training-warnings', label: 'enhanceTrainingPage', when: () => onPage("training.php"), run: () => enhanceTrainingPage() },
    // Shared feeder: deposit rate powers both SAFE forecasts and the upgrades-page readiness rows
    { f: ['safe-forecasts', 'upgrade-timers'], label: 'collectSafeDepositRate', when: () => onPage("safe.php"), run: () => collectSafeDepositRate() },
    { f: 'safe-forecasts', label: 'addSafeForecasts', when: () => onPage("safe.php"), run: () => addSafeForecasts() },
    { f: 'upgrade-timers', label: 'addExpUpgradeTimeRows', when: () => onPage("safe.php"), run: () => addExpUpgradeTimeRows() },
    { f: 'attack-alternative', label: 'addAttackAlternativeTable', when: () => onPage("safe.php"), run: () => addAttackAlternativeTable() },
    { f: 'tech-projector', label: 'enhanceTechLevelPicker', when: () => onPage("safe.php"), run: () => enhanceTechLevelPicker() },
    { f: 'upgrade-timers', label: 'collectExpPerTurn', when: () => onPage("upgrades.php"), run: () => collectExpPerTurn() },
    // Feeds the gold/pt Paired check and the "before an upgrade" flag (armory)
    { f: ['rank-up-costs', 'gpp-panel', 'stat-reshuffler', 'armory-sliders', 'attack-alternative'], label: 'collectSkillLevels', when: () => onPage("upgrades.php"), run: () => collectSkillLevels() },
    { f: 'upgrade-timers', label: 'addUpgradeReadyRows', when: () => onPage("upgrades.php"), run: () => addUpgradeReadyRows() }
  ];

  async function runFeatures() {
    PAGE_KOC_TIME = readPageServerTime();   // before any step: the clock starts ticking in one
    // Logged out (only allowed on Inactive Accounts, see the security check):
    // run the steps marked loggedOut and nothing else — no settings link, no
    // clock, nothing that reads a sidebar or an identity from the page.
    if (LOGGED_OUT_INACTIVES) {
      for (const step of FEATURE_STEPS) {
        if (!step.loggedOut || !stepEnabled(step.f)) continue;
        let applies = false;
        try { applies = !!step.when(); } catch (e) { applies = false; }
        if (applies) await safeExecute(step.label, step.run);
      }
      return;
    }

    // Read-only pages (War List, Farm List — see READ_ONLY_PAGE): the game
    // allows no changes there at all, so run the steps marked readOnly and
    // nothing else. No settings link, no clock, no sidebar calculator; the
    // collectors that do run only read the page and talk to the roster.
    if (READ_ONLY_PAGE) {
      for (const step of FEATURE_STEPS) {
        if (!step.readOnly || !stepEnabled(step.f)) continue;
        let applies = false;
        try { applies = !!step.when(); } catch (e) { applies = false; }
        if (applies) await safeExecute(step.label, step.run);
      }
      return;
    }

    // Settings entry point first — must stay reachable even with every feature off
    await safeExecute('injectSettingsLink', () => injectSettingsLink());

    for (const step of FEATURE_STEPS) {
      if (!stepEnabled(step.f)) continue;
      let applies = false;
      try {
        applies = !!step.when();
      } catch (e) {
        applies = false;
      }
      if (!applies) continue;
      await safeExecute(step.label, step.run);
    }
  }

  // ==================== MAIN EXECUTION ====================

  (async () => {
    try {
      const isReady = await initializeScript();
      if (isReady) {
        await runFeatures();
        debugLog("✅ All features initialized");
      }
    } catch (error) {
      ErrorHandler.log(
        ErrorHandler.LOG_LEVELS.ERROR,
        'Critical error during initialization',
        error
      );
      ErrorHandler.showUserError('DataCentre failed to initialize. Please refresh the page.', error);
    }
  })();

  // ==================== EMBEDDED IMAGE ====================
  // The Sweet Revenge logo in the sidebar box, kept inside the script so the
  // page loads nothing from outside the game for it (220 px WebP).
  function srLogoSrc() {
    return 'data:image/webp;base64,UklGRoIsAABXRUJQVlA4IHYsAAAQiQCdASrcANwAPm0skkWkIqGYfAVMQAbEtQbek4QDSO2de/nb+l83yzv4z8j+0Htx7C813nD/e/4T8bfm7/t/1291/6b9gP9Zf9r6Zfq1/c71G/0j/Vfs97uX+l/bL3Rf3b/Vf8T3AP5R/h//D7X3/Y9hH+0/7z2Df5X/ZvTZ/bD4Rf7D/zP29+Bz9qf/57AH//9QDVLeNv6Twn8hnq/90/cj2J8ifZ/qa/MPwJ+4/x/7r+13e/84tQL8o/n3+k9Qb7Tsr7a+gL7hfXf+j+cnnif7Xod9lv2G+AH+i/2T/h/2z2q/5ng3/bP+V7An9C/wX/f/y35XfKX/6f7b0B/V//y/13wGfz7+7f9314P//7mP3V///uzft9//24ND3ltNJEj1HxJmRFCKjZObz1VQqL4xRHoEK8DfDZgKgiylk8fRJwyebj1cY2TRztXWJtU99X0wWQa+B7sF3eAxkXb3vXhw3C8djRt/+UG+IJR/prx6htAcr8+6R9VhU1dqNyuMknQFGI0sp7YzOq/Zom+vcaFxB0grMrHP1Fi3FfmfpGVRb0I+NZSOZWACkUnrJizCTuOeyQpg7+PCVHEDUf88yrGxVY/VNuDQViJUG4JzdpDbXZTS8yUUlHYTnEa/b/wSFt8CCvDdApdFrdXvR1X9ixtziZUUXwGkktNhlywnyOUjQ3obLCH1SjENU3VoS3Fnyq6PczhpTw3JPSsKG26ZUNsm6QNYB2MDeZtWloPGBkja9Uu0JzMF/qwdjBfDj5Lsel8ZBT0NS2+6qAxcpAHW66/tEqxa7SOY+7+kAJAkxEgOThBskLyLc5e/iE6jt6BcKbBWT2p9kBpTzX93yIaYl73u1QXaNh5xrTX6U4J5x3bmvS2f2kErg/TH1scFez5vj0JsiIbqLyCLX7tw7WE1AuNsAq1G5rHwtvC0emcPZeT7eDBijmo5Jagwr4GZejWbCL+ysUTLMQgh0bPtbla4SGz+xH6e32ki8PdUjOZjUX3xnScvksCV6+8qrwVgMwUUo9tQOYxCCI9VmMCWDYekuv2m/23xJnsFSli/pv+OQ5+tZnwFKOtvMDge0yh357nSxN0gT+7aVlLWgMln3OzfGrBdEfSPEv/OECb2QcaMrNOnsX7dKbwmHstN5Yf9UutFyJkG38vyioJXz8f/IYRz0f6mN7GMqDerUm68U9BxYcQPiRiUt2Ss/Rupa5qX4IK1hRCfhtCIB1jJrOsfBqN7xLBcPrN6C0B4S+qkjaLX51xvYngESSiCPbzehi+lJtgolK73mb8LuUCwocO5w6v5Subm+mQFoBvaRTo88lu6Rv4JhNoJ7jtpDgO6f6zhjtNs3DnKKpny6wU1NMSZPwPWxIj5PLIC3ZPdjDROIcP41/Yfo7vSnnrsjQ8lUR9seOXKHbUi2jU56rH8oy3/mftKyNXPwX6QN+6N5AHvayb/bWTvNOTTHUmkOBI8PyQwu2WIAP7+pTYB9v9f/yg/t9IY5gTXCougYn1YNf8DaI4LOrohgvBmYf1WPYHgjd+I2DaXnBHo9ttGpbSaEnkwMG/IIABV5H1IsDafI+ghlOd1EjmSZQRk/X/LSVQDNYQNgTE6lVHxZeHAln1UH7K2I0hvVWZ4oUU5MqDGhbGEIJswcxzhIbeFpFepT3W61azj8FLz4s6G1bXVHkEQRwHdQakp17N763Vb0AJqRx+vODOq3T7epA+zc3g61Imj3gcSSsDoyJUIkxh+qRHVK8TERTjr/4oZApqqsl24Pm5LuVsPPt0jEGHNHvC7HO8rrAEhFaqflE1hIReyl3QtEThJhHjIEeSjceInQr8J3Gatfx7ogx02xJSMZ/MFlj3XGDTf+Ly49H+MwTRjYC9mKw/Rrlg3RUpl2Cp182KeAglGFihL0Pthkb6MkK/yGElr8kVVyfxeohD/kIwOUqg9aZTfb3MGFyqJ/mVknomH0O2JbbvdUHgfxlspyaFElaFQCzBHJmEL/GwhMmtWIe4ESfVSbcUBPZBzvVKUXbWoWpouxziPSRBpykSXehD/Ihi/SkM3MUbIfyLwyUU+l+0gquogk42VCzycixlmJBXcZCjpJ+TLkjEmsQxmQgwzi4SAxDzwUd6Diamci2VIXqND5Pmg+DbxP9ptMtawFPlMmEvq2NHI9clC8s2j40SRt7PS4+P09nnUwEt+ryhPTBNImOnRLZ6eYq6TMfsqseElFrtek8rUkTKkaWVAVLY9ZTvrFw90TJUjxChVYW+YBj4H2gzwpKSdz1EjQotY3bETTryPDfJtC0UMW679udpEQal28JvYHQY4WcEc2xK5zXJY30z3YhfixbW3tW7QRtDVl36R2PXntlWCof6Vd/aiyDvxEG5jiUuXsVku9c22/cP/jwbKKe5xb2f1j8sX0yo+qDwG7vAmGGqBpEsIfKbHqzXAZlrmnSPHiYn8O1GF1SjyZaxE95elMGuSDT1DkDHgNZYQ1BRZ5LFE2pOTI9OmS0ibpo+5G1GYWqMzKbh3TnvcWab1z4j4IDII7aN7rzvfvdGcQAMYFXJJ3h9YH/J4LIA8hWnosxOTOlo9zIdrGLBRUGgpvypxnYmTVQnm5tkfv8L08uPG99PrGrtvnCDYmgzyKuSD7ph7OUApM7r8KeYQ9LscLN/XVK20X3mkHEI2PMlhx65yuqbusTJ8JgX+o+QGph1NewK9gZ34W10MBkDPpdzxdzvUPFcOrOfvt+eMHGR6I/AEHf3/Sv0DkoTe1RPEJdnPEiiLvGAeiD7gZ5kEitpaEbZBuc9gWthWT2l3v3O5T4c/okNu4VxOVqffSkU+Nyd8ZOHfh4IC/+NDKAgByMUWCF0LNCc/QJ/Cnn9Ok+qBAQfWhMMc8JA3oVunq/y/7uAKd4WRXZFyaInF8ItOo47mfMxGuUOs0QL97wnOclhatbR32EdqGtTuocEzxym0ZOcO/5DN/ZPK5hZuxOSgyVJ+oQSgL2WTJ4yd4VocUFP0Hd5ZycMTc0IV9BkKlS9YnVjmjRhYFfRMwIyPMEG8cKeLTjBIfSQht+jgVoo0F1sge9bQoAaLEr1GIm/y+0YWajf14rEVqdBKaHIZEFBm2+zGqXwFME0BSaUd/QMqG45g81wfD3bOaLqJ9PBb+SQIiRBwFMdLF34H1QZbjpSDD8PnEisn5xErxPXqS227RZaZ+Veba7EPsuL/Lm2XR4lMjzSD4g3sgpBaVQyJ0cX7JwV1dSYUwwCvmfkzQfsRXfxexDglNOwydP+lebsbJQSpWcSeRTsEizVxhkjcXhrwxVtxwy4KXrA9XeGawXVSqa3Z7KS1aBwYI7aXsEpql/6N/bwUG/Yg80Ko9jWb/B0GWXifLcPKL7qWUYa9aczpjqAymlEOWmfbj4utkftGvBfKt/TmDfZ0XKwSuNSwHbelNXeEZ1/vN1E86X2bzEKjjD1k5AKPhIevC6BqZpxDuU8q382NjrIP+r5PEa7EIB38NHaM8Uq8SjofIRfjQ//qu/Vbybi73W1m/37oHGJ+61q1gI4sMqRLo3QdhmwHTaffFBYh45k9xh+Su+KSl+95wcexx6350Z3zrxus0mNVc0POETvNe/xTffhsaBE9ZAeUY4AEighkgdMU12Dd9EN3CQz7Sh20stgEQg7T0Lp/GiB+dkUATuVDv8W5dS2BWOOESI0m54AukwCZVumIRd6ymx2mzHfTEIGr+4orFjKvLmgKfAuiUdTPAyEtZ32jD1ath4NPV5BVbO+y9LwEz9fVl6llqnj83Z801cRieeOsuYwPefqcID3oy2mcMvLws3DJqj4Gw30Is5tMjpcbLNDCxr2FEpbe+v6TPbn5BnAT1tH3ZbrOjq6iHLeYhws15jtdwqtDIZmRgoPy5YB7a+6Xak4J5pJgbqPJGGxA1fIjTKmsOf4UWE/oUbrjTRnK2j+hZXEoBK1xC/ZgWoathQWo30O59/8AH7eIutpW9bZxMyRKZx4pGTMp4JL2s6XJV9GYLXRbWZU4+Vvb40wRBhy4gxrxZtsMsa4h48h0/SzBbIE3X7rYD/pfdkhkQxvKZniDW5sK8vPDZBKG+rHSyts5sdOTFqS2Q9Cb933ybOv3633VxHGj0dNdNi1eNTwObuIfaMbFdn5dGNmBP42GaTillfHKAngdh+g31xQ8kPfJAXIp6BJ3XjP26QX0J5kH+77iTsxgvHxjIdjFO1TBd1MHuXvokNBenQxWdaExH3l6jg0R7KoGPHBMZ1VAtEOW7AGQZdXq2l+Y7+iQc2obHiBPYSwWt3IjlWitT7Y8NwkQ6fys7DWQ96Aag7odDc5Bp/uXGBf5HWjDF5LsZUR+VZaCvbbLlMpE2J+Rz/i54VcRo13/AscZ8ijzNOAiS9rtUJTtJrOiWJpUlNai1Hfmkp7MRx4jk0K/IJCedFMe9pmxBs58g23PqAkQgT7N95Fa/DiXeVM9fhWthjGWnELqRg+u0ueEtiivmYyy640v5ziq900E4q+RVkgXj+BC7O2GAYVj1DVvYgFsQtfnHewZFLPtwg4TB7BRKQehhKWJg4rpIPBCvD4AJh2yUd6OrsnTZrUMcdAHqv9Hz42uD3RDft/oM3ZtyEzAC+m0GQUVm0NDsR+aEi3eubLRFb83d47TrfDdD51ELNMfOWVHtmJMgHnLBugf8qBjcVBn8jtURYWOSY71Wm6ah3AgYdAwiSyh60Nt0VV7tU8kHzVvfdR2xUMrSM/4R7Rt712iCfW+0XY+AY965QPdty8fsqe7qRfgjbU/Mxq5VWjHbLk4uEXgDK96LdXWhHT81ibED7tCVKglzWlM8dHt+1rWuNaiyE0ek25BhIkdiSy7OUuhrMZ5a1cJcrB1/x8hcljGmspjVa1fZfZZauJ+p9KDD2hsRQycNwlaGyFDZnIwk55bklwXn+gJjrrGwNMWTsiY6ms/U+p6m+itcaR9N/9toprdL3tuzmyRC/CasRpYWxKQWzv18NgymSRbyYIAaX5AiYmbAfLeDPhBXVvMoJBZ3fp7uU+vPh+MMNYn/8dx7zkgTcxuH59NlJx12L1+Z/QW4SDZUlCmCFKdzCw17S14zs2w/5klSD9jGyae3mDH5GBbJ8ug+JV5BfrbVV/yc66Aj6afZSrSSl7ZsTN1Ina006oPkNWYiJDPBznjs/dbT0LoedLaUzRn8gDeOyn3OI6LrSwRKW8F60237PKbOcVFBVSMqwmdb/uLkPJbcf7KvYlWdJ3megfqS03g6w30gCu5gNZsdjnPVwxJo+bQbLKf/5zDZ/t7uRqTNI+ukURPYs0vCI62uKRZNIfvRzvvtrg2Ouyfe5yc+W+6CLuUB+DoItipoyEfGh/NBc4OVWKOr9lYFslahHfjmWioQOC1sAQzDNxt6xeTZJL62UrBRLPjXBrUypuGadCW3D8ayHEaZ/zlK4DhiAP/lJfnpoh2Nta4OSscU7gzVW42bVW/xlBVqDn7Oa8SUF1H90oGZL97EIb7sbBA2Y/UHDPQfiHVnWsQgTtxFeJHTkyoDtF/dlLpbtNLAcytQ7d1JWE272Tiab+bizaSf4X9m3MXcgVlaOSbXwAMNFGr153yRVa3Mx2En123iEgUJ45Va13WrK5lfiQtvLjstr1OWlFX6Ap1f+WYTkHIo/eRJY9rdfcgF4ttE9iXip12PLmtjADnUlwiBxzHY7BCUAYGP6HoSujUHJu0MNivYJxW/8iPLXad+E30kjwlLDq+ia7skRToYxWt0cmKP2Q46ijMkhzqPg/i8a/kbLNS9jWwGA+CmNB0QvSYsUwcOqDzOIhsR1zmbOchOds1rhcuDTUisixyGEY4EVsdHkLBl0SRr5+fytDOLCDlgFb2kbrDQ4wB36EXAjgmJEhxQI6SK+duN6EQiVLgHtcviAKtat2FflTsQBxEX9mzz0Is94HI42FnUueisvDDBKWrmfEBBitmvH1NR+VDm8aZWO0sBkh5xKUviD6mQ4UCAjy7lle4jb0e1y2l3cD9zcJqzHbq+QGEz+mYQlgIRB1X/BjkYVC7nxwTPnVVQJnG2xAglIa5JGsHviMsanWFjl5Sr2bu6DGdul0AhYldkV+JxET7er6xDXsNwWnGfoy2D8y0dwHSalXGHpv8HpdpKwb42fgzRKP0+p/eI9J/2FZ4ScRmfk94EWpesOLZYVZmRw5ulqyag/gDJfrzwH1xmLAAACtfsoOenPbME1y84HiklRag3pysmsDOQN6Ur362J3JoAU09nwOuVR3TkTertlWqN3rzKuYaD+5IA8bAAdr1cECTKJ1m2VZGRR/cj0kVlUzB/8A8S6zAQ+k7sikgtP5umJVQyTDVKqNsNRUGZ8xBacQCCCD7FkoFhtQrp656W51bWiuXYpUxbI9MadYMuSD2Y+fx4qHX3rp9kFbxb09W3eexkR2xifGUXLXIg6jXp61K/86RbDjm4GswX2h3vU4eY+ntCjs84hhGD8GZL3NAhzBgTw4VnKV3yMCjnzA8jTDOgaBvX+VH5n8d+b8+GBcDKX5wi78ieicFR8wxMvnk3abDGcTNiTxSlfPo/lzAhrL+LTeCKQe+OUaoMFRPUuMZ0+jB9CLzkwVG0a+JbCkw3b1edcb1Gm0FODLrI/wFtCtl/te5gHCqj4VHGRHOOTSP4aMO5+CI0PPkSIv2DqeXBeLb9T4qRDCWihPhXGyqkrdf592f2q6D9TIYhypmVSDGdb3vCli8dn2SFNZzT5g3T9Pok75IWbjb+mI0yhHPOXu67ySx7v+9VmgtUsznp4L+nMil19cIt7Qntrd/5SX5Vnk9degQT6iHkSZgisbx3DXte+zHfRtqxFAPmKB2bFfUk3VM16VpViO7/A+IAzvTYrZcA0caaoaD/6J1Sj+jGEYsfp9Ty21W4634RYD6iX04dHPzeUeLqPM0Qiln++DI5pte5xQfqI5YN4f1YDyfvNb4jyKfabJwwFD3kswLHh7LYimZ1ziy8F+f6jOt0X5v/KH91v8EK7NzfjxTA5KG4GYicVyryyB/eEwfyZok6Sfow/KBvd3rprt1Y4Scae7Qd9HTQqxT/P7PdY1nwjVQuhDi1vXcLBP2xgV/aOobcOF/bs3SP2ulunL0M2/S7idOLQLXZqvCSGniythuZoOwbE/ZKtj44Son858nIjvqRzvFeNM8nK4S4bC3D8Ze5DvRI10BN8w/8RIZkYb37BZkmY6m7M8v1i/jHtFEu/3qmncCnlHBhp2yX/CqKbNCMQQ35o0k670/gNLG+7XaAX99yjj6nzc+IIr1Qgk+R89i0nP/LNZk3FfoSujy2Uk/Q6TRKecKq8lWc7m+zfhC64OZNgJDhE50Hid8OjjWkQwkJbnUOtnJgUt04BMk4XT0KkeBlP0BMXrarWYU203Kp5UfaGomuyeh3o1Cqg8eqM+w5gDKkNVAcg/pUI61k4kYimPh0rAlAtOXgar+E3tEBezUXgPY2xFsuCovgKvgWl+GYN5bOFkz70dRadku4u0cRwYspcP8galubaqwo5ZC5biYKPbyxswniCv3MKLXPtwc3MTBnH3wU5BHAhRuGUk+VYBfslxxlgB3vlm/VW8/DiwlWJ9eKsDu8leOgr78BQZ4Mj4L/8XlA/wmzPPPsKWWq9AN7TbGXG2DiSpLRfdp98BEYkHH88Q4kVWk+K+KxsS48z4Op1E4/uYmSJ2bFOECmK+tAaoEsM7H/Fd8IpEMLDjot6YMjDV7EVEOtcQAdD1mGSkZpbcB+kN5Mp9oDIFALZFLPFA82Z6+R3XW/vcIuQhcfacGxwWER4pVquqPUczTgKk4joHkXAk6jMysFzUX1qdUHUgddZU6lhzfcTwn66Eu83B8pb7VT0hwgMiYpOgij5rYiY/9U+06pJUIzZ0l9V42yut+H5RQ5tdeYcqk3vAR5lAhH16oG/8kseuvIYvEurg9Sst2T/+UuYby/Lquk4F1pbVG6P4DOrX1BT8Wzs8XglftQecTChypt9ZnCHJl5tG/amVqyfs2HYVGGMtPW5CsCrS13t6Cidv/Lf2Vyuy77O8MVc7iY/WmQOSJ07vtaSBsN+efNuE0Bj2chPsYjm/JSerpzSc5oAr+jyPaPrTfX0el8KR5FB3P9BKM1WxQ02Zx4Xxt83Gel0KkW3vky0qDx8RG0SlKrILRfiYN2LcjRULyNDj/SXiJOe+kjHryaHJXky4tAQ/cKYGS6R8kQu27ruqD7zyeiwcDNnm1DOYP4QYjHftDz69CbWktsCB/TA29j5bZPjHDQ4pbwoj2fXz99NFiuk69rVe27VVc1+9G5yXm9zRE9Ec5YummNVeD1Jd+lFPQMrQHkEYvfAqZnRdqB2NdUcB6OMP+ysYJIXZmtyKlbPh33ont7bIgEE+q5TpILbWgKMy7xiYNblc5sFykubJ1cT9ahN59S9rN1J4KWO40CTAW0juxug/5InLjNbB/n0WDeGAyBw50oJ4KALHyU0UcfTtv6Nt8U4ODy76SpfYVQ9A/7ZLeuV4wIfPM5sG8BabEDOWaPO0y1/zSe3PJwUhd/smeUsyhViYN24l1881LvvJKW9oRly0B7qigXuL6n5W5JfekDW3df5/T4Ey0PuerUB8ez/ytU4LwrAb8MMts6iwabo5e991KZWib2tC0M6z8F7YhqAnDraGdBOw55nRB7CZmDQwjrV2DQtDWTxhW5BXU0H1z6ExqWNwmUwk18OFaxc83Yxkao+5N39/hWqsZogxpR7errx2l2c/ON+JNSvonPhIgiSs/7U5RcD96Ilq/Khk+PGZr1kWp62U/1fVDhgSTBEsrnyv+IIFg3/n+xwjpsiKyB6Z4GNEjIc5Sg4qClcSa9c8PCzqFrvtb1sbcd8SE4tJsSyro82rUr8Tq0dojp9lb18qqMnZZ9+T6Y7POCzId0EDt5D576PKNoPGHmwywmTan2iQWCT9STjD96tWxtcVzJhVkTPaKFlIZZM+GCE486BZ1MDdCo9wIcBvO6w+PVozTx6Yye5Jtb1da+dpH0/3nZd2ASCfeD819+DGGrugHRNJbL+yy4t+b5/n6qMVKLDHuU5hZFpy9arV18alldnHyCadsoIRoNY2RavuHivqvwoNtGVp8+UWwD7aPFPoIKuZL702wwBE12B+gqHjCBqyYqYqMfWEtqRYRwK0lGPmUPfSuLc7ZPGDlKoNxHATefG9QsVFquIFwnRM14cPG2XCJucOVnYk2W88Vc4KvqmxzNhOPwgKffVM1WjtNqYyIChWJUObHNr2F5P/zYbjWWtnaJJq3fC8J2poH2TC7hZ6m8T94kreI3c3QIQqgS5wGRpwo+45LbS5ObEPscxfPIRiGzjhh8RLKV1o8DTeCE3O3Y6aF/6SHKy75HZSycx8epyw495ez9PHdCbJhN7uDAB3K2fG52qPrpSw9r0XeiGA44Jwq0TsoTGWMatVFhfAUTAn0P39KHx7yGJgKyB+cgry/9a3vOTJh3YjViQJ7iULtIWf/MNkCerh3SBLZfjomYvfehOeWxv0iJr0z7AmehizcS0YfQJ6+uOtcZB786ClOyGVaRdER+j60XQnf9Sc3tIX4WB5jkZy7Uqp/WiC0s/kafd1fdbd2HpDkh11pwycm6mAbZPcZuL+bP/NmStboudvKFQehe0l/HRvDktVROMSX/r+G+3b06BjqP1/tXQ+HPtHuYrAYV0kVqeTeoZdQhKL5HrgsEtgMv4KOEtbfefd3z5XNE/N7+I559oNRyNn4yv1gH3IiW+ileRdm6tE/IY7ZPGuhQQWj8+udsJ7ANHz9V18feGNsMgUc1uY4nNWQSU/4eJIKTiNgxy4x7yiE0RhAk+GJwXso+zAZnVBXYVlymt0R0fGZp0o2am5uuOGTyCrivxqLolcoOGgMmc4pKYoULLyvqJSpQD2OUwaPqqYYwGlxp23/VwlnKhlyC8XDqhe1ah7RldzvTAwd4JMeaPmiSuuEEhzj1t8p+YM5E7DrGRuUQDvm84vZ0DTpXpun7ZQgFOaXQYJwtO1rMW/3NGGmMFsIWgdoTlz3KNE8IdhzGcEEEoFztNwzkJgFz1p1J41wBlNS6g3uwThX3E3cnENq6o9iAn5znnrykik96fXLOxL7FlrC4XNTLuk4sF6p0nTT/wygm3RuZwyJ7+KFI+3wnuc4Cr73DoYdFqp+gGwz8BuXYhbuZOlcWA2T4OIaLw49mqfyjlwKfX5wXHbYGv3SANmM+MzVfWvXhmKmI11WGAY5yXxIlPE4HJyBAtCm/Eq8szzeDcPGl/IMa0pLV/F9fOtk82obkX4DwO6Nunc8TkwxbD4o9l0MRVbLGiS14zjN809NfRICwTXlKdhIZy2EBiOYRdOdyZCkdS/J4SV0f2/eJffM4heYGxFHi9J7+aTT/delbP4zz+vc/4Y+hc/M03vAwinim1HdrwTyFS+a57SbBMXrKxUeyPRnLGPNB8WrzvBpMofw5KS3YGsLDu9z3my3NrQfz60v1OnBKFTTLTewGM4VyH365qrzPNau7ndgkyK+68sboCEUiurgrpalnqoXjgl5zAN3vMwWez1TwXVKqaJwJFIf0HlbUBOZuZ5lKA3//QhofI0Nhvt8dfuGqNsmvuK7w+TlRjsSjuCAWjm//QHEjdPfOMncl05ZtLS+tfZJCmsL2ufaNju4SiFYy5mEr7GK91FkWEXUcWBPWwwwScN4u/HcLhYUY/fmNK6+ZqjQeiO+z79HqBGeA4lFVa8YHP9XCcAjtmMKrPaawz5sQJMCXvn3laNuFNyoHl50H1QJyx6fgMovnzwMdHva+PH5Om4XSi1/NVEfWcUA7B37S613Zfb11YeqVquTgdqXuV5OGgpTHIXTMU4Roj+aFufhOuaqCjucKxMYf3otHw+C77nuHDl1SokLAqoQfPwfPvpgkiuMS44xtvaOMtaR/D77yc3Z8GCvpCAcClbSVYIESB8GEPj1MsUc8H+ZSoqtN4YMYq74GhOM7Fa2u8lP6TMFOwoUcgiw3EBUByRcLmRAs+qqQsfwpvK3JxJRoh5Idh60pdUX/gW07uJ7Bjhnm7GnDIOgJFHFhSAw+dvZzsCNp0AN3MwDRjDitIf4lTl59LGeUGZRF+ezQr4qDnWdFhvZK9z0XNGSmgwd7BcqBUeI1wZMU4f/Dx9ONP8SV1MYkqpMYwUtMyimRkJXNirhZWgkPbtqYM5BYVQwhVXFm1NlxPzrtf9HHSqA5uiRs0/Ei9hevLwYk0kaAKVmPTYz7aktyzXPix4rlP/g4l2qSotRTfG4deeUBLE3JZZVxvLN3GZ41Dji4NEDIrUP0Epj60WZN19xEZazJZ1Ox6yMaetCp/F2lyp6KUBQbzSchMr9f1UzZHLzeHeUX0Dn0Iz7eo+xVRJnNKYVLXXHvQM2Xv/Qf9pQya7LIEj8iGBHV4y57RDNTzkOgI2KVSxuf0qa1XOA6lfW15Qp8aRPh7dC48pYv7hsTMo5zb7n/NOx4/wfj+XZzaVSKoVjYooMnwGNt6pySrZkMdzX2/V1q1OA0gBD7pM2qE/9g4Hv8O4lbXCIemF4qg+ubHtY96zEA2zDSIJiOYdTTtjYZsnxTmnllsrtqjuFozFNChfeFXS6tv3K2PteTbLjJdsNTqlKu7TiRQ1frFVkE2CGiv2gk/aPCbiLVeeLYbh/66DRXVPFsIlB66qukhcWb68enDLFTcetktJqVj73dHXWM2Uo+2IzoeDGf5m+N0rOpXCTPKhg/S1ld56QJF9w1tJbaYpWuCIVBf6sFKLOO8oL3bygPf2EvBllHWQWGTaP9JXuWsPO9/vieEWSf1m7mmbRdJ6tj+7IN91CDfrfPR6qBYWnyuAxapf0ks8yZTOmg/Z6cO0Rv6f4OfoY/J3h10QHhxwlWXu1Pvf6isqN5hToWCAwh3avhxrN8JN8yCkqmmDxDRgadT6wLhCKS/lpn5XfIvQ4r5Y2/TmmfwQBO7txYaOG4g6yRgXXf5jGYBhjLwV0S3vxqudcuyeibWp1SFhheT9Q+SWDzXLLmQV+Vz8FsliLzGyxDsS0RoGkBfnm1cMzJpdp8eNHi/ld98lanIXwboe9OeQHEEJOKHjGuM9wtbue9AuR9tCH81vttQxHqYa9bjCOHXOi0SjgejgqHP34pzqllN0p+tnVenCMhzhduMFa2wJx/oerM8QBt8lTVC0oiHcypQtu2/X0M6LhONnm5LFkY3BpFkvw20IXG5+tAi5j0CQ7HOf+avwkXaXGl0LYVEaGsmCJWo5kEwHsKTSY385gunH5SNNLHZqMKr3iccdYkGW4y2Qjmm9FOsEjWv/rpcboKFc09YGMUgjsKq3AYuLjcsjovcdBABV96PU6wIg8JmliFCLehbLVlvaZNgjF0mSmKJEhatypyjAnhQKe8rVmI3ioCo3kWNfbRSz5QmEd0RJbDD/rE6+RtYZawansGxr2/3+XPskrFL+9OLxyFaZnHhi9KoQ4LHGlicR6IS8r2Jp3VSHbWVBvSQHLh3GebNJAlJELrMYRpBxHEtPJfY10r6zpoe47i8WBtbxwVUXwLqFEl0t0zgdDS8CQ6IT0qasmbNFmdFnz06Ck3fuNIU35uFCUHDkME/prdZN+BnkxSw4WEcpfbgbvckRgGR3/HoRfEGnV5Eb9SbE9VkZea+xC1p5tZCDTKt+R8lRTjV8q6HoMElKhdp9kH8j0j9pY6taM2Hm7Z5PLnDp+RjZCshlmE+wIirHEWLTyIxXgyhGQMhYNmDoVRlgBglV78L0tb3ZoEOTVwMYde86UGQM7bsEFavjiiIL4FO80KhmVe2dvSH/LXmC32SY7khqyQ7HAFEJZ2v6ied5a0Txi8pNLBkFCIOGDMnOKHYLVsiqrPsnXE5TmQNCINN7gdbemKAta51g0EDfIJD8ZcKW63t69ruceH0Dfj7DwwjE8wmuLjC7glkks0WrbiF3vITKRZoRwK2757wStiPZ1fd+3uN0VU+JrNjzOIIahPeNk//GiLP+FqF5ZwCb3SgRr13+49SmoO2agEKwahCPfNo1kJn1w8ZhrDncW5JddHzNbYpdSShcaQYarFiNXgVhf9Ks7U0PCK7ibjGfJcyrG8SG4kkGKOWZkvqKCGwo0tnF9pvdpW2x56Dp6+H7Ur6heNK8K1hHuWwH+fDK3k3m4h8SZhsbdoNoSq658CfwPs8s8ZiVQxWXEFBWLwCjkV6QbyEB3a9IQ4OttmoVTdK++w6QQB/63NtCLNOaQXPVnEwLVP9+KaHEd1KutoFcU4D9tTXEdHmqHG0D1FmVshD8PA7jT2VqxtrMTPS6kEz5sZVBiwwwNkyr5YiEMtaWPym/ySvMgWqlno6bBZ1O6YhvEyVecX9fcwylGH1SMzMYl0eV/bm7FJRYH6CyhkTgOFuQQamPzN2oDLCnPpgWgvYErGoG1QYI7hHnKhNgWw2NstyZbkWejYD13a1IZ39X8bMuB3jAiDQDvFiCgpaGzNYIzrJpUXpSmOemW+Y8CVuzgwiQR4EinjtOy2OlsXEacM+GG61yRioTQhaejQfCNdLmfusg8Ow1gFLGSG/ndwegVzKgZltOsQVT0aCWk1FUlOAEe5sX6yjCpDpFVZSDSyhUqv/DYS00XP/hv31a/jRqU1qRclbaWIme2WtTRH7UUH1MohZtRvvOCHSoURR7hyPnO5enF1lgq4vz2u+Ep5rztZ9RG5USNY8DMRZfb5eFjGBhuqt8pSLqSU+2Noq/s4FZqGY+cGTfu+JcB8RpWuOHtbY+gpdxBVLUXmSMicckKzUprK5rMJ77viiQdQM8r8H0mn6CoUsGCoMWNRbW5PrvrXWcjl7yFB2n4/UdAYJ/9LWDEfypFxL/6tuLXKoQO4dzXVMMJBk3i0eOQF5BLfhCq4sg1krWKnD7pwRMant9kYgYlV/CHmBVV5KFr25gOFFnmqShhXskEgFpdbXnmJgoecmcBW90qbrTBmLOoCSRIpLxDmuko9sMUi4NZHgUg6d+zsLJkJ2cBwbQDMFsf/S76HQk7J7n48nuDukST0S13fH1u0JHU9vfd21wb0rH8G2/PGQn8NCA27u6pHJG7bxD92GUJayPHneTMmUmSfnU7J+1QSYPDpjwJpO1BvliEPvRA73QB7IMCckYn3qJu3Hncl8q/YOwqUqEHCF+wasP2NxEP7TcD1+n6Xg+XjhfoCtpQfIFD+mfIQCMgWLEtkJqFWwAW7m5caAZKT497cIUgS5PtnkFrtfmqGNm9Alu7ZrhNi340qbfIUJwVYwAtqKkR29+9N0QzT1MRDrjmd4GfpKyQcffsnMN2ZUWjeB2d7mPqCy1J9OnbVOPsfdRyk7buQU9/PHvFKBCtu6ofQOxH7851qa/4c5WrfFnR2Ca87wyCErTfoBS61vUX0igCRS/L/TZTg77J2zZG7fattQWPdddqNEDhZt/0rSa1ndj8Giqx2wj7Ogmy9iH9V08SQFhG+OQC5K6kq1UFhUT88QEHkXPbL00fWuTvBB5d2D8shFME0qBV2xzCtheaBTdqXBoGF1Hag/ci2Gg/1eAOTVRzquT1uKfdyr6yLWigsJuTrzerbQ5A2OaKA+Jmc46VuhWTfB+GjN3/KPyiKCT/THFiSicbUvd8ZAa//lIOclIlXjviwfYCoU5W3jVCbOuL4JzXv/TvBdp3C3qkQrZej38KleXtvQyTuX21Cq0h35OKQI6KFbE98tvVpa8m59mOShITXNzK6V1cuQX1UHQheubW//0Xo4UWICXyj0pPUVPtRTaxNoXsYZ0M/+oTVgIjNGK20oBr8/gMYDuKDNFoB+e06fs86QZ8Cm6/gA0Pae9vcJOPk8iR+yb1vJ4GAfFKhKtra7dK9+PW04yYMbHJIfaeQ3l0n6IlhLXNaLIL+QetMZPjA3BzK59+8ZWhVvKKfgUle8EiJc8TydfawJa0QixqlcwK3IwWwI/gMQk/skZHo2YHEu5/6ImwMw8YJAfk7eDerwh4pJA72xQtjX/dyffV2S2FTfmRirvKdTAsyDnhS7GOauXMqWVh2hLwuJgBMENXuNpt1MuuXeA4RK7TXc8e5zT+tsZHqKktGEDF3+q4WL3Jzy5q9mllqGYLoQIW+SSjexczx6NjAdXhdnVwuZLVY3TT9zV8C9gvmKcHkB+UkdDophwkIh0yV6mLWoDqaeCJA9mIStNoggAAAAId0I6+WIYE7HvWPrIGRUH7EIga+q1s0Aw0Hwcn8sFfCbrPpi+uh9GoAAAAAAA=';
  }

})();
