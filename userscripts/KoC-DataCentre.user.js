// ==UserScript==
// @name         KoC Data Centre
// @namespace    trevo88423
// @version      2.25.0
// @description  Sweet Revenge alliance tool: tracks stats, syncs to API, adds dashboards, XP→Turn calculator, mini Top Stats panel. v2.25.0: Mission history — the pages that list missions are now read when you open them and shared with the alliance roster: a target's Intelligence file (your recon and sab missions on them, Success or Aborted), the Poison Log and Theft Log (both directions, with what was stolen), your Intelligence page (recon and sab missions run against you, and how many of their spies were caught) and the Attack Log (attacks and raids both ways, with gold stolen and losses). Any sab report you open adds its details too — what it destroyed, spies and sentries executed, gold and XP. This feeds the War Room's new success rates — per member and per mission type, never per target — which are visible to everyone with roster access, as the settings panel now says. The script sends each page's own wording and the server interprets it, so a result nobody has seen yet (a successful poison, say) is kept rather than lost and is sorted out once it turns up. Only the page you open is read: it never turns a page, opens a report or fetches anything, and those pages look exactly as before. Also: the Sab Tracker's Intelligence-file backfill now shares that same read. v2.24.0: Attack page range warnings — under each mission's "can … up to …" line the attack page now says whether the target is actually in reach: their sentry, antidote, vigilance or defensive action as last recorded by the alliance, against the limit the game prints for you, with how old that reading is. ⛔ Out of range means the mission will fail — the game lets an out-of-range theft fire anyway, which is how four thefts on one target all failed. The Theft box also gets a theft-cap line: how much of the target's daily theft cap is left, or THEFT MAXED. New Target check log: every attack page you open records that you checked that target — whether it was maxed, how much of its sab and theft caps is used, and your own attempt and success counters on it — so the War Room can show who saw a target maxed and how long ago; those counters are visible to everyone with roster access and will feed members' success rates. The War List collector now also shares who is on the list, when and why they were added, and your own "My 24hr" counters — and on the War List and Farm List the script now makes no changes at all (no toasts, no styles, no overlays), as the game's rules require. The settings panel now says exactly what the Sab Tracker sends. v2.23.2: Fix — the Sab Tracker vanished on the page the game shows after refusing a sab on a maxed target ("This player has been maxxed…"): that page has no player id in its address, so the tracker, the TIV reading and the sab-cap sharing all quietly gave up — at the one moment the script knew for certain the target was maxed. They now read the target from the page itself. Also fixes the Intelligence-file backfill for the Sab Tracker, which looked for the mission type in the wrong column and so never matched a row; it now finds the column by its header. v2.23.1: Inactive Accounts sync now works while you are logged out — including while you are on vacation and cannot log in — using the login saved from your last visit. On that page, logged out, it is the only thing the script does; every other feature still needs you logged in. Also: a network blip or server restart while renewing your session no longer logs you out of the script. v2.23.0: Inactive Accounts sync — opening the in-game Inactive Accounts page now shares the list with the alliance roster: who went into Vacation Mode and exactly when, and who has been deleted. Anyone who has dropped off the list since the last visit is marked back from vacation. This powers the new Vacation Watch tab on the dashboard, with live countdowns to when each player can return. The script only reads the page you open; the more often members check it, the sooner returns show up. v2.22.0: The War List's "Last Sab" column is now collected too — who last hit each target, for how much, and how long ago — giving the war dashboard a "Last hit" column that shows which targets the alliance is actually working and which nobody has touched, plus a running log of destroyed value for the war. v2.21.2: Fix — TIV readings from the attack page and your Armory were being sent with a timestamp field nothing reads, so they arrived unstamped and skipped the server's "only overwrite if newer" guard, letting an older reading quietly replace a fresher one. v2.21.1: War List collector reads the AAT and Sentry cells from their own DOM nodes instead of the cell's flattened text — those cells hold two numbers separated only by a line break, so any flattening ran "488" and "488,000,000 damage per sab" together into 488 billion. Works on both the Alliance and Single Target lists. v2.21.0: War List collector — opening the War List now records, for every player on it at once, their sentry (stamped with the age the game itself shows, so it never overwrites fresher recon), the weapon the game recommends sabbing them with, and the AAT: how many of that weapon they actually hold plus the gold one full sab would destroy. The war dashboard gets an AAT column and a "Min AAT" filter, so targets who simply do not own enough weapons to be worth organising around can be filtered out in one click. v2.20.1: Fix — race now updates when a player switches race. Race was only ever read from a full recon report, so a race change sat wrong in the roster until somebody spent a recon on that player, even though every visit to their stats page showed the new race in plain sight; the stats-page collector now reads the Information table too (race and rank), and it no longer gives up on players who have no shared recon data. v2.20.0: Sab cap sharing — opening any attack page now records that target's "Total lost from sabbs in the last 24hours" and "Maximum Daily Sabotage loss" to the alliance roster, so the War Room can show how much of every player's daily cap is already gone and how much gold is still worth sabbing, with a share button that copies a Discord-ready line. Also fixes the sab-cap reader: KoC prints the cap with decimals when it isn't a whole number, which the old pattern could not match, so the in-game "sab damage left before maxed" line silently never appeared on those targets. v2.19.1: Fix — a target sabbed flat reads "Total Invested Value: ()" with empty brackets, which the TIV collector could not parse, so the roster kept that player's pre-sab value forever and never stopped asking for a recon that could not land; empty brackets now record as a real 0 (on your own Armory too), while a box the script genuinely cannot read is left alone instead of writing a false zero. v2.19.0: Stat Reshuffler — Goal mode: pick a stat and type a target rating (commas fine, or shorthand like 4.78T) and the calculator shows the gap from your PROJECTED rating — so your sells, race change and re-buys are already counted — plus how many weapons and how much gold on top of the plan would close it, netting off any unspent pool. Warns when your units couldn't hold that many more weapons. The goal is remembered between visits and updates live as you tweak the scenario. v2.18.3: Stat Reshuffler — the launcher moved: it now sits as a full-width banner directly above the "Armory Preferences" header, styled by cloning that header's own theme (background, border, font) so it looks native in any skin; falls back to the old Total Invested Value spot if the header isn't found. v2.18.2: Stat Reshuffler — stale-multiplier warning: a learned weapon multiplier quietly goes wrong after skill/tech upgrades (it only refreshes when you buy), which left phantom rating behind on sell-all scenarios; the reshuffler now compares each learned multiplier against what your live rating implies and flags "⚠ stale multiplier — buy 1 to recalibrate" per stat plus a summary warning, with the multiplier's age shown. v2.18.1: Stat Reshuffler — new "Ignore carrier caps" toggle for when you're happy to train soldiers/covert units as needed: projections then count every weapon as held (including ones currently sitting unheld) and the ⚠ unheld warnings disappear; the choice is remembered. v2.18.0: Stat Reshuffler — a 🔀 button under the Armory's Total Invested Value box opens a full what-if rework calculator: choose weapons (or whole categories) to sell, optionally switch race, and pour the proceeds — plus your on-hand + vault gold if you tick it — into any mix of the eight stats. It projects the gold you'd recover (sales pay 50% and land in your Vault), how many of each weapon you could buy, whether your units can actually carry them (unheld weapons add nothing), your projected new ratings including the race-bonus swing, and your new TIV. Pure calculator — it never sells, buys or presses anything. v2.17.1: Fix — clicking the sidebar Sweet Revenge logo now opens the feature-settings popup (same as the ⚙ Data Centre link) instead of navigating away. Internal cleanup: removed the unused armory sell-value cache (nothing has used it since the v2.11.2 "Upgrade Ready" rework). v2.17.0: Feature Settings — a new "⚙ Data Centre" link in the sidebar opens a settings panel where EVERY feature can be switched on/off individually (or all at once with the master switch), each with a plain-English description of what it does and a badge showing whether it only changes your display or also records data to the alliance roster; toggles apply on the next page load and everything stays ON by default, so nothing changes until you say so. Under the hood the script's ~40 page hooks were rebuilt onto a single feature registry that drives both the dispatcher and the panel, ~600 lines of dead legacy code were removed, and small fixes landed (DST helper deduplicated, script load message now always visible in console, toast animation style no longer re-injected per notification). Also: the sidebar Sweet Revenge logo is now a link to the Data Centre (with a hover glow), and the Top Stats panel's Debug button is gone — debug mode lives in the console via KoCDebug.toggle(). v2.16.0: Sab Tracker learns the exclusivity rule — per target you either regular-sab OR revenge-sab in a 24h window, so the panels now show 🔒 "Regular sabs locked — you revenge-sabbed this target" with an unlock countdown that keeps working after the Revenge section vanishes (target un-maxed — exactly when KoC hides the info), and 🔒 "Revenge locked — you've sabbed this target this window" when the Revenge form is up but unusable; the native "First sab (last 24hrs)" row is age-formatted like the rest and its exact server stamp now anchors the tracker, making the "Can sab again in …" countdown precise instead of an estimate. v2.15.0: Sabotage Tracker on attack.php — "You last sabbed / poisoned / stole" and the revenge timestamps now show colour-coded ages like the stats pages (hover for the raw server time); the Sabotage and Revenge Sabotage sections get a live status line: attempts left in the rolling 24h window with a ticking "Can sab again in …" countdown when you're out of slots (10 sabs / 4 revenge per target per 24h, tracked automatically whenever you fire a sab and backfilled with exact server times when you open the target's Intelligence file), plus a "sab damage left before maxed" line (Maximum Daily Sabotage loss − lost in last 24h) that flips to TARGET MAXED when the cap is hit. Display-only: it records only missions you fire by hand and never presses anything. v2.14.0: Tech Level Projector — the "Stats After Upgrading Tech" table on safe.php gets a "Project to" dropdown: pick ANY future tech level (up to Obi Bon Kenobi) and the table shows your projected stats at that level, with the total ▲% vs now and the cumulative EXP needed across all the upgrades in between. v2.13.1: Rank-neighbour links now blend into the native table — no dot markers or underline, the numbers just quietly became links (hover tooltip still shows who it is, data age, and gap/stale warnings). v2.13.0: Rank-neighbour recon links — the "Rating For Previous/Next Rank Gain" numbers are now hyperlinks to the player we believe holds that rank (matched by rating value from the roster DB, never by stale DB rank), with a tooltip showing who it is + how fresh their data is; an orange dot means a DB gap (recon upward), a red dot means DB rank/rating disagree (recon me first). Click → recon → DB refreshes; wrong candidates rotate out on the next page load, so the links self-correct toward the true neighbour. v2.11.2: Banking Mode redesigned — your exposed gold now shows in a native-style "Estimated Funds" box that matches the in-game funds boxes, with a ⚙ that holds the Banking Mode toggle, screen-awake, and all settings (including an optional "show yellow/red times" line); a live-ticking Server Time clock on every page; and the Upgrades "Upgrade Ready" row now uses realistic funds (drops full-armory-sell) and shows any shortfall as a slay estimate. v2.10.1: Fix — the slider Armory Preferences now also resync when you press KoC's "Clear Percentage Prefills" button (sliders drop to 0 instead of keeping their old values). v2.10.0: New slider-based Armory Preferences — drag to allocate with auto-balancing, theme-matched styling, and one-tap presets (Cheapest first, Optimizer, All spy, All defense) plus saved presets — replacing the in-game percentage form; rank Optimizer also fixed (weapon efficiency now synced). v2.9.0: "Time to upgrade" + "EXP still needed to be deposited" now show on ALL EXP-cost safe.php upgrades (Increase Soldiers, Economic Development, SAFE Upgrade) — not just Technological Development. v2.8.2: Fix — "EXP still needed to be deposited" now shows cost − Experience Bank (what must still be banked) instead of also subtracting on-hand EXP, so it no longer reads 0 when you hold the EXP but haven't deposited it. v2.8.1: Fix — sidebar abbreviates large gold/safe values (e.g. "2,560M"); getSidebarValue now parses K/M/B/T suffixes so SAFE Forecasts and gold-upgrade rows use real balances (previously read as ~0). SAFE Forecasts also uses the full-precision "Gold in Safe" value. v2.8.0: SAFE Forecasts on safe.php — time for your Safe to reach 1B/2B/5B/9B/10B(MAX) based on current Safe + deposit/min. v2.7.0: Gold upgrade timer — upgrades.php now shows "Upgrade Ready" (liquidation + safe-growth time) and "Gold Needed on top of Safe" under each skill upgrade (uses gold/vault/safe + full armory sell value from Armory + safe deposit rate from Safe). v2.6.0: Tech upgrade timer — safe.php now shows "Time to upgrade" + "EXP still needed to be deposited" under Technological Development (uses EXP on-hand + Experience Bank + your EXP/turn rate, auto-captured from the Upgrades page). v2.5.1: Banking Mode last-bank fix — now watches the per-weapon buy form (anotherbuyform), not just the hidden one-click form, and stamps banks reliably for high-income accounts. v2.5.0: 🏦 Banking Mode on the Armory page — toggleable inline widget that projects your exposed (stealable) gold every second, colour-codes the risk (SAFE/CAUTION/DANGER) from your attack-log steal history, shows time-to-yellow/red, and keeps the screen awake. Display-only: no automated requests, observes (never presses) the buy/repair forms. v2.4.0: Banking trend graph (📈 in the sidebar tracks your banked % over time) + manual override for Avg Gold/Atk (✏️ in the sidebar, survives attack-log recalibration). v2.3.4: Recons panel now shares counts alliance-wide via API (previously localStorage-only — each user only saw themselves). v2.3.0: Added "Stats If You Attacked Instead" table on safe.php to compare tech upgrades vs attacking. v2.2.9: Added optimizer auto-fill for armory (uses roster API to calculate optimal stat allocation). v2.2.8: Minor fixes. v2.1.0: Integrated slaying competition tracker (attack missions & gold stolen tracking, team competitions, leaderboards). v2.0.0: Optimized API architecture, previous versions deprecated.
// @author       Blackheart
// @match        https://www.kingsofchaos.com/*
// @exclude      https://*.kingsofchaos.com/confirm.login.php*
// @exclude      https://*.kingsofchaos.com/confirm.login.php
// @exclude      https://*.kingsofchaos.com/security.php*
// @exclude      https://*.kingsofchaos.com/error.php*
// @exclude      https://*.kingsofchaos.com/recruit.php*
// @exclude      https://*.kingsofchaos.com/farmlist.php*
// @exclude      https://*.kingsofchaos.com/error.php
// @exclude      https://*.kingsofchaos.com
// @icon         https://www.kingsofchaos.com/favicon.ico
// @grant        none
// @updateURL    https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js
// @downloadURL  https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js
// ==/UserScript==

(async function() {
  'use strict';

  // ==================== SECURITY CHECK ====================
  // Don't run on login/security pages or when logged out — with one exception.
  // The Inactive Accounts page opens without logging in, and a player on
  // vacation cannot log in at all, so on that page alone a logged-out visit
  // runs the Inactive Accounts collector and nothing else (see runFeatures).
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
  // collectors marked readOnly (see runFeatures), and every piece of shared
  // machinery that could draw something — the version-check overlay, error
  // toasts, the stylesheet at the end of this file — stands down. farmlist.php
  // is @excluded as well; it is listed here so the guard holds even if a
  // script manager ignores the exclude.
  const READ_ONLY_PAGE = location.pathname.includes('warlist.php') ||
                         location.pathname.includes('farmlist.php');

  // ==================== SCRIPT MANAGER CHECK ====================
  // Check if this script is enabled in Script Manager
  if (window.KoC_ScriptManager && !window.KoC_ScriptManager.isEnabled('data-centre')) {
    console.log("❌ DataCentre disabled by Script Manager");
    return;
  }

  // ==================== VERSION CHECK ====================
  // Check if this script version is allowed to run
  const SCRIPT_NAME = 'koc-data-centre';
  const SCRIPT_VERSION = '2.25.0'; // Must match @version above
  const VERSION_CHECK_API = 'https://koc-roster-api-production.up.railway.app';

  async function checkScriptVersion() {
    try {
      const response = await fetch(`${VERSION_CHECK_API}/script-version/check/${SCRIPT_NAME}/${SCRIPT_VERSION}`);
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

        // Stop script execution
        console.error(`[${SCRIPT_NAME}] Version ${SCRIPT_VERSION} is blocked. Please update.`);
        throw new Error('Script version blocked');
      }

      // Show a non-blocking "update available" warning ONLY when the server
      // actually reports a newer version. When version checking is disabled for a
      // script, the server returns {allowed:true, "Version checking disabled"} with
      // no isLatest/latestVersion fields — guarding on latestVersion here prevents a
      // spurious "A newer version (undefined) is available" log in that case.
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

  // Version & API
  const VERSION = (typeof GM_info !== "undefined" && GM_info.script && GM_info.script.version)
    ? GM_info.script.version : "1.41.9";
  const API_URL = "https://koc-roster-api-production.up.railway.app";

  // LocalStorage Keys
  const TOKEN_KEY = "KoC_SRAUTH";
  const TIV_KEY = "KoC_DataCentre";
  const MAP_KEY = "KoC_NameMap";

  // Authentication & API
  const TOKEN_EXPIRY_MS = 12 * 60 * 60 * 1000; // 12 hours
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
  const PAGE_LOAD_DELAY_MS = 500;
  const ATTACK_LOG_DELAY_MS = 600;
  const POPUP_REFRESH_MS = 1000;
  const NOTIFICATION_DURATION_MS = 5000;

  // Storage & Validation
  const MAX_STRING_LENGTH = 1000;
  const MAX_PLAYER_FIELD_LENGTH = 200;
  const STORAGE_CLEANUP_DAYS = 30;
  const ASSUMED_STORAGE_LIMIT_MB = 5;

  // Performance
  const BATTLEFIELD_DEBOUNCE_MS = 300; // Debounce battlefield observer
  const BATTLEFIELD_COLLECT_DELAY_MS = 200; // Delay before collecting battlefield data

  // ==================== DEBUG MODE SYSTEM ====================

  /**
   * Debug Mode System
   * - Stores debug state in localStorage
   * - Provides conditional logging functions
   * - Can be toggled via UI or console
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
  infoLog(`✅ DataCentre+XPTool v${VERSION} loaded on`, location.pathname);
  if (DebugMode.isEnabled()) {
    infoLog("🐛 Debug mode is ENABLED - Toggle with: KoCDebug.toggle()");
  }

  // ==================== KOC SERVER TIME UTILITIES ====================

  /**
   * Parse KoC Server Time from page and convert to UTC ISO string
   * Server Time is displayed in left panel on all pages
   * KoC uses US Eastern Time (EDT/EST)
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

  // Live-ticking Server Time clock. DISPLAY-ONLY: anchors to the value KoC rendered and
  // advances it locally each second (re-synced on every page load, so it can't drift).
  // Compliant — no network, no game actions; it only rewrites the clock's own text node.
  let __serverClockId = null;
  function startServerClock() {
    if (__serverClockId) return;
    // Find the leaf element holding ONLY a datetime. Prefer the one whose ancestors/table carry
    // the "Server Time" label (pages with other timestamps); else the page's sole datetime.
    const leaves = [...document.querySelectorAll('b,td,th,span,div,font')].filter(e =>
      e.children.length === 0 && /^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\s*$/.test(e.textContent || ''));
    if (!leaves.length) return;
    const labeled = leaves.filter(e => {
      let c = e;
      for (let i = 0; i < 5 && c; i++) { if (/Server Time/i.test(c.textContent || '')) return true; c = c.parentNode; }
      const tb = e.closest('table');
      return tb && /Server Time/i.test(tb.textContent || '');
    });
    const leaf = labeled[0] || (leaves.length === 1 ? leaves[0] : null);
    if (!leaf) return; // ambiguous (multiple unlabelled timestamps) — skip rather than tick the wrong one
    const m = (leaf.textContent || '').match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
    if (!m) return;
    const baseMs = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();
    const t0 = Date.now();
    const p = n => (n < 10 ? '0' + n : '' + n);
    __serverClockId = setInterval(() => {
      if (!leaf.isConnected) { clearInterval(__serverClockId); __serverClockId = null; return; }
      const d = new Date(baseMs + (Date.now() - t0));
      leaf.textContent = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    }, 1000);
    debugLog('🕐 Server clock ticking');
  }

  /**
   * Whether US Eastern DST (EDT, UTC-4) applies on the given date.
   * US DST: 2nd Sunday in March to 1st Sunday in November.
   */
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

      const isDST = isEasternDST(year, month, day);
      const offset = isDST ? 4 : 5; // EDT = UTC-4, EST = UTC-5

      // Create date object in Eastern Time, then convert to UTC by adding offset
      const date = new Date(Date.UTC(year, month, day, hour + offset, minute, second));
      return date.toISOString();
    } catch (err) {
      console.warn('⚠️ Error converting KoC Server Time to UTC:', err);
      return new Date().toISOString();
    }
  }

  /**
   * Convert UTC ISO string to KoC Server Time string
   * @param {string} utcIsoString - UTC ISO string like "2025-12-22T13:57:05.000Z"
   * @returns {string} KoC Server Time string like "2025-12-22 09:57:05" (or "2025-12-22 08:57:05" in winter)
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

      const isDST = isEasternDST(year, month, day);
      const offset = isDST ? 4 : 5; // EDT = UTC-4, EST = UTC-5

      // Subtract offset from UTC to get Eastern Time
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

          // Try to free up space
          this.cleanup();

          // Try again
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

    static cleanup() {
      ErrorHandler.log(ErrorHandler.LOG_LEVELS.INFO, 'Attempting to cleanup old localStorage data');

      try {
        // Remove old data (anything with timestamps older than configured days)
        const cutoff = Date.now() - (STORAGE_CLEANUP_DAYS * 24 * 60 * 60 * 1000);

        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (!key) continue;

          // Check if it's a timestamp key
          if (key.includes('_time')) {
            try {
              const value = localStorage.getItem(key);
              const timestamp = parseInt(value, 10) || Date.parse(value);
              if (timestamp && timestamp < cutoff) {
                localStorage.removeItem(key);
                // Also remove associated data key
                const dataKey = key.replace('_time', '');
                localStorage.removeItem(dataKey);
                ErrorHandler.log(ErrorHandler.LOG_LEVELS.DEBUG, `Cleaned up old data: ${key}`);
              }
            } catch (e) {
              // Skip if can't parse
            }
          }
        }
      } catch (error) {
        ErrorHandler.log(ErrorHandler.LOG_LEVELS.ERROR, 'Cleanup failed', error);
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

  /**
   * API call wrapper with offline detection
   */
  class ResilientAPI {
    static isOnline = navigator.onLine;
    static failureCount = 0;
    static MAX_FAILURES = 3;

    static {
      // Monitor online/offline status
      window.addEventListener('online', () => {
        this.isOnline = true;
        this.failureCount = 0;
        ErrorHandler.showNotification('Connection restored', 'info');
      });

      window.addEventListener('offline', () => {
        this.isOnline = false;
        ErrorHandler.showNotification('You are offline. Some features may not work.', 'warn');
      });
    }

    static async callWithFallback(apiFn, fallbackFn = null) {
      // Check online status first
      if (!this.isOnline) {
        ErrorHandler.log(ErrorHandler.LOG_LEVELS.WARN, 'Offline - using fallback');
        return fallbackFn ? fallbackFn() : null;
      }

      try {
        const result = await apiFn();
        this.failureCount = 0; // Reset on success
        return result;
      } catch (error) {
        this.failureCount++;

        ErrorHandler.log(
          ErrorHandler.LOG_LEVELS.ERROR,
          `API call failed (${this.failureCount}/${this.MAX_FAILURES})`,
          error
        );

        // If too many failures, suggest offline mode
        if (this.failureCount >= this.MAX_FAILURES) {
          ErrorHandler.showUserError('API appears to be unavailable. Working in offline mode.', error);
        }

        // Use fallback if available
        if (fallbackFn) {
          ErrorHandler.log(ErrorHandler.LOG_LEVELS.INFO, 'Using fallback function');
          return fallbackFn();
        }

        return null;
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

    if (result.values.avgGold < 0) {
      result.errors.push('Average gold cannot be negative');
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

  // ==================== AUTH MANAGER ====================

  // True when an element lives inside script-injected UI (SR stats panel,
  // competition panels, calculators) rather than native KoC markup.
  function isInjectedContent(el) {
    return !!el.closest('[data-koc-injected], #sr-stats-tables, [id^="koc-comp-panel"], [class*="sr-stat-"]');
  }

  // Find your own id/name from the native "User Info" table on base.php:
  // a row whose label cell is exactly "Name" and whose value cell holds your
  // stats.php link. Never read identity from the first stats.php link on the
  // page — injected leaderboards and farm lists come first in DOM order, which
  // is how wrong identities (Tobi-SR id='self', 'Members') got stored.
  function findOwnIdentityOnPage() {
    for (const row of document.querySelectorAll("tr")) {
      const labelCell = row.querySelector("td, th");
      if (!labelCell || !/^name:?$/i.test(labelCell.innerText.trim())) continue;
      const link = row.querySelector("a[href*='stats.php?id=']");
      if (!link || isInjectedContent(link)) continue;
      const id = link.href.match(/id=(\d+)/)?.[1];
      const name = link.textContent.trim();
      if (id && name) return { id, name };
    }
    return null;
  }

  class AuthManager {
    constructor() {
      this.token = null;
      this.authData = null;
      this.initPromise = null;
      this.listeners = new Map();
    }

    // Get stored auth from localStorage
    getStoredAuth() {
      return SafeStorage.get(TOKEN_KEY, null);
    }

    // Save auth to localStorage
    saveAuth(token, id, name) {
      // Decode JWT to extract role
      let role = 'member'; // Default role
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        role = payload.role || 'member';
        debugLog('🔍 Extracted role from JWT:', role);
      } catch (err) {
        console.warn('⚠️ Failed to decode JWT for role extraction:', err);
      }

      const authData = {
        token,
        id,
        name,
        role,  // Include role from JWT
        expiry: Date.now() + TOKEN_EXPIRY_MS
      };

      const success = SafeStorage.set(TOKEN_KEY, authData);
      if (!success) {
        ErrorHandler.showUserError('Failed to save authentication data. Storage may be full.');
        return null;
      }

      this.authData = authData;
      this.token = token;
      this.emit('authChanged', authData);
      return authData;
    }

    // Initialize auth (check stored or refresh)
    async initialize() {
      if (this.initPromise) {
        return this.initPromise;
      }

      this.initPromise = (async () => {
        const stored = this.getStoredAuth();

        if (!stored) {
          debugLog("🔒 No stored auth found");
          return false;
        }

        // Check if still valid
        if (Date.now() < stored.expiry) {
          this.token = stored.token;
          this.authData = stored;
          debugLog("✅ Using cached token for:", stored.id, stored.name);
          return true;
        }

        // Try to refresh
        debugLog("🔄 Token expired, attempting refresh for:", stored.id, stored.name);
        try {
          const resp = await fetch(`${API_URL}/auth/koc`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: stored.id, name: stored.name })
          });

          if (!resp.ok) {
            const err = new Error("Refresh failed " + resp.status);
            err.status = resp.status;
            throw err;
          }

          const data = await resp.json();
          const token = data.token || data.accessToken;
          this.saveAuth(token, stored.id, stored.name);
          debugLog("🔄 Token refreshed successfully");
          return true;
        } catch (err) {
          console.warn("⚠️ Auto refresh failed:", err);
          // Forget the saved identity only when the server rejected it (unknown
          // player, no longer in the alliance). A network blip, a server
          // restart or a rate limit is no reason to make somebody log in
          // again — and a player on vacation cannot; the next page load retries.
          if ([400, 401, 403, 404].includes(err.status)) this.clearAuth();
          return false;
        }
      })();

      return this.initPromise;
    }

    // Get current token (waits for init if needed)
    async getToken() {
      if (!this.initPromise) {
        await this.initialize();
      } else {
        await this.initPromise;
      }
      return this.token;
    }

    // Check if authenticated
    async isAuthenticated() {
      const token = await this.getToken();
      return !!token;
    }

    // Login with KoC credentials
    async login() {
      try {
        let id = null;
        let name = null;

        // Only trust the native User Info "Name" row — never arbitrary
        // stats.php links (injected leaderboards poison the scrape).
        const identity = findOwnIdentityOnPage();
        if (identity) {
          ({ id, name } = identity);
        }

        // Fallback: previously verified identity from localStorage
        if (!id) id = SafeStorage.get("KoC_MyId", null);
        if (!name) name = SafeStorage.get("KoC_MyName", null);

        if (!id || !name) {
          throw new Error("Could not detect your KoC ID/Name — open your Command Center (base.php) and try again");
        }

        debugLog("🔍 Attempting login with:", { id, name });

        const resp = await fetch(`${API_URL}/auth/koc`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id, name })
        });

        if (!resp.ok) throw new Error("Auth failed " + resp.status);

        const data = await resp.json();
        const token = data.token || data.accessToken;
        this.saveAuth(token, id, name);

        alert("✅ SR Login successful! Refreshing…");
        location.reload();
      } catch (err) {
        ErrorHandler.log(ErrorHandler.LOG_LEVELS.ERROR, 'Login failed', err);
        ErrorHandler.showUserError(null, err);
        throw err;
      }
    }

    // Logout
    logout() {
      this.clearAuth();
      this.emit('authChanged', null);
      alert("Logged out.");
      location.reload();
    }

    // Clear auth data
    clearAuth() {
      SafeStorage.remove(TOKEN_KEY);
      this.token = null;
      this.authData = null;
      this.initPromise = null;
    }

    // Show token info
    showToken() {
      const auth = this.getStoredAuth();
      if (!auth) {
        alert("❌ No token stored.");
        return;
      }
      alert(`📜 Token Info:\n\nID: ${auth.id}\nName: ${auth.name}\nExpiry: ${new Date(auth.expiry).toLocaleString()}\n\nToken: ${auth.token.substring(0,40)}...`);
      debugLog("📜 Full token object:", auth);
    }

    // Make authenticated API call with auto-retry
    async apiCall(endpoint, data, retries = RETRY_ATTEMPTS) {
      const token = await this.getToken();

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
        try {
          const fetchOptions = {
            method,
            headers: {
              "Authorization": "Bearer " + token,
              "X-Script-Name": SCRIPT_NAME,
              "X-Script-Version": SCRIPT_VERSION
            }
          };

          // Only add Content-Type and body for POST requests
          if (method === "POST") {
            fetchOptions.headers["Content-Type"] = "application/json";
            fetchOptions.body = JSON.stringify(data);
          }

          const resp = await fetch(`${API_URL}/${endpoint}`, fetchOptions);

          // Handle 401 - token expired
          if (resp.status === 401 && attempt === 1) {
            debugLog("🔄 Token expired (401), refreshing...");
            const refreshed = await this.initialize();
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

    // Get auth data for external redirect (secure)
    getAuthForRedirect() {
      if (!this.authData) return null;
      return {
        token: this.authData.token,
        id: this.authData.id,
        name: this.authData.name,
        role: this.authData.role || 'member',  // Include role for admin access
        expiry: this.authData.expiry
      };
    }
  }

  // Create global auth instance
  const auth = new AuthManager();

  // Add server debug control functions to KoCDebug (now that auth exists)
  window.KoCDebug.serverEnable = async function() {
    const token = await auth.getToken();
    if (!token) {
      console.error("❌ No auth token found. Please log in first.");
      return;
    }
    try {
      const response = await fetch('https://koc-roster-api-production.up.railway.app/debug/enable', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const result = await response.json();
      console.log("🐛 Server debug mode ENABLED:", result.message || result);
      return result;
    } catch (err) {
      console.error("❌ Failed to enable server debug mode:", err);
    }
  };

  window.KoCDebug.serverDisable = async function() {
    const token = await auth.getToken();
    if (!token) {
      console.error("❌ No auth token found. Please log in first.");
      return;
    }
    try {
      const response = await fetch('https://koc-roster-api-production.up.railway.app/debug/disable', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const result = await response.json();
      console.log("🔇 Server debug mode DISABLED:", result.message || result);
      return result;
    } catch (err) {
      console.error("❌ Failed to disable server debug mode:", err);
    }
  };

  window.KoCDebug.serverStatus = async function() {
    const token = await auth.getToken();
    if (!token) {
      console.error("❌ No auth token found. Please log in first.");
      return;
    }
    try {
      const response = await fetch('https://koc-roster-api-production.up.railway.app/debug/status', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const result = await response.json();
      console.log("📊 Server debug status:", result);
      return result;
    } catch (err) {
      console.error("❌ Failed to check server debug status:", err);
    }
  };

  // ==================== STORAGE HELPERS ====================

  function getTivLog() {
    return SafeStorage.get(TIV_KEY, []);
  }

  function saveTivLog(arr) {
    // Limit TIV log to last 100 entries to prevent unbounded growth
    const MAX_TIV_ENTRIES = 100;
    const trimmed = arr.slice(-MAX_TIV_ENTRIES);
    debugLog(`📊 TIV log trimmed from ${arr.length} to ${trimmed.length} entries`);
    return SafeStorage.set(TIV_KEY, trimmed);
  }

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
  function runPeriodicMaintenance() {
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

    if (!isAuthenticated) {
      // Show login UI only on base.php
      if (location.pathname.includes("base.php")) {
        const box = document.createElement("div");
        box.style = "padding:12px;background:#111;color:#fff;border:1px solid #555;margin:12px;font-family:Arial;";

        // Check if there's expired/invalid auth in storage
        const storedAuth = auth.getStoredAuth();
        const hasExpiredToken = storedAuth !== null;

        box.innerHTML = `
          <h2>🔒 KoC Data Centre Login</h2>
          <p>You must log in with SR to enable the script.</p>
          ${hasExpiredToken ? '<p style="color:#ff9800;"><strong>⚠️ Your session has expired. Please login again.</strong></p>' : ''}
          <button id="srLoginBtn" style="padding:6px 12px;cursor:pointer;">🔐 Login to SR</button>
          <button id="srShowTokenBtn" style="padding:6px 12px;margin-left:10px;cursor:pointer;">Show Token</button>
          ${hasExpiredToken ? '<button id="srClearAuthBtn" style="padding:6px 12px;margin-left:10px;cursor:pointer;background:#dc2626;color:white;border:none;border-radius:4px;">Clear Session</button>' : ''}
        `;
        document.body.prepend(box);

        document.getElementById("srLoginBtn").addEventListener("click", () => auth.login());
        document.getElementById("srShowTokenBtn").addEventListener("click", () => auth.showToken());
        if (hasExpiredToken) {
          document.getElementById("srClearAuthBtn").addEventListener("click", () => {
            auth.clearAuth();
            alert("✅ Session cleared. Click 'Login to SR' to authenticate again.");
            location.reload();
          });
        }
      } else {
        console.warn("🔒 Data Centre disabled — not logged in.");
      }
      return false; // Stop initialization
    }

    debugLog("✅ Authenticated with SR, initializing features...");

    // Run periodic localStorage maintenance
    runPeriodicMaintenance();

    return true;
  }

  // ==================== PLAYER DATA MANAGEMENT ====================

  function updatePlayerInfo(id, patch) {
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
      auth.apiCall("players", { id, ...apiPayload });
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

  // ==================== BANKING HISTORY (TREND GRAPH) ====================

  // Throttled submission of a banking-efficiency snapshot to the API. The server
  // also throttles, but we avoid needless calls on every base.php load.
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
      const result = await auth.apiCall("banking/snapshot", data);  // data present → POST
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
      alert("Log in (🔐 button in the sidebar) to track your banking trend.");
      return;
    }

    const history = await auth.apiCall("banking/history?days=30");  // no data → GET
    const points = (history || [])
      .map(r => ({ t: new Date(r.recorded_at).getTime(), pct: Number(r.banked_pct) }))
      .filter(p => isFinite(p.t) && isFinite(p.pct))
      .sort((a, b) => a.t - b.t);

    if (points.length === 0) {
      alert("No banking history yet.\n\nVisit the attack log, then the command centre, a few times over the coming days — the banked % trend will build up here.");
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
    debugLog("[XPTool] initSidebarCalculator called");
    const BOX_ID = "koc-xp-box";
    if (document.getElementById(BOX_ID)) return; // Prevent duplicates

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
        <tr><td align="center" style="color:black;">Banked <span id="xp-banked">—</span> <span id="xp-banked-graph" title="Banking % trend over time" style="cursor:pointer;">📈</span></td></tr>
        <tr>
          <td align="center">
            <a href="#" id="sr-logo-link" class="koc-button" title="Data Centre feature settings">
              <img src="https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/images/SR_Logo.png"
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

        // Feature 1: record a throttled banking snapshot for the trend graph
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
          auth.logout();
        } else {
          await auth.login();
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
          debugLog("[XPTool] Avg Gold/Atk reverted to auto:", auto);
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
          debugLog("[XPTool] Avg Gold/Atk manual override set:", val);
        }
        updateXPBox();
      });
    }

    // Banking trend graph button (opens the banked-% timeline modal)
    const bankingGraphBtn = document.getElementById("xp-banked-graph");
    if (bankingGraphBtn) {
      bankingGraphBtn.addEventListener("click", (e) => {
        e.preventDefault();
        showBankingTrend();
      });
    }

    debugLog("[XPTool] Sidebar box inserted into page");
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
    debugLog("[XPTool] enhanceAttackLog called");

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
                    th.innerHTML = `<div style="text-align:center;">${th.innerText} (${labelTxt})</div>`;
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
                      debugLog("[XPTool] Avg Gold/Atk auto-calibrated:", avg);
                    } else {
                      debugLog("[XPTool] Avg Gold/Atk auto value updated, but manual override active — keeping manual.");
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

    debugLog("[XPTool] Recon Max Attacks row added:", maxAttacks);
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
      // so fixed indexes corrupt data: name gets the army size and alliance
      // gets the player name (the 'OwenN17'/'zeke1st' alliance rows in the DB).
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

        updatePlayerInfo(player.id, player);
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

    // Columns by header name, never by fixed position — the same rule the
    // battlefield collector learned the hard way when a dropped cell shifted
    // every value one place left.
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
    const rows = parseWarListPage();
    if (!rows.length) { debugLog('⚔️ War list: no parseable rows'); return; }

    // Who is on the War List, sent first and as ONE request, so it lands even
    // if the member moves on before the per-player loop below finishes: each
    // row's id, when and why it was added, and this member's own "My 24hr"
    // cells. The server keeps the list itself (first/last seen) and each
    // member's latest counters per target. Reading only — the game allows no
    // changes on this page, and nothing here makes any.
    const view = new URLSearchParams(location.search).get('view') || 'Alliance';
    try {
      const res = await auth.apiCall('api/war-room/warlist', {
        view,
        rows: rows.map((r) => ({ id: r.id, addedAt: r.addedAt, reason: r.reason, my24h: r.my24h }))
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

      try { await auth.apiCall('players', payload); } catch (e) { /* keep going */ }
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
        const res = await auth.apiCall("api/war-room/sab-results/bulk", { results: observed });
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

    const res = await auth.apiCall('api/war-room/inactives', read);
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
   * Reading the address alone made everything on that page go quiet: the Sab
   * Tracker vanished and the maxed state was never shared, at the one moment
   * the script knew for certain.
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
        await auth.apiCall(`players/${id}/mark-inactive`, {
          status: "deleted",
          error: "Invalid User ID"
        });
      }
      return;
    }

    // A target sabbed flat renders "Total Invested Value: ()" — empty parens,
    // not "(0)". The old [\d,]+ could not match that, so the one case we most
    // need to record silently skipped: the roster kept serving the pre-sab TIV
    // and the player sat on the War Room recon worklist forever, un-refreshable.
    const tivMatch = document.body.textContent.match(/Total Invested Value:\s*\(([\d,]*)\)/i);
    if (!targetId || !tivMatch) return;

    const id = targetId;
    const tivDigits = tivMatch[1].replace(/,/g, "");
    const tiv = tivDigits === "" ? 0 : parseInt(tivDigits, 10);
    if (!Number.isFinite(tiv)) return;
    const now = getKoCServerTimeUTC();

    // TIV on attack.php IS fresh data - it loads when you visit the page
    // It's used to calculate sabotage limits, so it must be current
    // Save locally
    const log = getTivLog();
    log.push({ id, tiv, time: now });
    saveTivLog(log);

    updatePlayerInfo(id, { tiv, tivTime: now });

    debugLog("📊 Attack TIV saved", { id, tiv });

    // Push to API
    await auth.apiCall("tiv", { playerId: id, tiv, time: now });
  }

  // ==================== ATTACK LOG COLLECTOR ====================

  async function collectAttackLog() {
    debugLog("📊 Attack log collector triggered");

    // Extract attack ID from URL
    const urlParams = new URLSearchParams(location.search);
    const attackId = urlParams.get('attack_id');
    if (!attackId) {
      debugLog("⚠️ No attack_id found in URL");
      return;
    }

    const bodyText = document.body.textContent || '';
    const myId = SafeStorage.get("KoC_MyId", null);

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
      debugLog("⚠️ Could not find target ID");
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

    debugLog("📊 Attack log collected:", attackLog);

    // Send to API
    await auth.apiCall("battlefield/attack-log", attackLog);
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
    const ranks = {}; // NEW: Track ranks separately
    const now = getKoCServerTimeUTC();

    table.querySelectorAll("tr").forEach(row => {
      const cells = row.querySelectorAll("td");
      if (cells.length < 2) return;

      const label = cells[0].innerText.trim().toLowerCase();
      const value = cells[1].innerText.trim();
      const rankText = cells[2]?.innerText.trim(); // NEW: Extract rank from 3rd column

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

    // Store ranks separately for Stat Hunt feature
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
      await auth.apiCall(`players/${playerId}/mark-inactive`, {
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
    // KoC server runs on US Eastern time - use convertKoCServerTimeToUTC for proper conversion
    // May also be "time ago" format if table was already enhanced - fall back to current time
    function parseTimestamp(text) {
      if (!text) return null;
      const match = text.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
      if (match) {
        // Convert KoC Eastern time to UTC using the shared function
        return convertKoCServerTimeToUTC(match[1]);
      }
      // If it's "time ago" format or unparseable, return null (caller will use current time)
      return null;
    }

    const now = getKoCServerTimeUTC();

    // The Information table is on this same page and carries Race and Rank.
    // Nothing else routinely refreshed them: race was only ever read on a full
    // recon (inteldetail.php), so a player who switched race kept the old one
    // in the roster until somebody spent a recon on them — while every visit
    // to this page had the new race sitting in plain sight. Reading it here
    // means race and rank refresh on the cheapest, most common action there is.
    const info = readStatsInfoTable();
    if (info.race) { stats.race = info.race; stats.raceTime = now; }
    if (info.rank) { stats.rank = info.rank; stats.rankTime = now; }

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
    updatePlayerInfo(playerId, stats);
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
   * name field is exactly what caused the 'Members' corruption incident.
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
        // is 1, which is how every 4-digit rank once showed as #1.
        const digits = value.replace(/[^0-9]/g, '');
        if (digits) out.rank = digits;
      }
    }
    return out;
  }

  // ==================== BASE PAGE COLLECTOR ====================

  function collectFromBasePage() {
    let myId = SafeStorage.get("KoC_MyId", null);
    let myName = SafeStorage.get("KoC_MyName", null);

    // Prefer the name from the native User Info table — it's the ground truth
    // on base.php. Stored auth names have been poisoned by bad login scrapes
    // before (the 'Members' incident) and would then overwrite the real name
    // in the roster on every base.php visit.
    const authData = auth.getStoredAuth();
    const nativeIdentity = findOwnIdentityOnPage();
    if (nativeIdentity) {
      if (authData?.name && authData.name !== nativeIdentity.name) {
        console.warn(`⚠️ Stored auth name "${authData.name}" doesn't match page name "${nativeIdentity.name}" — using page name`);
      }
      myName = nativeIdentity.name;
      myId = nativeIdentity.id;
    } else if (authData && authData.name) {
      myName = authData.name;
    }

    // Only scrape ID from page if we don't have it stored yet
    // (prevents grabbing alliance member links from stats tables)
    if (!myId) {
      // Look for YOUR stats link - it should be in the header/navigation area
      // Try multiple selectors to find the right link
      let myLink = null;

      // Strategy 1: Look for link with text matching authenticated name
      // CRITICAL: Exclude links from script-injected tables (Sweet Revenge panel, Competition panels)
      if (myName) {
        const links = document.querySelectorAll("a[href*='stats.php?id=']");
        for (const link of links) {
          // Skip links inside script-injected content
          const parent = link.closest('[data-koc-injected], .sr-stat-tiv, .sr-stat-strike, .sr-stat-spy, .sr-stat-poison, .sr-stat-theft, .sr-stat-rank, .sr-stat-defense, .sr-stat-sentry, .sr-stat-antidote, .sr-stat-vigilance, .sr-stat-recons, [id^="koc-comp-panel"]');
          if (parent) {
            continue; // Skip links from injected content (no logging - too many!)
          }

          if (link.textContent.trim() === myName) {
            myLink = link;
            debugLog("📊 Found stats link by name match:", myName);
            break;
          }
        }
      }

      // Strategy 2: Look in sidebar menu (safer than first table)
      if (!myLink) {
        const sidebar = document.querySelector("td.menu_cell");
        if (sidebar) {
          myLink = sidebar.querySelector("a[href*='stats.php']");
          if (myLink) {
            debugLog("📊 Found stats link in sidebar");
          }
        }
      }

      // Strategy 3: REMOVED - Don't blindly grab first link (could be from leaderboards!)
      // If we still don't have a link, warn and skip to avoid data corruption
      if (!myLink) {
        console.warn("⚠️ Could not safely find player stats link - skipping ID scraping");
      }

      if (myLink) {
        myId = myLink.href.match(/id=(\d+)/)?.[1] || "self";
        debugLog("📊 Scraped my KoC ID from page:", myId);
      }
    }

    // Save ID and name
    if (myId) {
      SafeStorage.set("KoC_MyId", myId);
    }
    if (myName) {
      SafeStorage.set("KoC_MyName", myName);
    }

    debugLog("📊 Using my KoC ID/Name:", myId, myName);

    let projectedIncome;
    let treasury;
    let economy;
    let xpPerTurn;
    let turnsAvailable;
    let economyLevel;
    let goldPerTurn;
    let technologyLevel;
    let technologyMultiplier;
    let soldiersPerTurn;
    let covertSkill;
    let sentrySkill;
    let toxicInfusionLevel;
    let viperbaneLevel;
    let siegeTechnology;

    // Economy / Treasury block
    const rows = [...document.querySelectorAll("tr")];
    rows.forEach(tr => {
      const txt = tr.innerText.trim();

      if (txt.includes("Projected Income")) {
        const match = txt.match(/([\d,]+)\s+Gold/);
        if (match) projectedIncome = parseInt(match[1].replace(/,/g, ""), 10);
      }

      // Economy: Industrial (9,536,800 gold per turn)
      if (txt.startsWith("Economy")) {
        const levelMatch = txt.match(/Economy\s+([A-Za-z\s]+)\s*\(/);
        const goldMatch = txt.match(/\(?([\d,]+)\s+gold per turn\)?/i);
        if (levelMatch) economyLevel = levelMatch[1].trim();
        if (goldMatch) goldPerTurn = parseInt(goldMatch[1].replace(/,/g, ""), 10);
        // Legacy economy field (just the number)
        if (goldMatch) economy = parseInt(goldMatch[1].replace(/,/g, ""), 10);
      }

      // Technology: Steam Engine (x 6.7)
      if (txt.startsWith("Technology")) {
        const levelMatch = txt.match(/Technology\s+([A-Za-z\s]+)\s*\(/);
        const multMatch = txt.match(/\(x\s*([\d.]+)\)/);
        if (levelMatch) technologyLevel = levelMatch[1].trim();
        if (multMatch) technologyMultiplier = parseFloat(multMatch[1]);
      }

      // Soldier Per Turn: 33 Soldiers
      if (txt.includes("Soldier Per Turn")) {
        const match = txt.match(/([\d,]+)\s+Soldiers/i);
        if (match) soldiersPerTurn = parseInt(match[1].replace(/,/g, ""), 10);
      }

      // Covert Level: George Love (Level 20)
      if (txt.includes("Covert Level")) {
        const match = txt.match(/Level\s+(\d+)/);
        if (match) covertSkill = parseInt(match[1], 10);
      }

      // Sentry Level: UnABooner (Level 20)
      if (txt.includes("Sentry Level")) {
        const match = txt.match(/Level\s+(\d+)/);
        if (match) sentrySkill = parseInt(match[1], 10);
      }

      // Poison Level: Miasmic Venom Concoction (Level 7)
      if (txt.includes("Poison Level")) {
        const match = txt.match(/Level\s+(\d+)/);
        if (match) toxicInfusionLevel = parseInt(match[1], 10);
      }

      // Antidote Level: Venomfang Wardenship (Level 8)
      if (txt.includes("Antidote Level")) {
        const match = txt.match(/Level\s+(\d+)/);
        if (match) viperbaneLevel = parseInt(match[1], 10);
      }

      // Siege: Morgath (x 146.19)
      if (txt.startsWith("Siege")) {
        const match = txt.match(/Siege\s+(.+)/);
        if (match) siegeTechnology = match[1].trim();
      }

      if (txt.includes("Experience Per Turn")) {
        const match = txt.match(/([\d,]+)/);
        if (match) xpPerTurn = parseInt(match[1].replace(/,/g, ""), 10);
      }
    });

    // Military Effectiveness block
    const stats = collectMilitaryStats();

    // Extract real ranks for Stat Hunt (separate from stats)
    const realRanks = stats._realRanks || {};
    delete stats._realRanks; // Don't send _realRanks to players endpoint

    const now = getKoCServerTimeUTC();

    // Full payload for local storage (UI features like recon ??? filling)
    const fullPayload = {
      name: myName,
      projectedIncome,
      treasury,
      economy,
      xpPerTurn,
      turnsAvailable,
      economyLevel,
      goldPerTurn,
      technologyLevel,
      technologyMultiplier,
      soldiersPerTurn,
      covertSkill,
      sentrySkill,
      toxicInfusionLevel,
      viperbaneLevel,
      siegeTechnology,
      ...stats,
      lastSeen: now
    };

    // Save full data locally for UI features (direct to localStorage, skip API)
    const map = getNameMap();
    map[myId] = { ...map[myId], ...sanitizePlayerData(fullPayload) };
    saveNameMap(map);
    debugLog("📊 Base.php self stats captured locally", fullPayload);

    // Send ONLY projectedIncome to API (needed for sidebar banked % calculator)
    const apiPayload = {
      name: myName,
      projectedIncome,
      lastSeen: now
    };

    auth.apiCall("players", { id: myId, ...apiPayload });
    debugLog("📊 Base.php data sent to API", apiPayload);

    // Push real ranks to API (for Stat Hunt feature)
    if (Object.keys(realRanks).length > 0) {
      auth.apiCall(`rankings/real-ranks/${myId}`, { ranks: realRanks });
      debugLog("🎯 Real ranks captured for Stat Hunt:", realRanks);
    }
  }

  // ==================== REWARDS PAGE COLLECTOR (RECONS) ====================

  // POST our current/max recon count to the API so alliance members can see it.
  // No-ops cleanly if not logged in. Errors are swallowed by the caller.
  async function publishReconCount(current, max) {
    const token = await auth.getToken();
    if (!token) return;
    const resp = await fetch(`${API_URL}/player-recons`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
        "X-Script-Name": SCRIPT_NAME,
        "X-Script-Version": SCRIPT_VERSION
      },
      body: JSON.stringify({ current, max })
    });
    if (!resp.ok) {
      throw new Error(`publishReconCount HTTP ${resp.status}`);
    }
  }

  function collectFromRewardsPage() {
    // Extract "Unsuccessful Recons" from "Actions against you" table
    // Page structure: Both /100 and /1000 milestones are in the SAME <tr> but DIFFERENT <td> cells
    // We need to search ALL cells to find the /1000 milestone

    const allCells = [...document.querySelectorAll("td")];

    for (const cell of allCells) {
      const cellText = cell.textContent.trim();

      if (cellText.includes("Unsuccessful Recons")) {
        const match = cellText.match(/(\d+)\/(\d+)/);

        if (match) {
          const current = parseInt(match[1], 10);
          const max = parseInt(match[2], 10);

          // Only process the /1000 milestone (skip /100)
          if (max !== 1000) continue;

          // Only track if player has recons to clear (current < max)
          if (current < max) {
            const remaining = max - current;
            const myId = SafeStorage.get("KoC_MyId", "self");
            const myName = SafeStorage.get("KoC_MyName", "Me");

            const reconData = {
              id: myId,
              name: myName,
              reconsRemaining: remaining,
              current: current,
              max: max,
              lastUpdate: getKoCServerTimeUTC()
            };

            SafeStorage.set(`reconTrack_${myId}`, JSON.stringify(reconData));
            debugLog("📊 Recons to clear captured:", reconData);

            // Publish to API for alliance-wide visibility (best-effort, non-blocking)
            publishReconCount(current, max).catch(err =>
              debugLog("⚠️ Recon publish failed (ignored):", err)
            );
          } else {
            // Player has cleared recons - remove tracking
            const myId = SafeStorage.get("KoC_MyId", "self");
            SafeStorage.remove(`reconTrack_${myId}`);
            debugLog("✅ Recons cleared - removed tracking");

            // Publish the cleared state (current === max) so alliance view stays current
            publishReconCount(current, max).catch(err =>
              debugLog("⚠️ Recon publish (cleared) failed (ignored):", err)
            );
          }

          break;
        }
      }
    }
  }

  // ==================== SWEET REVENGE STATS PANEL ====================

  async function insertTopStatsPanel() {
    const infoRow = document.querySelector("a[href='info.php']")?.closest("tr");
    if (!infoRow) return;

    // Fetch players (API → fallback to cache)
    let players = [];
    try {
      const token = await auth.getToken();
      if (token) {
        // Optimized: Filter by alliance and select only needed fields
        const fields = 'id,name,alliance,tiv,strikeAction,defensiveAction,spyRating,sentryRating,poisonRating,antidoteRating,theftRating,vigilanceRating,rank';
        const resp = await fetch(`${API_URL}/players?alliance=Sweet+Revenge&fields=${fields}`, {
          headers: {
            "Authorization": "Bearer " + token,
            "X-Script-Name": SCRIPT_NAME,
            "X-Script-Version": SCRIPT_VERSION
          }
        });
        if (resp.ok) players = await resp.json();
      }
    } catch (err) {
      console.warn("TopStats API failed, using cache", err);
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

    // Fetch alliance-wide recon counts from the API, with localStorage as fallback.
    // Returns rows in the shape expected by makeRBTable: { id, rank, name, value, rawValue }
    async function getReconTracking() {
      // 1) Try the API for alliance-wide data
      try {
        const token = await auth.getToken();
        if (token) {
          const resp = await fetch(
            `${API_URL}/player-recons?alliance=${encodeURIComponent("Sweet Revenge")}`,
            {
              headers: {
                "Authorization": "Bearer " + token,
                "X-Script-Name": SCRIPT_NAME,
                "X-Script-Version": SCRIPT_VERSION
              }
            }
          );
          if (resp.ok) {
            const list = await resp.json();
            return list.map((p, i) => ({
              id: p.id,
              rank: i + 1, // API already sorts by remaining desc
              name: p.name,
              value: `${p.current}/${p.max}`,
              rawValue: p.remaining
            }));
          }
          debugLog(`⚠️ /player-recons returned ${resp.status} — using localStorage fallback`);
        }
      } catch (err) {
        debugLog("⚠️ Recon fetch failed, using localStorage fallback:", err);
      }

      // 2) Fallback: read this user's own captures from localStorage
      const reconPlayers = [];
      for (const key of Object.keys(localStorage)) {
        if (key.startsWith("reconTrack_")) {
          try {
            const data = JSON.parse(localStorage.getItem(key));
            reconPlayers.push({
              id: data.id,
              rank: 0,
              name: data.name,
              value: `${data.current}/${data.max}`,
              rawValue: data.reconsRemaining
            });
          } catch (err) {
            console.warn("Failed to parse recon data:", key, err);
          }
        }
      }
      reconPlayers.sort((a, b) => b.rawValue - a.rawValue);
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
      { key: "recons", label: "🔍 Recons", id: "recons", custom: true }
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
                <td align="right" style="white-space:nowrap; padding:2px 4px; line-height:1.2;">${escapeHtml(r.value)}</td>
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

    // Header with column toggles (debug mode stays reachable via KoCDebug.toggle() in the console)
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
      // Use custom data source for recons
      const rows = def.custom && def.key === "recons"
        ? reconRows
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

  function displayRankUpCosts(stats, efficiency) {
    // Validate inputs
    if (!stats || Object.keys(stats).length === 0) {
      debugLog('⚠️ displayRankUpCosts: No stats provided');
      return;
    }

    if (!efficiency || Object.keys(efficiency).length === 0) {
      debugLog('⚠️ displayRankUpCosts: No efficiency data provided');
      return;
    }

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

      const currentStat = parseStatValue(stats[mapping.stat]);
      const nextRating = parseInt(nextRatingText.replace(/,/g, ''), 10);
      const efficiencyValue = efficiency[mapping.efficiency];

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
        debugLog(`Available efficiency keys:`, Object.keys(efficiency));
        return;
      }

      const gap = nextRating - currentStat;
      if (gap <= 0) return; // Already past next rank

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

      // Format gold amount
      const formatGold = (gold) => {
        if (gold >= 1e9) return (gold / 1e9).toFixed(1) + 'B';
        if (gold >= 1e6) return (gold / 1e6).toFixed(1) + 'M';
        if (gold >= 1e3) return (gold / 1e3).toFixed(1) + 'K';
        return gold.toFixed(0);
      };

      const goldFormatted = formatGold(goldNeeded);

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
          const formatCount = (count) => {
            if (count >= 1e6) return (count / 1e6).toFixed(1) + 'M';
            if (count >= 1e3) return (count / 1e3).toFixed(1) + 'K';
            return count.toLocaleString();
          };
          weaponCountText = ` (x${formatCount(weaponCount)})`;
        }
      }

      // Create tooltip text
      const tooltipText = `Gold needed for next rank:\n` +
        `Gap: ${gap.toLocaleString()} points\n` +
        `Efficiency: ${efficiencyValue.toFixed(3)} gold/point\n` +
        `Cost: ${gap.toLocaleString()} × ${efficiencyValue.toFixed(3)} = ${goldNeeded.toLocaleString()} gold`;

      // Add cost display to the cell
      const costSpan = document.createElement('span');
      costSpan.style.color = '#4CAF50';
      costSpan.style.fontWeight = 'bold';
      costSpan.style.marginLeft = '8px';
      costSpan.style.cursor = 'help';
      costSpan.textContent = `(${goldFormatted})${weaponCountText}`;
      costSpan.title = tooltipText;

      cells[2].appendChild(costSpan);
      processedCount++;
      debugLog(`✅ ${actionText}: Added cost display (${goldFormatted})`);
    });

    debugLog(`✅ displayRankUpCosts: Processed ${processedCount} rank cost displays`);
  }

  // ==================== RANK NEIGHBOUR RECON LINKS ====================
  // Turns each Previous/Next rating threshold into a hyperlink to the player we
  // believe holds that rank. Clicking → recon → their stats refresh in the DB.
  // Candidates are matched by RATING VALUE (the game's threshold is ground
  // truth), never by the drift-prone DB rank columns, so a wrong candidate
  // rotates out on the next page load — the loop self-corrects toward the true
  // neighbour and curious clickers become a distributed recon workforce.

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

    const resp = await auth.apiCall('rankings/rank-neighbors', { thresholds });
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
      showAutoFillMessage('❌ Cost data not available. Please refresh the page.', 'error');
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
      showAutoFillMessage('❌ Please log in first. Visit your Profile page to authenticate.', 'error');
      return;
    }

    // 3. Get player ID
    const playerId = SafeStorage.get("KoC_MyId", null);
    if (!playerId) {
      showAutoFillMessage('❌ Player ID not found. Please visit your Profile page.', 'error');
      return;
    }

    // 4. Call optimizer API
    const apiUrl = `${API_URL}/api/roster/optimizer/${playerId}?mode=budget&value=${totalPotentialGold}`;
    debugLog(`🌐 Calling optimizer API: ${apiUrl}`);

    try {
      const resp = await fetch(apiUrl, {
        headers: {
          "Authorization": "Bearer " + token,
          "X-Script-Name": SCRIPT_NAME,
          "X-Script-Version": SCRIPT_VERSION
        }
      });

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

  function scrapePurchaseConfirmation() {
    const bodyText = document.body.textContent;

    // Regex: "You Purchased 20 Serpentbane Arbalest, and Gained 1,122,377 Antidote."
    const purchaseRegex = /You Purchased ([\d,]+) (.+?), and Gained ([\d,]+) (\w+)\./gi;
    const matches = [...bodyText.matchAll(purchaseRegex)];

    if (matches.length === 0) return null;

    debugLog(`🛒 Found ${matches.length} purchase(s) on page`);

    // Process each purchase
    const results = [];
    for (const match of matches) {

    const quantity = parseInt(match[1].replace(/,/g, ''), 10);
    const weaponName = match[2].trim();
    const statGained = parseInt(match[3].replace(/,/g, ''), 10);
    const statType = match[4].toLowerCase();

    debugLog('🛒 Purchase detected:', { quantity, weaponName, statGained, statType });

    // Check for zero stat gain (no soldiers to hold weapons)
    if (statGained === 0) {
      showAutoFillMessage(
        `⚠️ No ${statType} increase from ${weaponName} purchase!\n` +
        `You have no soldiers trained to hold these weapons.\n` +
        `→ Visit training page to train more soldiers`,
        'error'
      );
      debugLog(`⚠️ Zero stat gain detected for ${statType} - need to train soldiers`);
      continue; // Skip multiplier calculation for zero gains
    }

    // Get weapon data (use weaponData from calculateWeaponEfficiency)
    const weaponData = {
      'Sarumans Ball': { price: 100, strength: 1 },
      'Heavy Steed': { price: 50000, strength: 100 },
      'Chariot': { price: 450000, strength: 600 },
      'Blackpowder Missile': { price: 1000000, strength: 1000 },
      'Spider': { price: 5000, strength: 10 },
      'Mithril': { price: 50000, strength: 100 },
      'Ebony Platemail': { price: 450000, strength: 600 },
      'Invisibility Shield': { price: 1000000, strength: 1000 },
      'Cloak': { price: 140000, strength: 140 },
      'Grappling Hook': { price: 250000, strength: 250 },
      'Skeleton Key': { price: 600000, strength: 600 },
      'Nunchaku': { price: 1000000, strength: 1000 },
      'Horn': { price: 140000, strength: 140 },
      'Tripwire': { price: 250000, strength: 250 },
      'Guard Dog': { price: 600000, strength: 600 },
      'Lookout Tower': { price: 1000000, strength: 1000 },
      'Toxic Needle Dagger': { price: 140000, strength: 140 },
      'Venomfang Staff': { price: 250000, strength: 250 },
      'Blightbane Bow': { price: 600000, strength: 600 },
      'Plaguebringer Scythe': { price: 1000000, strength: 1000 },
      'Viperfang Dirk': { price: 140000, strength: 140 },
      'Basiliskbane Halberd': { price: 250000, strength: 250 },
      'Wyrmclaw Longsword': { price: 600000, strength: 600 },
      'Serpentbane Arbalest': { price: 1000000, strength: 1000 },
      'Greasy Gloves': { price: 140000, strength: 140 },
      'Rusty Lockpick': { price: 250000, strength: 250 },
      'Shadow Cloak': { price: 600000, strength: 600 },
      'Ethereal Grasp': { price: 1000000, strength: 1000 },
      'Wooden Whistle': { price: 140000, strength: 140 },
      'Steel Shackles': { price: 250000, strength: 250 },
      'Silver Scepter': { price: 600000, strength: 600 },
      'Adamantine Bastion': { price: 1000000, strength: 1000 }
    };

      const weapon = weaponData[weaponName];
      if (!weapon) {
        debugLog('⚠️ Unknown weapon:', weaponName);
        continue;
      }

      // Calculate multiplier: statGained / (quantity × weaponStrength)
      const multiplier = statGained / (quantity * weapon.strength);

      // Map stat type to category
      const statCategoryMap = {
        'strike': 'attack',
        'defense': 'defense',
        'spy': 'spy',
        'sentry': 'sentry',
        'poison': 'poison',
        'antidote': 'antidote',
        'theft': 'theft',
        'vigilance': 'vigilance'
      };

      const category = statCategoryMap[statType];
      if (!category) {
        debugLog('⚠️ Unknown stat type:', statType);
        continue;
      }

      // Check for multiplier changes
      const oldMultiplier = getMultiplier(category);
      const changeType = detectMultiplierChange(category, oldMultiplier, multiplier);

      if (changeType === 'untrained_weapons') {
        showAutoFillMessage(
          `⚠️ ${category} multiplier dropped ${((oldMultiplier - multiplier) / oldMultiplier * 100).toFixed(1)}%\n` +
          `Likely cause: Untrained weapons diluting stats\n` +
          `Old: ${oldMultiplier.toFixed(3)}× → New: ${multiplier.toFixed(3)}×`,
          'error'
        );
      } else if (changeType === 'race_change') {
        showAutoFillMessage(
          `🔄 ${category} multiplier changed ${Math.abs((multiplier - oldMultiplier) / oldMultiplier * 100).toFixed(1)}%\n` +
          `Possible race change detected\n` +
          `Old: ${oldMultiplier.toFixed(3)}× → New: ${multiplier.toFixed(3)}×`,
          'info'
        );
      } else if (changeType === 'new') {
        showAutoFillMessage(
          `✅ Learned ${category} multiplier: ${multiplier.toFixed(3)}×\n` +
          `From purchase: ${quantity} ${weaponName}`,
          'success'
        );
      }

      // Save multiplier
      saveMultiplier(category, multiplier);

      results.push({
        category,
        weaponName,
        quantity,
        statGained,
        multiplier,
        changeType
      });
    }

    return results.length > 0 ? results : null;
  }

  // ==================== ARMORY SELF COLLECTOR ====================

  async function collectTIVAndStatsFromArmory() {
    const myId = SafeStorage.get("KoC_MyId", "self");
    const myName = SafeStorage.get("KoC_MyName", "Me");

    // TIV
    const header = [...document.querySelectorAll("th.subh")]
      .find(th => th.textContent.includes("Total Invested Value"));
    const tivCell = header?.closest("tr").nextElementSibling?.querySelector("td b");
    // null = the box could not be read at all, so say nothing and leave the
    // roster's value alone. 0 = the box really is empty/zero (sabbed flat, or
    // sold out mid-reshuffle), which is data worth recording. The old code
    // collapsed both to 0: an unreadable box wrote a bogus zero to the roster,
    // while a genuine zero was swallowed by the `if (tiv)` guard below.
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
    // (The rank-up display and slider UI are separate registry features now.)
    const efficiency = calculateWeaponEfficiency(weapons, stats);

    const now = getKoCServerTimeUTC();

    // Save to TIV log — a real zero counts (it is the whole point of the
    // timestamped /tiv endpoint that it records what the armory says today).
    if (tiv !== null) {
      const log = getTivLog();
      log.push({ id: myId, tiv, time: now });
      saveTivLog(log);

      // Send TIV to API
      await auth.apiCall("tiv", { playerId: myId, tiv, time: now });
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
      // Gold-per-point efficiency (goldPerAttackPoint, …) — computed above for the rank-up
      // display but PREVIOUSLY NEVER SENT. The server rank optimizer skips any stat whose
      // gold_per_point is null, so without this it returned an empty allocation ("no allocations").
      ...efficiency
    };

    // Save to localStorage (skip updatePlayerInfo to avoid duplicate API call)
    const map = getNameMap();
    map[myId] = { ...map[myId], ...sanitizePlayerData(payload) };
    saveNameMap(map);

    await auth.apiCall("players", { id: myId, ...payload });

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

  // ==================== WEAPON MULTIPLIER SYSTEM ====================

  // Blackheart's verified multipliers - hardcoded defaults
  const DEFAULT_MULTIPLIERS = {
    attack: 2976,    // 0.252 gold/stat (Chariot)
    defense: 2978,   // 0.252 gold/stat (Ebony Platemail)
    spy: 3406,       // 0.294 gold/stat
    sentry: 4257,    // 0.235 gold/stat (+25% race bonus)
    poison: 56,      // 17.86 gold/stat
    antidote: 56,    // 17.86 gold/stat
    theft: 11.6,     // 86.21 gold/stat
    vigilance: 11.6  // 86.21 gold/stat
  };

  function getStoredMultipliers() {
    return SafeStorage.get('KoC_WeaponMultipliers', {});
  }

  function saveMultiplier(category, multiplier) {
    const multipliers = getStoredMultipliers();
    multipliers[category] = {
      value: multiplier,
      timestamp: Date.now()
    };
    SafeStorage.set('KoC_WeaponMultipliers', multipliers);
    debugLog(`💾 Saved multiplier for ${category}: ${multiplier.toFixed(3)}×`);
  }

  function getMultiplier(category) {
    const multipliers = getStoredMultipliers();
    return multipliers[category]?.value || null;
  }

  function detectMultiplierChange(category, oldMultiplier, newMultiplier) {
    if (!oldMultiplier) return 'new';

    const percentChange = Math.abs((newMultiplier - oldMultiplier) / oldMultiplier * 100);

    if (percentChange < 2) return 'normal';
    if (percentChange < 20) return 'untrained_weapons';
    if (percentChange >= 20) return 'race_change';

    return 'unknown';
  }

  // Expose global helper for manual multiplier management
  window.KoCMultipliers = {
    set: (category, multiplier) => {
      saveMultiplier(category, multiplier);
      console.log(`✅ Set ${category} multiplier to ${multiplier.toFixed(3)}×`);
    },
    get: (category) => {
      const mult = getMultiplier(category);
      if (mult) {
        console.log(`${category}: ${mult.toFixed(3)}×`);
      } else {
        console.log(`⚠️ No multiplier set for ${category}`);
      }
      return mult;
    },
    getAll: () => {
      const multipliers = getStoredMultipliers();
      console.table(Object.entries(multipliers).map(([cat, data]) => ({
        Category: cat,
        Multiplier: data.value.toFixed(3) + '×',
        'Set Date': new Date(data.timestamp).toLocaleString()
      })));
      return multipliers;
    },
    clear: (category) => {
      const multipliers = getStoredMultipliers();
      if (category) {
        delete multipliers[category];
        console.log(`🗑️ Cleared ${category} multiplier`);
      } else {
        SafeStorage.remove('KoC_WeaponMultipliers');
        console.log(`🗑️ Cleared all multipliers`);
        return;
      }
      SafeStorage.set('KoC_WeaponMultipliers', multipliers);
    },
    // Blackheart's verified multipliers - use as starting point
    setBlackheartDefaults: () => {
      for (const [category, multiplier] of Object.entries(DEFAULT_MULTIPLIERS)) {
        saveMultiplier(category, multiplier);
      }
      console.log('✅ Set Blackheart\'s verified multipliers for all categories');
      console.log('⚠️  Note: Your multipliers may differ based on research, officers, and race!');
      console.table(Object.entries(DEFAULT_MULTIPLIERS).map(([cat, mult]) => ({
        Category: cat,
        Multiplier: mult.toFixed(3) + '×'
      })));
    }
  };

  // Only show multiplier commands on armory page
  if (location.pathname.includes('armory.php')) {
    console.log('💡 KoC Multipliers Commands:');
    console.log('   KoCMultipliers.set(category, value)     - Set a multiplier');
    console.log('   KoCMultipliers.setBlackheartDefaults()  - Use Blackheart\'s values (for reference only)');
    console.log('   KoCMultipliers.get(category)            - Get a multiplier');
    console.log('   KoCMultipliers.getAll()                 - View all multipliers');
    console.log('   KoCMultipliers.clear([category])        - Clear multipliers');
    console.log('   ⚠️  Multipliers auto-learn from weapon purchases! Buy weapons to populate.');
  }

  function calculateWeaponEfficiency(weapons, stats) {
    // New formula using multipliers learned from actual purchases:
    // goldPerStat = weaponPrice / (weaponStrength × multiplier)

    const weaponData = {
      // Attack weapons
      'Sarumans Ball': { price: 100, strength: 1 },
      'Heavy Steed': { price: 50000, strength: 100 },
      'Chariot': { price: 450000, strength: 600 },
      'Blackpowder Missile': { price: 1000000, strength: 1000 },

      // Defense weapons
      'Spider': { price: 5000, strength: 10 },
      'Mithril': { price: 50000, strength: 100 },
      'Ebony Platemail': { price: 450000, strength: 600 },
      'Invisibility Shield': { price: 1000000, strength: 1000 },

      // Spy Tools
      'Cloak': { price: 140000, strength: 140 },
      'Grappling Hook': { price: 250000, strength: 250 },
      'Skeleton Key': { price: 600000, strength: 600 },
      'Nunchaku': { price: 1000000, strength: 1000 },

      // Sentry Tools
      'Horn': { price: 140000, strength: 140 },
      'Tripwire': { price: 250000, strength: 250 },
      'Guard Dog': { price: 600000, strength: 600 },
      'Lookout Tower': { price: 1000000, strength: 1000 },

      // Poison Tools
      'Toxic Needle Dagger': { price: 140000, strength: 140 },
      'Venomfang Staff': { price: 250000, strength: 250 },
      'Blightbane Bow': { price: 600000, strength: 600 },
      'Plaguebringer Scythe': { price: 1000000, strength: 1000 },

      // Antidote Tools
      'Viperfang Dirk': { price: 140000, strength: 140 },
      'Basiliskbane Halberd': { price: 250000, strength: 250 },
      'Wyrmclaw Longsword': { price: 600000, strength: 600 },
      'Serpentbane Arbalest': { price: 1000000, strength: 1000 },

      // Theft Tools
      'Greasy Gloves': { price: 140000, strength: 140 },
      'Rusty Lockpick': { price: 250000, strength: 250 },
      'Shadow Cloak': { price: 600000, strength: 600 },
      'Ethereal Grasp': { price: 1000000, strength: 1000 },

      // Vigilance Tools
      'Wooden Whistle': { price: 140000, strength: 140 },
      'Steel Shackles': { price: 250000, strength: 250 },
      'Silver Scepter': { price: 600000, strength: 600 },
      'Adamantine Bastion': { price: 1000000, strength: 1000 }
    };

    const storedMultipliers = getStoredMultipliers();
    const efficiency = {};

    // Get multiplier for each category
    const categories = ['attack', 'defense', 'spy', 'sentry', 'poison', 'antidote', 'theft', 'vigilance'];

    for (const category of categories) {
      const multiplierData = storedMultipliers[category];

      // ONLY use stored multipliers - no fallback to defaults
      if (!multiplierData || !multiplierData.value) {
        debugLog(`⚠️ ${category}: No multiplier learned yet - buy weapons to auto-detect!`);
        continue; // Skip this category if no multiplier
      }

      const multiplier = multiplierData.value;
      debugLog(`📊 ${category}: Using learned multiplier ${multiplier.toFixed(3)}×`);

      // Find the most efficient HIGH-TIER weapon for this category
      // We only consider top 2 tiers (the expensive ones that high-level players buy)
      const highTierWeapons = {
        attack: ['Chariot', 'Blackpowder Missile'],
        defense: ['Ebony Platemail', 'Invisibility Shield'],
        spy: ['Skeleton Key', 'Nunchaku'],
        sentry: ['Guard Dog', 'Lookout Tower'],
        poison: ['Blightbane Bow', 'Plaguebringer Scythe'],
        antidote: ['Wyrmclaw Longsword', 'Serpentbane Arbalest'],
        theft: ['Shadow Cloak', 'Ethereal Grasp'],
        vigilance: ['Silver Scepter', 'Adamantine Bastion']
      };

      let bestGoldPerStat = Infinity;
      let bestWeaponName = null;

      // Check only high-tier weapons for this category
      const weaponsToCheck = highTierWeapons[category];
      if (!weaponsToCheck) {
        debugLog(`⚠️ No high-tier weapons defined for ${category}`);
        continue;
      }

      for (const weaponName of weaponsToCheck) {
        const weapon = weaponData[weaponName];
        if (!weapon) {
          debugLog(`⚠️ Weapon data not found for ${weaponName}`);
          continue;
        }

        // Calculate goldPerStat for this weapon
        const goldPerStat = weapon.price / (weapon.strength * multiplier);

        if (goldPerStat < bestGoldPerStat) {
          bestGoldPerStat = goldPerStat;
          bestWeaponName = weaponName;
        }
      }

      if (bestWeaponName) {
        // Store efficiency with the proper key format
        const efficiencyKey = `goldPer${category.charAt(0).toUpperCase() + category.slice(1)}Point`;
        efficiency[efficiencyKey] = Math.round(bestGoldPerStat * 1000) / 1000;

        debugLog(`💰 ${category}: Best weapon = ${bestWeaponName}, Gold per stat = ${bestGoldPerStat.toFixed(3)}, Multiplier = ${multiplier.toFixed(3)}×`);
      }
    }

    debugLog('💰 Weapon efficiency calculated:', efficiency);
    return efficiency;
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
          // prints a single number e.g. "1,000". Parse BOTH — the old slash-only regex
          // read covert strength as 0, collapsing covert TIV/distribution to 0 (which
          // zeroed the safe.php "Attacked Instead" table and under-reported covert TIV to the API).
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

          // No longer need totalStrength - we calculate it from quantity × strength
          const totalStrength = quantity * maxStrength;

          if (weaponName && quantity > 0) {
            weapons.push({
              name: weaponName,
              category: category,
              quantity: quantity,
              minStrength: minStrength,
              maxStrength: maxStrength,
              totalStrength: totalStrength,  // Use game's pre-calculated total
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
  // Era 23 race bonuses that touch armory stats (Humans' 15% Hostage isn't one).
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
                    bankFindInnermostTable('Trained Attack Soldiers');
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
    // Same live-tested funds regexes as Banking Mode (read-only, no side effects)
    const bodyText = document.body.textContent;
    const funds = num(bodyText.match(/Available\s+Funds:\s*([\d,]+)\s*Gold/i)?.[1]);
    const vault = num(bodyText.match(/Vault\s+Gold:\s*([\d,]+)\s*Gold/i)?.[1]);
    const caps = reshufUnitCaps();
    const mults = getStoredMultipliers();

    const cats = {};
    for (const cat of RESHUF_CATS) {
      const rows = weapons.filter(w => w.category === cat).map(w => ({
        name: w.name, qty: w.quantity, cur: w.minStrength || 0, max: w.maxStrength || 0,
        sell: reshufPerUnitSell(w)
      }));
      rows.sort((a, b) => b.cur - a.cur); // carriers grab the strongest first
      const capacity = caps ? caps[cat] : null;
      const heldNow = reshufHeldStrength(rows.map(r => ({ qty: r.qty, str: r.cur })), capacity);
      const learned = (mults[cat] && mults[cat].value) ? mults[cat].value : null;
      // Fallback multiplier: what the page shows right now (rating per held strength).
      const derived = (!learned && heldNow > 0 && ratings[cat] > 0) ? ratings[cat] / heldNow : null;
      cats[cat] = {
        rows, capacity, heldNow, rating: ratings[cat],
        mult: learned !== null ? learned : derived,
        multSource: learned !== null ? 'learned' : (derived !== null ? 'derived' : null),
        multTs: (learned !== null && mults[cat].timestamp) ? mults[cat].timestamp : null
      };
    }
    return { cats, tiv, funds, vault, capsKnown: caps !== null };
  }

  // Learned multipliers go quietly stale: every skill/tech upgrade multiplies
  // the rating, but the stored value only refreshes on a purchase — so an old
  // one under-counts what your weapons contribute and leaves phantom rating
  // behind on sell-all scenarios. The page itself implies rating/heldNow
  // (a hair HIGH — it includes the tiny unarmed-unit base, ~0.1% on live
  // data), so a learned value well below it predates upgrades. Fresh mults
  // sit at ~1.0× implied; real stale cases measured 0.23–0.86× (2026-08-30).
  function reshufStaleCheck(c) {
    if (c.multSource !== 'learned' || !(c.heldNow > 0) || !(c.rating > 0)) return null;
    const implied = c.rating / c.heldNow;
    return c.mult < implied * 0.9 ? { learned: c.mult, implied } : null;
  }

  // Parse a goal target: plain digits, commas/spaces, or K/M/B/T shorthand
  // ("4,784,687,574,927", "4.78T", "500b"). Returns null when unreadable.
  function reshufParseTarget(s) {
    if (!s) return null;
    const m = String(s).trim().replace(/[,\s]/g, '').match(/^([\d.]+)([kmbt])?$/i);
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
    const mapRace = (getNameMap()[SafeStorage.get('KoC_MyId', 'self')] || {}).race || null;
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
      '<div style="padding:8px 12px;color:#8b94a7;font-size:11px;border-bottom:1px solid #262c37;">Every sale returns <b>50%</b> of a weapon\'s value (and lands in your Vault), so a full rework costs half of what you liquidate. Projections use the weapon multipliers learned from your own purchases.</div>' +
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
        html += '<span style="color:#e6b450;">Projected ' + L + ' is unknown (no multiplier learned) — buy 1 ' + L.toLowerCase() + ' item once to calibrate.</span>';
      } else {
        html += '<span style="color:#8b94a7;">Projected ' + L + ' after this plan:</span> <b>' + fmt(g.projected) + '</b> &nbsp;·&nbsp; <span style="color:#8b94a7;">goal:</span> <b>' + fmt(target) + '</b><br>';
        if (g.reached) {
          html += '<span style="color:#5fcf7a;">✅ Goal reached — ' + fmt(g.surplus) + ' over the target.</span>';
        } else if (g.noMult) {
          html += '<span style="color:#e6b450;">Gap ' + fmt(g.gap) + ', but no ' + L + ' multiplier is known — buy 1 item once to calibrate.</span>';
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
          const age = c.multTs ? Math.max(0, Math.round((Date.now() - c.multTs) / 86400000)) : null;
          notes.push('<span style="color:#e6b450;">⚠ stale multiplier — learned ×' + staleInfo.learned.toFixed(1) +
            (age !== null ? ' (' + (age === 0 ? 'today' : age + 'd old') + ')' : '') +
            ' but the page implies ×' + staleInfo.implied.toFixed(1) + '; buy 1 to recalibrate</span>');
        }
        if (r.bought > 0) notes.push(fmt(r.bought) + ' × ' + h(r.weapon));
        if (r.unheld > 0) notes.push('<span style="color:#e6b450;">⚠ ' + fmt(r.unheld) + ' unheld (only ' + fmt(c.capacity) + ' ' + h(RESHUF_UNIT_LABEL[cat]) + ')</span>');
        if (c.multSource === 'derived' && r.changed) notes.push('<span style="color:#8b94a7;">est. multiplier</span>');
        if (c.mult === null && after === null) notes.push('<span style="color:#e6b450;">no multiplier — buy 1 ' + h(RESHUF_LABELS[cat].toLowerCase()) + ' item once to calibrate</span>');
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
      if (staleCats.length) warn.push('⚠ Stale multiplier' + (staleCats.length > 1 ? 's' : '') + ': ' +
        staleCats.map(cat => RESHUF_LABELS[cat]).join(', ') +
        ' — buy 1 weapon/tool in each and reload before trusting these projections.');
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

      // Fallback: the old native-styled button under the Total Invested Value box
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
   * Works alongside standalone KoC-SlayingComp.user.js script
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

  // Helper function to extract sidebar values
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
    const comps = await auth.apiCall("competitions/active");
    if (!comps || (Array.isArray(comps) && comps.length === 0)) {
      debugLog("ℹ️ No active competitions");
      return false;
    }

    // Handle both single object (old API) and array (new API) responses
    activeCompetitions = Array.isArray(comps) ? comps : [comps];

    // Clear old competition data from localStorage
    const activeIds = activeCompetitions.map(c => c.id);
    clearOldCompData(activeIds);

    // Load entries for each competition
    for (const comp of activeCompetitions) {
      const entry = await auth.apiCall(`competitions/${comp.id}/my-entry`);
      if (entry) {
        myCompEntries.set(comp.id, entry);
      }
    }

    return activeCompetitions.length > 0;
  }

  // Team management
  async function joinCompTeam(competitionId, teamId) {
    const result = await auth.apiCall(`competitions/${competitionId}/join-team`, "POST", { team_id: teamId });
    if (result) {
      myCompEntries.set(competitionId, result);
      return true;
    }
    return false;
  }

  async function getAvailableCompTeams(competitionId) {
    return await auth.apiCall(`competitions/${competitionId}/teams`);
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

  async function submitAllCompStats() {
    // Submit stats for all active competitions
    for (const comp of activeCompetitions) {
      await submitCompStats(comp);
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
        `competitions/${competition.id}/toggle`,
        "POST",
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
      leaderboard = await auth.apiCall(endpoint);

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
              ${entry.team_name || 'Unknown'}${currentMedal}
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
              👥 Team: <strong>${myEntry.team_name}</strong>
            </div>
          </div>
        `;
      } else {
        teamDisplay = `
          <div style="margin-top:8px; padding:6px; background:#2a2a2a; border-radius:4px;">
            <div style="font-size:10px; color:#f90; margin-bottom:4px;">
              ⚠️ No team selected
            </div>
            <button class="comp-select-team-btn" data-comp-id="${competition.id}" style="padding:4px 8px; cursor:pointer; background:#2196F3; color:white; border:none; border-radius:4px; font-size:10px;">
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
          🏆 ${competition.name}
        </div>
        <button class="comp-minimize-btn" data-comp-id="${competition.id}" style="padding:2px 8px; cursor:pointer; background:#555; color:white; border:none; border-radius:3px; font-size:10px;">
          ▲ Hide
        </button>
      </div>
      <div style="color:#999; font-size:11px; margin-bottom:8px;">
        ${statusText}
        ${scoringDisplay}
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

          const isDST = isEasternDST(year, month, day);
          const offset = isDST ? 4 : 5;
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
      // Skip our own Data Centre link
      if (a.href.includes('id=datacentre')) continue;
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
      await auth.apiCall(`players/${id}/mark-inactive`, {
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
    updatePlayerInfo(id, stats);
    debugLog(`📊 Fresh recon collected for ${id}: ${statCount} combat stats`);

    // Fill any ??? values with last known data from API
    await fillMilitaryStatsFromAPI(id);
  }

  // Fill ??? values in Military Stats table with last known data from API
  async function fillMilitaryStatsFromAPI(playerId) {
    try {
      // Fetch player data from API
      const playerData = await auth.apiCall(`players/${playerId}`);
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
      const playerData = await auth.apiCall(`players/${playerId}`);
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

  // ==================== DATA CENTRE REDIRECT ====================

  async function handleDataCentreRedirect() {
    if (!location.search.includes("id=datacentre")) {
      return false; // Not a redirect request
    }

    debugLog("[DataCentre] Redirecting to React app...");

    const authData = auth.getAuthForRedirect();
    debugLog("[DataCentre] Auth data:", authData ? "✅ Available" : "❌ Not available");

    if (authData) {
      debugLog("[DataCentre] Valid auth found, using URL parameter method");

      // Encode auth data as base64 for URL
      const authEncoded = btoa(JSON.stringify(authData));
      const redirectUrl = `https://koc-roster-client-production.up.railway.app?auth=${authEncoded}`;

      debugLog("[DataCentre] Redirecting with auth in URL");
      window.location.href = redirectUrl;
    } else {
      debugLog("[DataCentre] No valid auth found, redirecting without token");
      window.location.href = "https://koc-roster-client-production.up.railway.app";
    }

    return true; // Redirect was handled
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

    // Get learned multipliers
    const multipliers = getStoredMultipliers();
    const hasMultipliers = Object.keys(multipliers).length > 0;

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
            Visit <a href="armory.php" style="color: #66ccff;">Armory</a> and buy weapons to calibrate multipliers
          </td>
        </tr>
      `;
      techStatsTable.parentNode.insertBefore(warningTable, techStatsTable.nextSibling);
      debugLog('[SafePage] No multipliers learned - showing warning');
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

    // Strength of each best weapon above (parallels bestWeaponPrices). The learned
    // multiplier is stat per (quantity × strength) — see saveMultiplier — so the
    // projected gain MUST include the weapon's strength. Omitting it made every
    // gain come out 600× (attack/defense) to 1000× (covert) too small.
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
      // Stored (learned) multipliers only — matches calculateWeaponEfficiency's
      // convention (no fallback to DEFAULT_MULTIPLIERS); an uncalibrated stat stays 0.
      const multiplier = multipliers[cat]?.value || 0;
      const weaponPrice = bestWeaponPrices[cat];
      const weaponStrength = bestWeaponStrength[cat] || 1;

      // weapons bought = goldForStat / weaponPrice; each weapon adds (strength × multiplier)
      // stat, since multiplier is stat per (qty × strength). The strength factor was missing.
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

  // ==================== GOLD UPGRADES: READINESS + TIME (upgrades.php) ====================

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

      // Row 1: can we afford it from gold we actually hold? Full-armory-sell is excluded —
      // selling your whole armory to upgrade isn't realistic. The shortfall is what you'd make
      // up by selling some weapons or slaying (shown as a slay estimate from your avg gold/atk).
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

  // ==================== BANKING MODE (inline armory enhancement) ====================
  // Display-only gold projection + attack-risk colour bands, inserted INTO the live
  // Armory page (above the "Available Funds:" banner). Ported from the standalone
  // koc-banking-mode.user.js v0.2.2 — the kiosk shell is dropped; the game page is
  // never reparented, hidden, or touched. We only INSERT widgets and OBSERVE forms.
  //
  // HARD CONSTRAINTS honoured throughout:
  //  - The 1s ticker is DISPLAY-ONLY: it repaints numbers already known locally.
  //    No fetch/XHR, no navigation, no game action ever fires from any timer.
  //  - ZERO synthetic events on game elements. The buy/repair forms are OBSERVED
  //    with passive listeners only — never .click()/.submit()/dispatchEvent.
  //  - Notifications (off by default) carry {body, tag} ONLY — never an icon: URL
  //    (a remote icon would make the display timer fire a network request).
  //  - All persistence via SafeStorage under the KoC_Banking_ key namespace.
  //  - TIMEKEEPING: LOCAL clock (new Date()) for every "now" stamp; the existing
  //    convertKoCServerTimeToUTC() (Eastern→UTC) is used ONLY for genuine past
  //    event times scraped from attack-log rows. "now" is never inferred from the
  //    first datetime on the page (on attacklog.php that is a stale attack time).

  const BANK_PREFIX = 'KoC_Banking_';

  // Era 23 verified defaults — every one is editable in the inline Settings panel
  // and none is hardcoded into the maths.
  const BANK_DEFAULT_SETTINGS = {
    // Steal rate is a RANGE (TFF-relative: 0.75–1.0). v1 risk maths divides stolen
    // gold by the MAX (1.0 conservative bound) so held-gold estimates are lower
    // bounds and risk bands trip earlier, never later.
    stealRateMin: 0.75,
    stealRateMax: 1.00,
    // TBG fallback (gold/unit/turn, 1 turn = 1 minute). Regulars 2.3, coverts 0.92,
    // mercs 0 (excluded). Only used when no scraped Projected Income is calibrated.
    tbgRegular: 2.3,
    tbgCovert: 0.92,
    // Quadratic growth term: new production arrives untrained → 2.3 gold/turn.
    growthGoldPerSoldier: 2.3,
    // Risk model
    riskWindowDays: 7,
    yellowPercentile: 25,
    redPercentile: 50,
    // Used until at least 3 steal events exist in the window
    fallbackYellowGold: 50000000,
    fallbackRedGold: 150000000,
    // Notifications — OFF by default per integration spec; no-icon notifications only
    notifyEnabled: false,
    notifyMinGapMins: 10,
    // Show the yellow/red countdown on the box itself (off by default so the box matches the native funds box)
    showTimes: false,
    // Calibration older than this is flagged stale in the widget
    staleCalibrationMins: 1440
  };

  // --- namespaced persistence (delegates to SafeStorage; KoC_Banking_ prefix) ---
  function bankGet(key, def = null) { return SafeStorage.get(BANK_PREFIX + key, def); }
  function bankSet(key, val) { return SafeStorage.set(BANK_PREFIX + key, val); }
  function bankRemove(key) { return SafeStorage.remove(BANK_PREFIX + key); }

  // --- self-contained utilities (bank-prefixed to avoid collisions) ---
  function bankCleanNumber(str) {
    if (str === null || str === undefined || str === '???' || str === 'Unknown') return null;
    const cleaned = String(str).replace(/,/g, '').replace(/[^\d]/g, '');
    const num = parseInt(cleaned, 10);
    return isNaN(num) ? null : num;
  }

  function bankFormatGold(n) {
    if (n === null || n === undefined || isNaN(n)) return '???';
    const abs = Math.abs(n);
    if (abs >= 1e12) return (n / 1e12).toFixed(2) + 'T';
    if (abs >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (abs >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (abs >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return String(Math.round(n));
  }

  function bankFormatMinutes(min) {
    if (min === null || min === undefined || !isFinite(min)) return '—';
    if (min <= 0) return 'now';
    const m = Math.round(min);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ${m % 60}m`;
    return `${Math.floor(h / 24)}d ${h % 24}h`;
  }

  function bankFormatTimeAgo(timestamp) {
    if (!timestamp) return '';
    const d = new Date(timestamp);
    if (isNaN(d)) return '';
    const sec = Math.floor((Date.now() - d.getTime()) / 1000);
    if (sec < 0) return 'just now';
    if (sec < 60) return `${sec}s ago`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    const remMin = min % 60;
    if (hr < 24) return remMin > 0 ? `${hr}h ${remMin}m ago` : `${hr}h ago`;
    return `${Math.floor(hr / 24)}d ago`;
  }

  // Percentile of a SORTED ascending numeric array (linear interpolation)
  function bankPercentile(sorted, p) {
    if (!sorted.length) return null;
    if (sorted.length === 1) return sorted[0];
    const idx = (p / 100) * (sorted.length - 1);
    const lo = Math.floor(idx);
    const hi = Math.ceil(idx);
    if (lo === hi) return sorted[lo];
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  }

  function bankFindInnermostTable(marker) {
    const matches = [...document.querySelectorAll('table')]
      .filter(t => t.textContent.includes(marker));
    return matches.length ? matches[matches.length - 1] : null;
  }

  function bankFindRowByLabel(table, labelRegex) {
    if (!table) return null;
    return [...table.rows].find(r => r.cells[0] && labelRegex.test(r.cells[0].textContent.trim()));
  }

  // --- settings ---
  function bankGetSettings() { return { ...BANK_DEFAULT_SETTINGS, ...bankGet('settings', {}) }; }
  function bankSaveSettings(partial) {
    const merged = { ...bankGet('settings', {}), ...partial };
    bankSet('settings', merged);
    debugLog('💾 Banking settings saved:', partial);
    return merged;
  }

  // ==================== OWN-STATE CALIBRATION ====================
  // base.php recalibrates G0/income/SPM; armory + sidebar refresh G0 (and vault).
  // All scrapes are passive reads of the already-loaded page — no requests.

  // Save a fresh available-funds reading. Vault is stored alongside but NEVER
  // counted toward exposed gold — only available funds are stealable (era 23).
  function bankSaveGoldReading(gold, vault, source) {
    if (gold === null || gold === undefined) return;
    const prevVault = bankGet('gold_reading', {}).vault;
    const reading = {
      gold: gold,
      vault: (vault === null || vault === undefined) ? (prevVault === undefined ? null : prevVault) : vault,
      ts: new Date().toISOString(),   // LOCAL clock — keeps dt-arithmetic self-consistent
      source: source
    };
    bankSet('gold_reading', reading);
    debugLog(`💰 Banking gold reading: ${gold.toLocaleString()} available (vault ${reading.vault === null ? '?' : reading.vault.toLocaleString()}) from ${source}`);
  }

  // Sidebar money cells (present on every page with the left menu):
  // td[align=center] whose trimmed text starts "Gold:"/"Vault:" → its <b> amount.
  function bankCollectSidebarGold() {
    try {
      let gold = null, vault = null;
      [...document.querySelectorAll('td[align="center"]')].forEach(td => {
        const label = td.textContent.trim();
        if (label.length > 80) return;
        const amountEl = td.querySelector('b');
        if (!amountEl) return;
        if (/^Gold:/.test(label)) gold = bankCleanNumber(amountEl.textContent);
        else if (/^Vault:/.test(label)) vault = bankCleanNumber(amountEl.textContent);
      });
      if (gold !== null) bankSaveGoldReading(gold, vault, 'sidebar');
      return gold;
    } catch (err) {
      debugLog('⚠️ Banking sidebar gold scrape failed:', err);
      return null;
    }
  }

  // Personnel table (base.php AND armory.php: table.table_lines.personnel).
  // regulars exclude mercenaries (0 TBG); coverts are the six covert unit types.
  function bankCollectPersonnel() {
    try {
      const table = document.querySelector('table.table_lines.personnel') ||
                    bankFindInnermostTable('Trained Attack Soldiers');
      if (!table) return null;

      const counts = {};
      [...table.rows].forEach(row => {
        if (row.cells.length < 2) return;
        const label = row.cells[0].textContent.trim();
        const val = bankCleanNumber(row.cells[1].textContent);
        if (val !== null) counts[label] = val;
      });

      const regulars = (counts['Trained Attack Soldiers'] || 0) +
                       (counts['Trained Defense Soldiers'] || 0) +
                       (counts['Untrained Soldiers'] || 0);
      const coverts = (counts['Spies'] || 0) +
                      (counts['Sentries'] || 0) +
                      (counts['Venomweavers'] || 0) +
                      (counts['Serpentwardens'] || 0) +
                      (counts['Thieves'] || 0) +
                      (counts['Rangers'] || 0);

      if (regulars === 0 && coverts === 0) return null;
      return { regulars, coverts };
    } catch (err) {
      debugLog('⚠️ Banking personnel scrape failed:', err);
      return null;
    }
  }

  // Calibrate from the Command Centre (base.php) — reuses the same overview rows
  // the main script already reads ("Projected Income", "Soldier Per Turn").
  function bankCollectCommandCentre() {
    try {
      const mo = bankFindInnermostTable('Projected Income');
      if (!mo) {
        debugLog('⚠️ Banking: Military Overview table not found on base.php');
        return null;
      }

      // Available funds (exposed gold — this is G0)
      let gold = null;
      const fundsRow = bankFindRowByLabel(mo, /^Available Funds/);
      if (fundsRow && fundsRow.cells[1]) {
        gold = bankCleanNumber(fundsRow.cells[1].textContent.match(/([\d,]+)\s+Gold/i)?.[1]);
      }

      // Projected income (gold/turn = gold/min) — already includes economy, tech
      // and era bonuses, so it is preferred over the troop-count fallback.
      let goldPerMin = null;
      const projRow = bankFindRowByLabel(mo, /^Projected Income/);
      if (projRow && projRow.cells[1]) {
        goldPerMin = bankCleanNumber(projRow.cells[1].textContent.match(/([\d,]+)\s+Gold\s+\(in 1 min\)/i)?.[1]);
      }

      // Soldiers per turn (= per minute) for the quadratic growth term
      let spm = null;
      const sptRow = bankFindRowByLabel(mo, /^Soldier Per Turn/);
      if (sptRow && sptRow.cells[1]) {
        spm = bankCleanNumber(sptRow.cells[1].textContent.match(/([\d,]+)\s+Soldiers/i)?.[1]);
      }

      const personnel = bankCollectPersonnel();
      const cal = {
        goldPerMin: goldPerMin,
        spm: spm,
        regulars: personnel ? personnel.regulars : null,
        coverts: personnel ? personnel.coverts : null,
        ts: new Date().toISOString(),
        source: 'base.php'
      };
      bankSet('calibration', cal);
      if (gold !== null) bankSaveGoldReading(gold, null, 'base.php');

      debugLog(`✅ Banking calibrated: income ${goldPerMin === null ? '?' : goldPerMin.toLocaleString()}/min, SPM ${spm === null ? '?' : spm}, G0 ${gold === null ? '?' : gold.toLocaleString()}`);
      return cal;
    } catch (err) {
      debugLog('⚠️ Banking calibration failed:', err);
      return null;
    }
  }

  // Read own state from the Armory page (funds banner + vault + personnel).
  // Reuses the proven body-text regexes ("Available Funds:" / "Vault Gold:").
  function bankCollectArmoryState() {
    try {
      const bodyText = document.body.textContent;
      // \s*Gold (not \s+) — textContent can concatenate adjacent cells without a
      // space; this is the live-tested form from the verified selectors table.
      const fundsMatch = bodyText.match(/Available\s+Funds:\s*([\d,]+)\s*Gold/i);
      const vaultMatch = bodyText.match(/Vault\s+Gold:\s*([\d,]+)\s*Gold/i);
      const gold = fundsMatch ? bankCleanNumber(fundsMatch[1]) : null;
      const vault = vaultMatch ? bankCleanNumber(vaultMatch[1]) : null;

      if (gold !== null) bankSaveGoldReading(gold, vault, 'armory.php');

      // Refresh personnel (fallback income inputs) without clobbering the scraped
      // goldPerMin/spm from the last base.php calibration.
      const personnel = bankCollectPersonnel();
      if (personnel) {
        const cal = bankGet('calibration', {});
        cal.regulars = personnel.regulars;
        cal.coverts = personnel.coverts;
        if (!cal.ts) cal.ts = new Date().toISOString();
        bankSet('calibration', cal);
      }
      return gold;
    } catch (err) {
      debugLog('⚠️ Banking armory state read failed:', err);
      return null;
    }
  }

  // ==================== GOLD PROJECTION MODEL ====================
  // gold(t) = G0 + S0·g·t + 0.5·g·spm·t²   (1 game turn = 1 minute; vault excluded)
  //   G0   = available funds at last reading
  //   S0·g = gold/min — PREFERRED scraped "Projected Income (in 1 min)";
  //          FALLBACK tbgRegular·regulars + tbgCovert·coverts (mercs excluded)
  //   g    = growthGoldPerSoldier (new production arrives untrained)
  //   spm  = "Soldier Per Turn"

  function bankFallbackIncome(cal, settings) {
    if (!cal || cal.regulars === null || cal.regulars === undefined) return null;
    return settings.tbgRegular * cal.regulars + settings.tbgCovert * (cal.coverts || 0);
  }

  function bankGetProjection(nowMs = Date.now()) {
    const reading = bankGet('gold_reading', null);
    if (!reading) return null;

    const settings = bankGetSettings();
    const cal = bankGet('calibration', null);
    const dtMin = Math.max(0, (nowMs - new Date(reading.ts).getTime()) / 60000);
    const calAgeMin = (cal && cal.ts)
      ? Math.max(0, (nowMs - new Date(cal.ts).getTime()) / 60000)
      : Infinity;

    let goldPerMin = cal && cal.goldPerMin !== null && cal.goldPerMin !== undefined
      ? cal.goldPerMin
      : bankFallbackIncome(cal, settings);
    const spm = cal && cal.spm ? cal.spm : 0;

    // The scraped rate is as old as the calibration; production has been adding
    // soldiers since. Age the linear term forward to the gold-reading time so the
    // projection starts from a current income rate.
    if (goldPerMin !== null && cal && cal.ts && spm) {
      const rateAgeMin = Math.max(0, (new Date(reading.ts).getTime() - new Date(cal.ts).getTime()) / 60000);
      goldPerMin += settings.growthGoldPerSoldier * spm * rateAgeMin;
    }

    let gold;
    if (goldPerMin === null) {
      gold = reading.gold; // no income data — show the raw last reading
    } else {
      gold = reading.gold +
             goldPerMin * dtMin +
             0.5 * settings.growthGoldPerSoldier * spm * dtMin * dtMin;
    }

    return {
      gold: Math.round(gold),
      dtMin: dtMin,
      calAgeMin: calAgeMin,
      goldPerMin: goldPerMin,
      spm: spm,
      stale: goldPerMin !== null && calAgeMin > settings.staleCalibrationMins,
      noIncome: goldPerMin === null,
      reading: reading,
      cal: cal
    };
  }

  // Minutes from now until projected gold reaches targetGold. Solves the quadratic
  //   0.5·g·spm·t² + goldPerMin·t + (gNow − target) = 0
  function bankMinutesToGold(targetGold, proj) {
    if (!proj || proj.noIncome) return null;
    const settings = bankGetSettings();
    const gNow = proj.gold;
    if (gNow >= targetGold) return 0;

    const a = 0.5 * settings.growthGoldPerSoldier * proj.spm; // gold/min²
    const b = proj.goldPerMin;                                // gold/min
    const c = gNow - targetGold;

    if (a > 0) {
      const disc = b * b - 4 * a * c;
      if (disc < 0) return null;
      return (-b + Math.sqrt(disc)) / (2 * a);
    }
    if (b > 0) return -c / b;
    return null;
  }

  // ==================== ATTACK-LOG SCRAPER (feeds the risk model) ====================
  // On attacklog.php: the "Attacks Against You" header table is a table_lines.attacklog;
  // the data rows live in the NEXT table_lines. Cache is keyed by attack_id.
  function bankCollectAttackLog() {
    try {
      const tables = [...document.querySelectorAll('table')];
      const headerIdx = tables.findIndex(t =>
        t.classList.contains('attacklog') && /Attacks Against You/.test(t.textContent));
      if (headerIdx === -1) {
        debugLog('⚠️ Banking: "Attacks Against You" header table not found');
        return 0;
      }

      let dataTable = null;
      for (let i = headerIdx + 1; i < tables.length; i++) {
        if (tables[i].classList.contains('table_lines') && tables[i].rows.length > 1) {
          dataTable = tables[i];
          break;
        }
      }
      if (!dataTable) {
        debugLog('⚠️ Banking: attack-log data table not found');
        return 0;
      }

      const events = bankGet('attack_events', {});
      let newCount = 0;

      [...dataTable.rows].forEach(row => {
        try {
          if (row.cells.length < 8) return;
          const rowText = row.textContent;
          // Only "attacked by" rows (excludes "Attacks By You" + the pagination row)
          if (!/attacked by/i.test(rowText)) return;

          const detailLink = row.querySelector('a[href*="attack_id="]');
          const idMatch = detailLink ? detailLink.getAttribute('href').match(/attack_id=(\d+)/) : null;
          if (!idMatch) return;
          const attackId = idMatch[1];
          if (events[attackId]) return; // already cached

          const attackerLink = row.querySelector('a[href*="stats.php?id="]');
          const attackerName = attackerLink ? attackerLink.textContent.trim() : 'Unknown';
          const attackerId = attackerLink ? (attackerLink.getAttribute('href').match(/id=(\d+)/)?.[1] || null) : null;

          const stolenMatch = rowText.match(/([\d,]+)\s+Gold stolen/i); // defended rows → 0
          const goldStolen = stolenMatch ? bankCleanNumber(stolenMatch[1]) : 0;

          // Exact server timestamp — the one place the Eastern→UTC conversion belongs
          const tsMatch = rowText.match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);
          const ts = (tsMatch ? convertKoCServerTimeToUTC(tsMatch[0]) : null) || new Date().toISOString();

          events[attackId] = { id: attackId, attacker: attackerName, attackerId: attackerId, goldStolen: goldStolen || 0, ts: ts };
          newCount++;
        } catch (err) {
          debugLog('⚠️ Banking: attack-log row parse failed:', err);
        }
      });

      // Prune: keep 60 days, cap 600 newest
      const cutoff = Date.now() - 60 * 86400000;
      const kept = Object.values(events)
        .filter(e => new Date(e.ts).getTime() >= cutoff)
        .sort((a, b) => new Date(b.ts) - new Date(a.ts))
        .slice(0, 600);
      const pruned = {};
      kept.forEach(e => { pruned[e.id] = e; });

      bankSet('attack_events', pruned);
      bankSet('last_attacklog_visit', new Date().toISOString());
      debugLog(`✅ Banking attack log: ${newCount} new, ${kept.length} stored`);
      return newCount;
    } catch (err) {
      debugLog('⚠️ Banking attack-log scrape failed:', err);
      return 0;
    }
  }

  // ==================== RISK MODEL ====================
  // Each steal back-calculates held = goldStolen / stealRateMax (MAX = conservative
  // lower bound). Yellow = P25, red = P50 of the held distribution in the window.
  // Under 3 samples → static fallback thresholds.
  function bankGetRiskModel() {
    const settings = bankGetSettings();
    const events = Object.values(bankGet('attack_events', {}));
    const cutoff = Date.now() - settings.riskWindowDays * 86400000;

    const held = events
      .filter(e => e.goldStolen > 0 && new Date(e.ts).getTime() >= cutoff)
      .map(e => Math.round(e.goldStolen / settings.stealRateMax))
      .sort((a, b) => a - b);

    if (held.length >= 3) {
      return {
        source: 'attacks',
        sampleSize: held.length,
        yellowGold: Math.round(bankPercentile(held, settings.yellowPercentile)),
        redGold: Math.round(bankPercentile(held, settings.redPercentile)),
        windowDays: settings.riskWindowDays
      };
    }
    return {
      source: 'fallback',
      sampleSize: held.length,
      yellowGold: settings.fallbackYellowGold,
      redGold: settings.fallbackRedGold,
      windowDays: settings.riskWindowDays
    };
  }

  function bankRiskBand(gold, model) {
    if (gold >= model.redGold) return 'red';
    if (gold >= model.yellowGold) return 'yellow';
    return 'green';
  }

  const BANK_BAND_META = {
    green: { label: 'SAFE', color: '#16a34a', glow: 'rgba(74, 222, 128, 0.35)' },
    yellow: { label: 'CAUTION', color: '#d97706', glow: 'rgba(251, 191, 36, 0.35)' },
    red: { label: 'DANGER', color: '#dc2626', glow: 'rgba(248, 113, 113, 0.4)' }
  };
  const BANK_BAND_ORDER = { green: 0, yellow: 1, red: 2 };

  function bankGetRiskStatus() {
    const proj = bankGetProjection();
    const model = bankGetRiskModel();
    if (!proj) return { proj: null, model, band: null };
    const band = bankRiskBand(proj.gold, model);
    return {
      proj: proj,
      model: model,
      band: band,
      minsToYellow: band === 'green' ? bankMinutesToGold(model.yellowGold, proj) : 0,
      minsToRed: band === 'red' ? 0 : bankMinutesToGold(model.redGold, proj)
    };
  }

  // ==================== WAKE LOCK ====================
  // Requested on toggle-on (user gesture), re-requested on visibilitychange (the
  // browser drops the lock when the tab hides), released on toggle-off.
  let bankWakeLock = null;
  let bankVisibilityHooked = false;

  async function bankRequestWakeLock() {
    if (!('wakeLock' in navigator)) { bankUpdateWakeLockPill(); return false; }
    if (bankWakeLock) return true;
    try {
      bankWakeLock = await navigator.wakeLock.request('screen');
      bankWakeLock.addEventListener('release', () => {
        // Fires on our release AND when the browser drops the lock (tab hidden) —
        // clear the sentinel so the pill reads true state.
        bankWakeLock = null;
        bankUpdateWakeLockPill();
        debugLog('🌙 Banking screen wake lock released');
      });
      debugLog('🔆 Banking screen wake lock active');
      bankUpdateWakeLockPill();
      return true;
    } catch (err) {
      debugLog('⚠️ Banking wake lock request failed:', err && err.message);
      bankWakeLock = null;
      bankUpdateWakeLockPill();
      return false;
    }
  }

  async function bankReleaseWakeLock() {
    if (bankWakeLock) {
      try { await bankWakeLock.release(); } catch (err) { /* already released */ }
      bankWakeLock = null;
    }
    bankUpdateWakeLockPill();
  }

  function bankUpdateWakeLockPill() {
    const pill = document.getElementById('koc-banking-wakelock');
    if (pill) {
      pill.textContent = bankWakeLock ? '🔆 screen awake' : '🌙 wake lock off';
      pill.style.color = bankWakeLock ? '#16a34a' : '#888';
    }
  }

  // ==================== NOTIFICATIONS (optional, off by default) ====================
  let bankLastNotifiedBand = 'green';

  function bankEnsureNotifyPermission() {
    const settings = bankGetSettings();
    if (!settings.notifyEnabled) return;            // don't prompt unless opted in
    if (!('Notification' in window)) return;
    if (Notification.permission === 'default') {
      Notification.requestPermission().then(p => debugLog(`🔔 Banking notification permission: ${p}`));
    }
  }

  // Notify on band ESCALATION only (green→yellow→red), rate-limited. {body, tag}
  // ONLY — no icon: a remote icon URL would make the display timer fire a request.
  function bankMaybeNotifyBand(band, gold) {
    const settings = bankGetSettings();
    if (!settings.notifyEnabled) return;
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    if (BANK_BAND_ORDER[band] <= BANK_BAND_ORDER[bankLastNotifiedBand]) {
      bankLastNotifiedBand = band; // de-escalation re-arms future alerts
      return;
    }
    const lastTs = bankGet('last_notify_ts', null);
    if (lastTs && Date.now() - new Date(lastTs).getTime() < settings.notifyMinGapMins * 60000) return;
    try {
      new Notification('🏦 KoC Banking Mode', {
        body: `Risk ${BANK_BAND_META[band].label}: ~${bankFormatGold(gold)} gold exposed. Time to bank!`,
        tag: 'koc-banking-risk'
      });
      bankSet('last_notify_ts', new Date().toISOString());
      bankLastNotifiedBand = band;
      debugLog(`🔔 Banking notified: band ${band}`);
    } catch (err) {
      debugLog('⚠️ Banking notification failed:', err);
    }
  }

  // ==================== POST-ACTION (LAST-BANK) DETECTION ====================
  // A pending stamp is written when the human submits the real form (observed via
  // passive listeners); on the armory reload the game performs after the POST, a
  // funds drop confirms the action and stamps last_bank. No reparenting, no
  // synthetic events — the forms are only observed.
  const bankHookedForms = new WeakSet();

  function bankSetPendingAction(type) {
    // Stamp the PROJECTED funds at submit time, not the raw last reading. With high
    // income the page-load reading can sit millions below the real balance by the
    // time the user presses Buy, which would make the post-buy drop look negative and
    // miss the bank. The projection tracks accrued income up to this moment.
    const proj = bankGetProjection();
    const reading = bankGet('gold_reading', null);
    const goldNow = proj ? proj.gold : (reading ? reading.gold : null);
    bankSet('pending_action', {
      type: type,
      gold: goldNow,
      ts: new Date().toISOString()
    });
  }

  function bankCheckPendingAction(currentGold) {
    const pending = bankGet('pending_action', null);
    if (!pending) return;
    bankRemove('pending_action'); // one-shot

    if (Date.now() - new Date(pending.ts).getTime() > 10 * 60000) {
      debugLog('⏰ Banking pending action expired');
      return;
    }
    if (pending.gold === null || currentGold === null || currentGold === undefined) return;

    const drop = pending.gold - currentGold;
    // A buy/repair was definitely submitted (pending is only set on a real form
    // submit), and on armory the sole funds-decreasing action is a purchase, so a
    // sizable positive drop confirms it. A flat 1M floor clears projection noise
    // without demanding the old 25%-of-balance spend, which big earners rarely hit
    // in a single buy (and which silently dropped every smaller purchase).
    const threshold = pending.type === 'buy' ? 1000000 : 1000;
    if (drop >= threshold) {
      bankSet('last_bank', { ts: new Date().toISOString(), spent: drop, action: pending.type });
      bankLastNotifiedBand = 'green'; // re-arm escalation notifications after banking
      debugLog(`🏦 ✅ Banked! ${drop.toLocaleString()} gold via ${pending.type} — last_bank stamped`);
    } else {
      debugLog(`⏭️ Banking: ${pending.type} pressed but no funds drop (drop ${drop.toLocaleString()})`);
    }
  }

  // Attach PASSIVE observers to the game's OWN buy/repair forms. We listen for BOTH
  // 'submit' AND a TRUSTED click on the submit input — KoC buttons often submit via
  // inline onclick form.submit(), which skips the submit event. We NEVER trigger them.
  function bankHookFormPending(form, type) {
    if (!form || bankHookedForms.has(form)) return;
    bankHookedForms.add(form);
    const stamp = () => {
      bankSetPendingAction(type);
      debugLog(`🏦 Banking: ${type} submitted by user — pending stamp written`);
    };
    form.addEventListener('submit', stamp);
    form.addEventListener('click', e => {
      if (e.isTrusted && e.target && e.target.type === 'submit') stamp();
    });
  }

  function bankHookForms() {
    // Buy: hook BOTH the one-click Autofill form (buyform) and the per-weapon form
    // (anotherbuyform). The game serves one and hides the other depending on whether
    // Armory Autofill is saved server-side — buyform commonly EXISTS but is
    // display:none while the user actually buys via the visible anotherbuyform.
    // Hooking only the first one found (buyform) misses every real purchase.
    const oneClickBuy = document.forms.namedItem('buyform');
    if (oneClickBuy) bankHookFormPending(oneClickBuy, 'buy');
    const perWeaponBuy = document.getElementById('anotherbuyform') || document.forms.namedItem('anotherbuyform');
    if (perWeaponBuy) bankHookFormPending(perWeaponBuy, 'buy');

    // Repair: the form around input[name=repair_all_weapons]
    const repairBtn = document.querySelector('input[name="repair_all_weapons"]');
    if (repairBtn && repairBtn.form) bankHookFormPending(repairBtn.form, 'repair');
  }

  // ==================== INLINE WIDGET UI ====================
  let bankTickerId = null;

  function bankInjectStyles() {
    if (document.getElementById('koc-banking-style')) return;
    const style = document.createElement('style');
    style.id = 'koc-banking-style';
    style.textContent = `
      #koc-banking-inline {
        margin: 8px 0; text-align: center;
      }
      #koc-banking-inline .kb-toggle-row {
        display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
        margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid rgba(255,255,255,0.12);
      }
      #koc-banking-toggle {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff;
        border: none; padding: 7px 16px; border-radius: 20px; cursor: pointer;
        font-size: 13px; font-weight: 600; box-shadow: 0 2px 8px rgba(102,126,234,0.4);
      }
      #koc-banking-inline .kb-btn {
        background: rgba(102,126,234,0.15); color: #4338ca; border: 1px solid rgba(102,126,234,0.4);
        padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;
      }
      #koc-banking-wakelock { font-size: 12px; color: #888; }
      #koc-banking-body { margin: 0 auto; }
      /* Native-style box: reuse KoC's own table_lines class so it matches whatever theme is set. */
      #koc-banking-box { width: 100%; margin: 8px auto; }
      #koc-banking-th { position: relative; text-align: center; padding: 6px 24px; }
      #koc-banking-gold { transition: color 0.3s ease; }
      #koc-banking-gear { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; font-size: 15px; user-select: none; opacity: 0.85; }
      #koc-banking-gear:hover { opacity: 1; }
      #koc-banking-box .kb-detail { text-align: left; padding: 10px 14px; background: rgba(0,0,0,0.22); font-size: 12px; line-height: 1.5; }
      #koc-banking-band { font-weight: 700; letter-spacing: 1px; }
      #koc-banking-inline .kb-stat { font-size: 13px; color: #ccc; margin: 4px 0; }
      #koc-banking-inline .kb-stat b { color: #FFD700; }
      #koc-banking-inline a { color: #93c5fd; }
      #koc-banking-inline .kb-live { color: #4ade80; }
      @keyframes kb-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
      #koc-banking-inline .kb-live { animation: kb-pulse 2s infinite; display: inline-block; }
      #koc-banking-settings { display: block; margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.12); padding-top: 10px; }
      #koc-banking-settings label {
        display: flex; justify-content: space-between; align-items: center;
        font-size: 12px; color: #ccc; margin: 6px 0; gap: 10px;
      }
      #koc-banking-settings input[type=number], #koc-banking-settings input[type=text] {
        background: rgba(0,0,0,0.3); color: #fff; width: 110px;
        border: 1px solid rgba(255,215,0,0.3); border-radius: 5px; padding: 4px 8px;
      }
    `;
    document.head.appendChild(style);
  }

  // Locate the table that holds the "Available Funds:" banner (verified live).
  function bankFindArmoryAnchor() {
    const fundsEl = [...document.querySelectorAll('b,font,td')]
      .find(el => /Available Funds:/.test(el.textContent) && el.textContent.trim().length < 60);
    return fundsEl ? fundsEl.closest('table') : null;
  }

  function bankBuildWidgets() {
    if (document.getElementById('koc-banking-inline')) { bankApplyEnabledState(); return; }
    bankInjectStyles();

    const s = bankGetSettings();
    const container = document.createElement('div');
    container.id = 'koc-banking-inline';
    container.innerHTML = `
      <div id="koc-banking-body">
        <table class="table_lines" id="koc-banking-box"><tbody>
          <tr><th id="koc-banking-th">
            <font size="4"><b class="kb-ef-label">Estimated Funds:</b></font> <font size="5"><span id="koc-banking-gold">—</span></font>
            <span id="koc-banking-gear" title="Settings &amp; detail">⚙️</span>
            <div id="koc-banking-times" style="display:none;font-weight:400;font-size:12px;margin-top:3px;"></div>
          </th></tr>
          <tr id="koc-banking-detailrow" style="display:none;"><td class="kb-detail">
            <div class="kb-toggle-row"><button type="button" id="koc-banking-toggle">🏦 Banking Mode</button><span id="koc-banking-wakelock" style="display:none;">🌙 wake lock off</span></div>
            <div class="kb-stat" id="koc-banking-band-line"><b id="koc-banking-band">—</b> · <span id="koc-banking-countdowns">—</span></div>
            <div class="kb-stat">⏱️ Last bank: <b id="koc-banking-lastbank">never</b></div>
          <div class="kb-stat">📐 Calibration: <b id="koc-banking-cal">—</b></div>
          <div class="kb-stat">🗡️ Risk model: <b id="koc-banking-risk-src">—</b> · <a href="attacklog.php">visit Attack Log to refresh</a></div>
          <div class="kb-stat">🏦 Vault (not at risk): <b id="koc-banking-vault">—</b></div>
          <div class="kb-stat"><span class="kb-live">●</span> display refresh only — no automated requests</div>
          <div id="koc-banking-settings">
            <div style="color:#FFD700; font-weight:600; margin-bottom:8px;">Settings</div>
            <label>Show yellow/red times on the box <input type="checkbox" id="kbs-showTimes" ${s.showTimes ? 'checked' : ''}></label>
            <label>Steal rate min (0–1) <input type="number" step="0.01" min="0.1" max="1" id="kbs-stealRateMin" value="${s.stealRateMin}"></label>
            <label>Steal rate max (risk maths uses this; 1.0 = conservative) <input type="number" step="0.01" min="0.1" max="1" id="kbs-stealRateMax" value="${s.stealRateMax}"></label>
            <label>Risk window (days) <input type="number" min="1" max="60" id="kbs-riskWindowDays" value="${s.riskWindowDays}"></label>
            <label>Yellow percentile <input type="number" min="1" max="99" id="kbs-yellowPercentile" value="${s.yellowPercentile}"></label>
            <label>Red percentile <input type="number" min="1" max="99" id="kbs-redPercentile" value="${s.redPercentile}"></label>
            <label>Fallback yellow gold <input type="text" inputmode="numeric" id="kbs-fallbackYellowGold" value="${s.fallbackYellowGold.toLocaleString()}"></label>
            <label>Fallback red gold <input type="text" inputmode="numeric" id="kbs-fallbackRedGold" value="${s.fallbackRedGold.toLocaleString()}"></label>
            <label>TBG gold/turn — regulars <input type="number" step="0.01" id="kbs-tbgRegular" value="${s.tbgRegular}"></label>
            <label>TBG gold/turn — coverts <input type="number" step="0.01" id="kbs-tbgCovert" value="${s.tbgCovert}"></label>
            <label>Growth gold/soldier/turn (SPM term) <input type="number" step="0.01" id="kbs-growthGoldPerSoldier" value="${s.growthGoldPerSoldier}"></label>
            <label>Notifications enabled <input type="checkbox" id="kbs-notifyEnabled" ${s.notifyEnabled ? 'checked' : ''}></label>
            <label>Notification min gap (mins) <input type="number" min="1" id="kbs-notifyMinGapMins" value="${s.notifyMinGapMins}"></label>
          </div>
        </td></tr>
        </tbody></table>
      </div>
    `;

    const anchor = bankFindArmoryAnchor();
    if (anchor && anchor.parentNode) {
      anchor.parentNode.insertBefore(container, anchor);
    } else {
      debugLog('⚠️ Banking: "Available Funds:" anchor not found — inserting at page top (re-verify the armory anchor selector)');
      document.body.insertBefore(container, document.body.firstChild);
    }

    // SAFETY: on some layouts the "Available Funds:" banner lives inside the
    // per-weapon buy form (#anotherbuyform), so this widget can end up INSIDE a
    // game form. Our buttons are type="button" (above) and we swallow Enter on our
    // own inputs here, so the widget can NEVER submit a game form / spend gold.
    container.addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.target && e.target.tagName === 'INPUT') e.preventDefault();
    });

    // --- wire controls ---
    container.querySelector('#koc-banking-toggle').addEventListener('click', bankToggle);
    const gear = container.querySelector('#koc-banking-gear');
    if (gear) gear.addEventListener('click', () => {
      const dr = container.querySelector('#koc-banking-detailrow');
      if (dr) dr.style.display = (dr.style.display === 'none' ? '' : 'none');
    });

    const numericFields = ['stealRateMin', 'stealRateMax', 'riskWindowDays', 'yellowPercentile',
      'redPercentile', 'tbgRegular', 'tbgCovert', 'growthGoldPerSoldier', 'notifyMinGapMins'];
    numericFields.forEach(field => {
      const el = container.querySelector('#kbs-' + field);
      if (el) el.addEventListener('change', e => {
        const v = parseFloat(e.target.value);
        if (!isNaN(v)) bankSaveSettings({ [field]: v });
      });
    });
    ['fallbackYellowGold', 'fallbackRedGold'].forEach(field => {
      const el = container.querySelector('#kbs-' + field);
      if (el) el.addEventListener('change', e => {
        const v = bankCleanNumber(e.target.value);
        if (v !== null) bankSaveSettings({ [field]: v });
      });
    });
    const notifyEl = container.querySelector('#kbs-notifyEnabled');
    if (notifyEl) notifyEl.addEventListener('change', e => {
      bankSaveSettings({ notifyEnabled: e.target.checked });
      if (e.target.checked) bankEnsureNotifyPermission();
    });
    const showTimesEl = container.querySelector('#kbs-showTimes');
    if (showTimesEl) showTimesEl.addEventListener('change', e => {
      bankSaveSettings({ showTimes: e.target.checked });
      bankUpdateDisplay();
    });

    bankApplyEnabledState();
  }

  // Reflect the persisted enabled flag: show/hide widgets, manage ticker + wake lock.
  function bankApplyEnabledState() {
    const enabled = bankGet('enabled', false);
    const toggle = document.getElementById('koc-banking-toggle');
    const wlPill = document.getElementById('koc-banking-wakelock');

    if (toggle) {
      toggle.textContent = enabled ? '🏦 Banking Mode: ON' : '🏦 Banking Mode';
      toggle.style.background = enabled
        ? 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)'
        : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
    }
    if (wlPill) wlPill.style.display = enabled ? '' : 'none';

    if (enabled) {
      bankHookForms();
      bankRequestWakeLock();
      bankStartTicker();
    } else {
      bankStopTicker();
      bankReleaseWakeLock();
    }
    // Box is always visible now → always paint the current estimate; the ticker adds live updates when ON.
    bankUpdateDisplay();
  }

  // The human press that arms everything (user gesture → wake lock + notify allowed).
  function bankToggle() {
    const enabled = bankGet('enabled', false);
    bankSet('enabled', !enabled);
    if (!enabled) bankEnsureNotifyPermission();
    bankApplyEnabledState();
    debugLog(`🏦 Banking Mode ${!enabled ? 'ON' : 'OFF'}`);
  }

  // Repaint the readouts (DISPLAY ONLY — no requests, no game actions).
  function bankUpdateDisplay() {
    const body = document.getElementById('koc-banking-body');
    if (!body) return;

    const status = bankGetRiskStatus();
    const goldEl = document.getElementById('koc-banking-gold');
    const bandEl = document.getElementById('koc-banking-band');
    const cdEl = document.getElementById('koc-banking-countdowns');
    if (!goldEl || !bandEl || !cdEl) return;

    if (!status.proj) {
      goldEl.textContent = '???';
      goldEl.style.color = '#999';
      bandEl.textContent = 'NO CALIBRATION';
      bandEl.style.color = '#999';
      cdEl.innerHTML = 'Visit the <a href="base.php">Command Centre</a> to calibrate';
      const tEl = document.getElementById('koc-banking-times'); if (tEl) tEl.style.display = 'none';
      return;
    }

    const meta = BANK_BAND_META[status.band];
    const showTimes = bankGetSettings().showTimes;
    goldEl.textContent = bankFormatGold(status.proj.gold);
    goldEl.title = status.proj.gold.toLocaleString() + ' gold';
    // Default: inherit the native funds-box colour (white) so the box blends into the page.
    // Only when "show times" is enabled do we tint the value + glow it by risk band.
    goldEl.style.color = showTimes ? meta.color : '';
    goldEl.style.textShadow = showTimes ? `0 0 10px ${meta.glow}` : '';
    bandEl.textContent = meta.label + (status.model.source === 'fallback' ? ' (fallback bands)' : '');
    bandEl.style.color = meta.color;

    const parts = [];
    if (status.band === 'green') parts.push(`🟡 yellow in <b>${bankFormatMinutes(status.minsToYellow)}</b>`);
    if (status.band !== 'red') parts.push(`🔴 red in <b>${bankFormatMinutes(status.minsToRed)}</b>`);
    if (status.band === 'red') parts.push('🔴 <b>over the red line — bank now</b>');
    if (status.proj.stale) parts.push('⚠️ calibration stale — visit the <a href="base.php">Command Centre</a>');
    if (status.proj.noIncome) parts.push('⚠️ no income data — visit the <a href="base.php">Command Centre</a>');
    cdEl.innerHTML = parts.join(' · ') || '—';

    // Compact countdown on the box itself — setting-gated (off by default to match the native box).
    const timesEl = document.getElementById('koc-banking-times');
    if (timesEl) {
      if (showTimes) {
        const compact = [];
        if (status.band === 'green') compact.push(`🟡 ${bankFormatMinutes(status.minsToYellow)}`);
        if (status.band !== 'red') compact.push(`🔴 ${bankFormatMinutes(status.minsToRed)}`);
        if (status.band === 'red') compact.push('🔴 bank now');
        timesEl.innerHTML = compact.join(' · ');
        timesEl.style.color = meta.color;
        timesEl.style.display = compact.length ? '' : 'none';
      } else {
        timesEl.style.display = 'none';
      }
    }

    const lastBank = bankGet('last_bank', null);
    const lastBankEl = document.getElementById('koc-banking-lastbank');
    if (lastBankEl) lastBankEl.textContent = lastBank
      ? `${bankFormatTimeAgo(lastBank.ts)} (${bankFormatGold(lastBank.spent)} via ${lastBank.action})`
      : 'never';

    const calTs = status.proj.cal && status.proj.cal.ts ? status.proj.cal.ts : null;
    const calEl = document.getElementById('koc-banking-cal');
    if (calEl) calEl.textContent =
      `rates ${calTs ? bankFormatTimeAgo(calTs) : 'never'} (base.php)` +
      ` · gold reading ${bankFormatTimeAgo(status.proj.reading.ts)} (${status.proj.reading.source})` +
      (status.proj.goldPerMin !== null ? ` · ${bankFormatGold(status.proj.goldPerMin)}/min · SPM ${status.proj.spm}` : '');

    const riskEl = document.getElementById('koc-banking-risk-src');
    if (riskEl) riskEl.textContent =
      status.model.source === 'attacks'
        ? `${status.model.sampleSize} steals in ${status.model.windowDays}d · yellow ${bankFormatGold(status.model.yellowGold)} · red ${bankFormatGold(status.model.redGold)}`
        : `fallback thresholds (only ${status.model.sampleSize} steals cached)`;

    const vault = status.proj.reading.vault;
    const vaultEl = document.getElementById('koc-banking-vault');
    if (vaultEl) vaultEl.textContent =
      vault === null || vault === undefined ? '?' : vault.toLocaleString() + ' gold';

    if (bankGet('enabled', false)) bankMaybeNotifyBand(status.band, status.proj.gold);
  }

  // 1-second DISPLAY repaint. Redraws locally-known numbers only — never the network.
  function bankStartTicker() {
    if (bankTickerId) return;
    bankTickerId = setInterval(bankUpdateDisplay, 1000);
  }
  function bankStopTicker() {
    if (bankTickerId) { clearInterval(bankTickerId); bankTickerId = null; }
  }

  // Armory entrypoint: read state, confirm any pending bank, inject the widgets.
  function bankOnArmory() {
    const gold = bankCollectArmoryState();
    bankCheckPendingAction(gold);
    bankBuildWidgets();

    if (!bankVisibilityHooked) {
      bankVisibilityHooked = true;
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' &&
            bankGet('enabled', false) &&
            location.pathname.includes('armory.php')) {
          bankRequestWakeLock();
        }
      });
    }
  }

  // ==================== BANKING MODE CONSOLE API ====================
  window.KoCBanking = {
    enable: () => { if (!bankGet('enabled', false)) bankToggle(); },
    disable: () => { if (bankGet('enabled', false)) bankToggle(); },
    status: () => {
      const st = bankGetRiskStatus();
      if (st.proj) {
        console.log(`💰 Projected: ${st.proj.gold.toLocaleString()} gold (${bankFormatTimeAgo(st.proj.reading.ts)} + ${st.proj.dtMin.toFixed(1)}min)`);
        console.log(`🚦 Band: ${st.band} | yellow @ ${st.model.yellowGold.toLocaleString()} | red @ ${st.model.redGold.toLocaleString()} (${st.model.source}, n=${st.model.sampleSize})`);
        console.log(`⏳ Time to red: ${bankFormatMinutes(st.minsToRed)}`);
      } else {
        console.log('⚠️ No banking calibration yet — visit base.php');
      }
      return st;
    },
    calibrate: bankCollectCommandCentre,
    collectAttackLog: bankCollectAttackLog,
    projection: bankGetProjection,
    riskModel: bankGetRiskModel,
    settings: { get: bankGetSettings, set: bankSaveSettings },
    events: () => {
      const ev = Object.values(bankGet('attack_events', {})).sort((a, b) => new Date(b.ts) - new Date(a.ts));
      console.table(ev);
      return ev;
    },
    clearData: () => {
      ['enabled', 'settings', 'calibration', 'gold_reading', 'attack_events',
       'last_bank', 'pending_action', 'last_notify_ts', 'last_attacklog_visit']
        .forEach(k => bankRemove(k));
      console.log('🗑️ Banking Mode data cleared');
    }
  };

  // ==================== SABOTAGE TRACKER (attack.php) ====================
  // Tracks YOUR OWN sabotage / revenge-sabotage attempts per target (KoC allows
  // 10 sabs + 4 revenge sabs per target in a rolling 24h window) and shows:
  //   • "You last sabbed/poisoned/stole" timestamps as colour-coded ages (stats-page style)
  //   • attempts left in the window + a ticking "Can sab again in …" countdown
  //   • sab damage left before the target is maxed (cap − lost in last 24h)
  // Compliance: display + passive recording only. It listens for missions the
  // player fires by hand, and reconciles against the counters KoC itself renders.
  // It never submits, clicks, or fetches anything.

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

  function recordSabAttempt(targetId, kind, tMs) {
    const log = getSabLog();
    const rec = log[targetId] || (log[targetId] = { sab: [], rev: [] });
    const arr = kind === 'rev' ? (rec.rev = rec.rev || []) : (rec.sab = rec.sab || []);
    arr.push({ t: tMs });
    arr.sort((a, b) => a.t - b.t);
    rec.seen = tMs;
    saveSabLog(log);
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
      // KoC prints the cap with decimals whenever it isn't a whole number —
      // "(62,522,883,715.60)". Requiring digits-then-bracket meant the regex
      // failed on exactly those pages, so maxLoss came back null and the
      // "sab damage left before maxed" line quietly never rendered. Allow the
      // fraction and drop it (parseInt truncates); whole-gold is the unit.
      maxLoss: bodyNum(/Maximum Daily Sabotage loss:\s*\(([\d,]+(?:\.\d+)?)\)/i),
      lost24: bodyNum(/Total lost from sabbs in the last 24\s*hours:\s*([\d,]+(?:\.\d+)?)/i),
      lastSabMs: stampMs(/You last sabbed:[^]{0,80}?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/i),
      // native row that appears once you've sabbed in the current window — exact oldest-sab time
      firstSabMs: stampMs(/First sab[^]{0,60}?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/i),
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
   * authoritative): drop the oldest tracked entries if KoC says fewer are in the
   * window, and pad with estimated entries (stamped from "You last sabbed", the
   * newest possible time) if KoC counted attempts we never saw — those show a
   * "≤" upper-bound countdown until real times arrive from the Intelligence file.
   */
  function reconcileSabLog(info) {
    const log = getSabLog();
    const rec = log[info.targetId] || (log[info.targetId] = { sab: [], rev: [] });
    const now = Date.now();
    const fit = (arr, pageCount, lastMs, firstMs) => {
      const okFirst = firstMs && now - firstMs < SAB_WINDOW_MS;
      const inWin = (arr || []).filter(e => e && now - e.t < SAB_WINDOW_MS).sort((a, b) => a.t - b.t);
      if (pageCount != null) {
        while (inWin.length > pageCount) inWin.shift();
        if (inWin.length < pageCount && okFirst && (!inWin.length || firstMs < inWin[0].t)) {
          inWin.unshift({ t: firstMs }); // KoC's own "First sab (last 24hrs)" stamp — exact
        }
        const estT = (lastMs && now - lastMs < SAB_WINDOW_MS) ? lastMs : now;
        while (inWin.length < pageCount) inWin.push({ t: estT, est: 1 });
        inWin.sort((a, b) => a.t - b.t);
        if (okFirst && inWin.length && inWin[0].est) {
          inWin[0] = { t: firstMs }; // upgrade an estimated oldest to the exact stamp
          inWin.sort((a, b) => a.t - b.t);
        }
      }
      return inWin;
    };
    rec.sab = fit(rec.sab, info.sabAttempts, info.lastSabMs, info.firstSabMs);
    rec.rev = fit(rec.rev, info.revAttempts, info.lastRevMs, null);
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
    relativizeMissionTimestamps();
    const rec = reconcileSabLog(info);
    const renders = injectSabPanels(info, rec);
    if (renders.length) startSabTicker(renders);
    debugLog('🕵️ Sab Tracker initialised', {
      target: info.targetId, sab: rec.sab.length, rev: rec.rev.length, maxed: info.maxed
    });

    // Share the two cap numbers with the roster. Nothing else records them,
    // and together they answer the only question that matters when picking a
    // target: how much of this player's daily cap is still takeable. The War
    // Room shows it per player with the reading's age, since the window rolls.
    if (info.maxLoss != null && info.lost24 != null) {
      const now = getKoCServerTimeUTC();
      Promise.resolve(auth.apiCall('players', {
        id: info.targetId,
        sabLost24h: info.lost24,
        sabLost24hTime: now,
        sabMaxDaily: info.maxLoss,
        sabMaxDailyTime: now
      })).catch(function () { /* display-only feature: never break the page */ });
      debugLog('🎯 Sab cap status sent', {
        id: info.targetId, lost24: info.lost24, maxLoss: info.maxLoss
      });
    }
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
      recordSabAttempt(String(targetId), isRev ? 'rev' : 'sab', Date.now());
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

    // Mission Type is found by its header, not by position. The Time column is
    // two cells ("6" | "hours ago"), which puts Mission Type third — reading
    // the second cell meant no row ever matched and this backfill never ran.
    for (const row of page.rows) {
      const type = (row.missionText || '').trim().toLowerCase();
      let kind = null;
      if (type === 'sabotage') kind = 'sab';
      else if (type.includes('revenge')) kind = 'rev'; // "Revenge_sabotage"
      else continue;
      if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(row.at || '')) continue;
      const t = Date.parse(convertKoCServerTimeToUTC(row.at));
      if (isNaN(t) || now - t >= SAB_WINDOW_MS) continue;
      found[kind].push({ t }); // aborted attempts still count toward the 10/4 caps
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
  // Five game pages list missions with their results, and a sixth describes
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
   * attacked" / "attacked by", both seen live; a raid is expected to read
   * the same way) is used only when there is no title; when it disagrees
   * with the title the row goes with the title's side and a debug line.
   * Wording nobody has seen never drops a row: with no title either, the
   * row is sent without a side and the server reads the wording it keeps.
   *
   * Banking Mode's reader (bankCollectAttackLog) and the summary enhancer
   * (enhanceAttackLog) read the same page on their own, untouched by this.
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
   */
  function recentSabTargetId(log, nowMs, windowMs) {
    let best = null;
    for (const [id, rec] of Object.entries(log && typeof log === 'object' ? log : {})) {
      for (const e of [...((rec && rec.sab) || []), ...((rec && rec.rev) || [])]) {
        if (!e || typeof e.t !== 'number' || nowMs - e.t > windowMs || e.t - nowMs > 5000) continue;
        if (!best || e.t > best.t) best = { id, t: e.t };
      }
    }
    return best ? best.id : null;
  }

  /**
   * The text lines of a sab report (inteldetail.php) — the report and
   * nothing else. On the live page the "Covert Mission Report" table holds
   * only its title and closes at once; the report sentences sit loose in the
   * page's own content cell, after the Attack / Raid / Recon button tables,
   * split by <p>, and are followed by the "Return to Top" table and the
   * footer. That content cell also holds the era notice, the footer links
   * and the copyright lines, so it cannot simply be read whole.
   *
   * So the page is read in order, one entry per line as it shows on screen
   * (<br> and block edges end a line; a link inside a sentence stays part of
   * it), with a marker wherever a table starts or ends. The report is the
   * line with "attempt to sabotage" (the dispatch line) and every line after
   * it up to the first table edge — the "Return to Top" table on the live
   * page, or the end of the table cell when a report sits inside one.
   * Nothing before the dispatch line is part of it. The walk starts at the
   * document root, not document.body: the live page opens an <a name="top">
   * before its <body> tag, which some parsers answer with a second, empty
   * body element.
   */
  function sabReportLines() {
    const EDGE = {};
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
      if (table) out.push(EDGE);
      for (const child of node.childNodes) walk(child);
      if (block) endLine();
      if (table) out.push(EDGE);
    };
    walk(document.documentElement);
    endLine();

    const start = out.findIndex((l) => l !== EDGE && /attempt to sabotage/i.test(l));
    if (start < 0) return [];
    const lines = [];
    for (const l of out.slice(start)) {
      if (l === EDGE) break;
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
   */
  function parseSabReportPage() {
    const reportId = (location.search.match(/[?&]report_id=(\d+)/) || [])[1] || null;
    if (!reportId) return null;
    const lines = sabReportLines();
    const dispatch = lines.find((l) => /attempt to sabotage/i.test(l));
    if (!dispatch) return null;
    const inside = lines.map((l) => l.match(/While inside (.+?)'s armory/i)).find(Boolean);
    const form = document.querySelector('input[name="defender_id"]');
    const targetId = form && /^\d+$/.test(form.value || '')
      ? form.value
      : recentSabTargetId(getSabLog(), Date.now(), 2 * 60 * 1000);
    return {
      source: 'report',
      family: 'intel',
      reportId,
      targetId,
      targetName: inside ? inside[1].trim() : null,
      missionText: dispatch,
      lines
    };
  }

  /** Which mission page this is, from the address; null on every other page. */
  function missionLogSource() {
    const page = (location.pathname.split('/').pop() || '').toLowerCase();
    return ({
      'intelfile.php': 'intelfile',
      'poisonlog.php': 'poisonlog',
      'theftlog.php': 'theftlog',
      'intel.php': 'intel',
      'attacklog.php': 'attacklog',
      'inteldetail.php': 'report'
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
    return null;
  }

  /**
   * One request per page view, fire-and-forget: nothing on the page waits on
   * it or changes because of it, and a failure is only ever a debug line.
   * The server dedupes (by report id where the page links one), so a reload
   * or the same mission seen from both sides never counts twice.
   */
  function sendMissionLog() {
    let body = null;
    try {
      const source = missionLogSource();
      body = source ? buildMissionPayload(source) : null;
    } catch (e) {
      debugLog('📜 Mission log: page not read', e);
      return null;
    }
    if (!body) { debugLog('📜 Mission log: nothing to record on this page'); return null; }
    return Promise.resolve()
      .then(() => auth.apiCall('api/war-room/missions', body))
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
    const re = /has been maxx?ed/i;
    if (!re.test(document.body.textContent || '')) return false;   // the usual page, cheaply
    const list = Object.values(boxes || {});
    for (const el of [document.body, ...document.body.querySelectorAll('*')]) {
      if (list.some((b) => b.contains(el))) continue;
      if (el.closest('[data-kdc], [id^="tdc-"]')) continue;
      const holdsBox = list.some((b) => el.contains(b));
      const text = holdsBox
        ? [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent || '').join(' ')
        : (el.textContent || '');
      if (re.test(text)) return true;
    }
    return false;
  }

  /**
   * Everything the attack page says about this target and about your own
   * standing against it, read from the mission boxes (see above). Returns
   * null when this is not a readable attack page (no target, no boxes — an
   * "Invalid User ID" page, say). Every number the page does not show is
   * null, never 0; the one deliberate 0 is the game's empty "()" brackets,
   * which it prints for a target sabbed down to nothing (see v2.19.1).
   *
   *   sab.limit      the sentry your spy rating can reach ("can sab up to")
   *   recon.limit    same for recon (x3 rather than x1.5)
   *   poison.limit   the antidote your poison rating can reach
   *   theft.limit    the vigilance your theft rating can reach
   *   attack.retreatDa  the DA above which your forces retreat
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

    // The Attack box's first row under its title is the target's name on its
    // own ("Hooplah"). A stats.php link to this id is the fallback — never
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
        rating: num('poison', poisonReach, 1), limit: num('poison', poisonReach, 2)
      },
      theft: {
        attempts: theftTries.used, cap: theftTries.cap, successes: theftWins.used,
        tiv: bracket('theft', /Total Invested Value:?\s*\(([\d,.]*)\)/i),
        maxDaily: bracket('theft', /Maximum Daily Theft loss:?\s*\(([\d,.]*)\)/i),
        lost24h: num('theft', /Total lost from theft in the last 24\s*hours:?\s*(\d[\d,]*(?:\.\d+)?)/i),
        rating: num('theft', theftReach, 1), limit: num('theft', theftReach, 2)
      },
      sab: {
        attempts: sabTries.used, cap: sabTries.cap, successes: sabWins.used,
        tiv: bracket('sab', /Total Invested Value:?\s*\(([\d,.]*)\)/i),
        maxDaily: bracket('sab', /Maximum Daily Sabotage loss:?\s*\(([\d,.]*)\)/i),
        lost24h: num('sab', /Total lost from sabbs in the last 24\s*hours:?\s*(\d[\d,]*(?:\.\d+)?)/i),
        revLost24h: num('sab', /Total lost from revenge sabbs in the last 24\s*hours:?\s*(\d[\d,]*(?:\.\d+)?)/i),
        rating: num('sab', sabReach, 1), limit: num('sab', sabReach, 2)
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
  // target whose vigilance is above your reach fire and fail — the case that
  // started this: four thefts on Lord_Hunaman, vigilance 249,256,356 against a
  // 237,874,638 ceiling, all "Failed", nothing stolen. So under each mission's
  // "can … up to …" line the page now says whether the target is actually in
  // reach: their rating as last recorded in the alliance roster, against the
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
   * changed since" is honest: a reading taken minutes ago is simply right —
   * Lord_Hunaman's 249.3M was 4.8% over and read just before the thefts that
   * failed, so it must say out of range, not maybe. Older than 24h the age
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
    try { player = await auth.apiCall(`players/${page.targetId}`); } catch (e) { player = null; }
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
  // that WAS maxed at some point and one somebody just confirmed — and, later,
  // into members' success rates. Automatic only: there is no mark button, and
  // opening the page is the only thing that records anything.

  const TARGET_CHECK_SENT_KEY = 'KoC_TargetCheckSent';

  /**
   * The check as the server takes it (see utils/target-checks.js). Pure.
   * sab.maxed: the game says so (revenge box up, or the "has been maxxed"
   * refusal), or the losses have reached the cap; null — not false — when the
   * page showed none of that, so an unreadable box never reads as "open".
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
      sab: {
        attempts: page.sab.attempts, cap: page.sab.cap, successes: page.sab.successes,
        lost24h: page.sab.lost24h, maxDaily: page.sab.maxDaily, maxed: sabMaxed
      },
      revenge: {
        available: page.revenge.present,
        attempts: page.revenge.attempts, cap: page.revenge.cap, successes: page.revenge.successes
      },
      theft: {
        attempts: page.theft.attempts, cap: page.theft.cap, successes: page.theft.successes,
        lost24h: page.theft.lost24h, maxDaily: page.theft.maxDaily, maxed: theftMaxed
      },
      poison: { attempts: page.poison.attempts, cap: page.poison.cap, successes: page.poison.successes },
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
      }
    };
  }

  /**
   * What a check says about the target and the member's own counters — the
   * whole payload except the printed limits, which drift by a few points as
   * ratings tick and would make every reload look new.
   */
  function targetCheckKey(payload) {
    const { limits, ...rest } = payload;
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
    const page = parseAttackPage();
    if (!page) return;
    const payload = buildTargetCheckPayload(page);
    const now = Date.now();
    if (targetCheckIsRepeat(SafeStorage.get(TARGET_CHECK_SENT_KEY, {}), payload, now)) {
      debugLog(`🎯 Target check for ${payload.targetId} skipped — same as the one sent under a minute ago`);
      return;
    }
    // Not awaited: the range warnings after this step should not wait on it.
    Promise.resolve(auth.apiCall('api/war-room/checks', payload)).then((res) => {
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
  // Every user-facing feature is declared once in FEATURES (name, plain-English
  // description, where it runs) and executed via the FEATURE_STEPS list in the
  // page dispatcher below. The Settings panel ("⚙ Data Centre" in the sidebar)
  // renders straight from FEATURES, so a feature added there automatically gets
  // a toggle and a description.
  //
  // Toggle state lives in localStorage[FEATURES_KEY] as {featureId: false} —
  // only disabled features are stored and a missing entry means enabled, so new
  // features ship ON and updates never change what existing users see.

  const FEATURES_KEY = "KoC_DataCentre_Features";

  // kind: 'display' = only changes what YOU see; 'sync' = records/shares data
  // with the alliance roster; 'both' = does both.
  const FEATURES = [
    // — Everywhere —
    {
      id: 'server-clock', group: 'Everywhere', kind: 'display',
      name: 'Live Server Time clock',
      desc: 'Makes the Server Time shown on every page tick forward each second instead of staying frozen at the moment the page loaded.'
    },
    {
      id: 'sidebar-calculator', group: 'Everywhere', kind: 'both',
      name: 'Sidebar XP→Turns calculator',
      desc: 'The calculator box under the sidebar: how many attacks your Experience and Attack Turns are worth, projected gold from them, your banked-% pill with trend graph (📈), the ✏️ manual average-gold override, and the SR logo (click it for the feature-settings popup) with the Login/Logout button. Clicking the box title opens a pop-up calculator.',
      note: 'Uses the average gold calibrated by the Attack log enhancer; the banked % also needs Own stats sync (income) and attack-log visits (gold lost). While on, the box quietly uploads throttled banking snapshots (banked %, gold on hand, gold lost, projected income) to the alliance server — not only when you open the graph.'
    },
    {
      id: 'rank-neighbor-links', group: 'Everywhere', kind: 'display',
      name: 'Rank-neighbour recon links',
      desc: 'Turns the "Rating For Previous/Next Rank Gain" numbers into links to the player we believe holds that rank, with a tooltip showing who they are and how fresh our data on them is.'
    },
    {
      id: 'sab-tracker', group: 'Everywhere', kind: 'both',
      name: 'Sabotage Tracker',
      desc: 'On attack pages: sab and revenge-sab attempts left on the target in the rolling 24h window, a countdown until your next slot opens, damage left before the target is maxed, and colour-coded ages on "You last sabbed" timestamps. Quietly records sab missions you fire by hand and reads the target\'s Intelligence file for exact times.',
      note: 'Your log of sab attempts stays in your own browser. What IS sent to the alliance roster is the target\'s two cap numbers from the attack page — "Total lost from sabbs in the last 24hours" and "Maximum Daily Sabotage loss" — so the War Room can show how much of each target\'s daily cap is left.'
    },

    // — Command Centre —
    {
      id: 'top-stats-panel', group: 'Command Centre', kind: 'display',
      name: 'Sweet Revenge Top Stats panel',
      desc: 'The alliance dashboard on your Command Centre: mini leaderboards (TIV, Strike, Spy, Defense and more) built from the shared roster, plus who still has recon attempts left. Each column can be shown or hidden.'
    },
    {
      id: 'base-collector', group: 'Command Centre', kind: 'sync',
      name: 'Own stats sync',
      desc: 'Reads your own Command Centre stats. Most are only cached on your device; what goes to the alliance server is your name, projected income per turn (feeds the banked-% calculator), a last-seen timestamp and your real stat ranks (feeds Stat Hunt).',
      note: 'Your TIV and combat stats sync from the Armory page, not here.'
    },
    {
      id: 'slaying-comp', group: 'Command Centre', kind: 'both',
      name: 'Slaying competitions',
      desc: 'Competition panels on the Command Centre with team leaderboards. Captures your attack missions (Rewards page) and gold stolen (Command Centre) and submits them — along with your current Experience, Turns and Gold — to every running competition, unless you switch that competition\'s tracking off in its panel.',
      note: 'For a submission to count, visit Rewards and then the Command Centre within 30 seconds. Auto-submission runs at most once every 5 minutes per competition; the 📊 Leaderboard button submits fresh stats right away.'
    },

    // — Armory —
    {
      id: 'banking-mode', group: 'Armory', kind: 'display',
      name: 'Banking Mode',
      desc: 'The "Estimated Funds" widget on the Armory: a live projection of your exposed (stealable) gold, colour-coded steal risk with time-to-yellow/red, screen-awake option and last-bank detection. Quietly recalibrates from your sidebar gold, Command Centre and attack log. The widget\'s own ⚙ holds its display settings.'
    },
    {
      id: 'armory-sliders', group: 'Armory', kind: 'display',
      name: 'Armory preference sliders',
      desc: 'Replaces the armory percentage boxes with auto-balancing sliders, plus one-tap presets: Cheapest first, Optimizer (uses alliance data to pick the best stat per gold), All spy, All defense, and your own saved presets.',
      note: 'The "Cheapest first" preset needs Rank-up cost display switched on, and the Optimizer\'s gold budget comes from the sidebar XP calculator (it also asks the alliance server, read-only, for the allocation).'
    },
    {
      id: 'stat-reshuffler', group: 'Armory', kind: 'display',
      name: 'Stat Reshuffler',
      desc: 'The 🔀 Stat Reshuffler banner above the Armory Preferences section opens a what-if calculator: pick weapons (or whole categories) to sell, optionally switch race, and pour the proceeds — plus gold on hand if you tick it — into other stats. Projects the gold recovered, weapons you could buy, your new ratings and your new TIV after the 50% sell tax. Set a Goal (a target rating for one stat) and it also shows the gold still needed to reach it, updating live as you tweak the plan. Pure calculator: it never sells, buys or presses anything.',
      note: 'Most accurate for stats where Purchase check alerts has learned a multiplier; otherwise it derives one from your current rating and weapon strength. Warns when a learned multiplier looks stale (it predates skill upgrades — buy 1 weapon there to refresh it). Weapons your units can\'t carry count as adding nothing — unless you tick "Ignore carrier caps" because you\'ll train units as needed.'
    },
    {
      id: 'rank-up-costs', group: 'Armory', kind: 'display',
      name: 'Rank-up cost display',
      desc: 'Shows how much gold of weapons you would need to buy to claim the next rank in each stat (the "Next Rank Gain" number), using your personal weapon efficiency learned from your own purchases.',
      note: 'Needs Purchase check alerts to have learned a stat\'s weapon multiplier — buy weapons in that stat once to calibrate it. Its numbers also power the armory sliders\' "Cheapest first" preset.'
    },
    {
      id: 'purchase-alerts', group: 'Armory', kind: 'display',
      name: 'Purchase check alerts',
      desc: 'After you buy weapons, checks the "You Purchased..." message: warns when a purchase gained you nothing (no trained soldiers to hold the weapons) and quietly learns your real per-stat weapon multipliers, which keeps the Optimizer and rank-up costs accurate.',
      note: 'Learned multipliers stay on your device. Armory data sync uploads the gold-per-stat efficiency calculated from them — that upload is what the Optimizer preset relies on.'
    },
    {
      id: 'armory-collector', group: 'Armory', kind: 'sync',
      name: 'Armory data sync',
      desc: 'Reads your Armory page and syncs your TIV, all eight stats with timestamps, your real stat ranks and your gold-per-stat efficiency to the alliance roster. Your weapons inventory and spend preferences are only cached on your device.',
      note: 'The Safe page "Attacked Instead" comparison relies on the locally cached weapon distribution and spend preferences.'
    },

    // — Attack & Intel —
    {
      id: 'attack-collectors', group: 'Attack & Intel', kind: 'sync',
      name: 'Attack data capture',
      desc: 'Records TIV sightings from attack pages and your battle reports — gold stolen, hostages, casualties on both sides, and the trained/untrained soldier counts the report shows for you and the target — into the alliance database. This powers everyone\'s target intel.'
    },
    {
      id: 'attack-warnings', group: 'Attack & Intel', kind: 'display',
      name: 'Attack page range warnings',
      desc: 'On attack pages, under each mission\'s "can … up to …" line: whether the target is actually in reach — their sentry (sab), antidote (poison), vigilance (theft) and defensive action (attack) as last recorded in the alliance roster, against the limit the game prints for you — with how old that reading is. ✅ in range, ⚠ borderline (close to your limit and not freshly read), ⛔ out of range (the mission will fail; the game lets it fire anyway), ❔ no reading yet (recon first). Also adds a theft-cap line to the Theft box: how much of the target\'s daily theft cap is left, or THEFT MAXED.',
      note: 'Reads the alliance roster (read-only) for the target\'s last known ratings; nothing is sent. It never blocks or changes the game\'s forms or buttons, and if the roster cannot be reached it shows nothing.'
    },
    {
      id: 'target-checks', group: 'Attack & Intel', kind: 'sync',
      name: 'Target check log',
      desc: 'Every time you open an attack page, records that you checked that target: your name, the target and the time, whether the game showed them maxed, how much of their daily sab and theft caps is used, your own attempt counters for that target (sab, revenge sab, theft, poison, attack, raid, recon) and success counters where the game shows them (sab, revenge sab, theft, poison), and your own Spy, Poison, Theft and Attack ratings with the range limits the game prints for you. The War Room uses it to show which targets were just seen maxed, and by whom, so nobody spends turns on them.',
      note: 'All of that — including your own attempt and success counters for each target you open — is visible to everyone with roster access, and used for members\' success rates. It is recorded only when you open an attack page yourself; the script never fires a mission.'
    },
    {
      id: 'mission-log', group: 'Attack & Intel', kind: 'sync',
      name: 'Mission history',
      desc: 'When you open your Intelligence page, a target\'s Intelligence file, the Poison Log, the Theft Log or the Attack Log, records the missions listed on that page to the alliance roster: your own sab, recon, poison, theft, attack and raid missions with their results (success, aborted, failed, defended — and what was stolen or destroyed), and the missions other players ran against you: who, when, what kind, how many spies, and what they took. Stored with them: the unit losses from the Poison Log; the casualties on both sides, the damage both ways and the hostages from the Attack Log; and the attacker\'s alliance and how many of their spies were caught from the Intelligence page. Any sab report you open is recorded too — not only one you just ran — with the report\'s full text: weapons destroyed, spies and sentries executed, and the gold and XP gained. The War Room turns this into success rates per member and per mission type.',
      note: 'Your success rates, and every mission behind them, are visible to everyone with roster access — as are the missions run against you. Rates are per member and per mission type, never per target. Only the page you open is read: the script never turns a page, opens a report or fetches anything, and these pages are left exactly as the game drew them.'
    },
    {
      id: 'attack-log-enhancer', group: 'Attack & Intel', kind: 'display',
      name: 'Attack log enhancer',
      desc: 'Adds your average gold per attack to the attack log\'s 24-hour summary headers, and quietly notes how much gold attackers stole from you. Both numbers are saved only on your device.',
      note: 'The sidebar calculator, Optimizer preset, Safe-page comparison and Upgrades-page slay estimates all build on the average-gold number. The gold-lost figure feeds the sidebar calculator\'s banked-% trend, which does upload snapshots to the alliance server.'
    },
    {
      id: 'recon-sharing', group: 'Attack & Intel', kind: 'both',
      name: 'Recon sharing',
      desc: 'When you recon someone or view their stats page, quietly shares what you saw (plus your recon-attempts count from the Rewards page) with the alliance database. Opening the War List shares that whole page in one go — everyone\'s sentry, the recommended sab weapon and how many of it they hold, who is on the War List and when (and why) they were added, and your own "My 24hr" sab / poison / theft counters for each player on it. Also fills "???" rows on your recon reports with the alliance\'s last known values.',
      note: 'The "???" backfill on recon reports belongs to this feature, not Recon display extras — turning this off turns that off too. Your War List "My 24hr" counters are stored under your name, are visible to everyone with roster access, and are used for members\' success rates; switching off Target check log does not stop them — switch off this feature for that. On the War List (and Farm List) the script only reads: the game allows scripts no changes there at all, so nothing on those pages is altered, added or styled.'
    },
    {
      id: 'recon-display', group: 'Attack & Intel', kind: 'display',
      name: 'Recon display extras',
      desc: 'Fills "???" values on stats pages from the alliance database, adds the freshness age column to Shared Recon Info, and a "max attacks" row on recon reports.',
      note: 'The matching "???" backfill on recon reports (fresh recon pages) is part of Recon sharing, not this feature.'
    },
    {
      id: 'battlefield-collector', group: 'Attack & Intel', kind: 'sync',
      name: 'Battlefield scanner',
      desc: 'Quietly records every player you scroll past on the battlefield into the alliance roster — name, alliance and rank only. No gold or army numbers are captured.'
    },
    {
      id: 'inactives-collector', group: 'Attack & Intel', kind: 'sync',
      name: 'Inactive Accounts sync',
      desc: 'When you open the in-game Inactive Accounts page, shares the list with the alliance roster: who went into Vacation Mode and exactly when, and who has been deleted. Anyone who has dropped off the list since the last visit is back from vacation. This keeps the dashboard\'s Vacation Watch countdowns exact — the more often someone opens the page, the sooner returns show up. Works while you are logged out too (say, on vacation yourself), using the login saved from your last visit; on that page, logged out, this is the only thing the script does.'
    },

    // — Safe & Upgrades —
    {
      id: 'safe-forecasts', group: 'Safe & Upgrades', kind: 'display',
      name: 'SAFE forecasts',
      desc: 'On the Safe page: how long until your safe reaches 1B / 2B / 5B / 9B / 10B (MAX) at your current deposit rate.'
    },
    {
      id: 'upgrade-timers', group: 'Safe & Upgrades', kind: 'display',
      name: 'Upgrade timers & readiness',
      desc: '"Time to upgrade" and "EXP still needed to be deposited" under every EXP upgrade on the Safe page, and "Upgrade Ready" time and shortfall rows under the gold upgrades on the Upgrades page.',
      note: 'Uses your EXP rate captured on the Upgrades page, your safe deposit rate captured on the Safe page, and the Attack log enhancer\'s average gold for the slay estimate.'
    },
    {
      id: 'attack-alternative', group: 'Safe & Upgrades', kind: 'display',
      name: '"Attacked Instead" comparison',
      desc: 'On the Safe page: what your stats would look like if you traded the tech upgrade\'s EXP for turns and spent the stolen gold on weapons instead, split by your actual spend preferences.',
      note: 'Needs Armory data sync, the Attack log enhancer, and the weapon multipliers learned by Purchase check alerts before it can show numbers.'
    },
    {
      id: 'tech-projector', group: 'Safe & Upgrades', kind: 'display',
      name: 'Tech Level Projector',
      desc: 'Adds a "Project to" dropdown to the tech-upgrade table so you can preview your stats at ANY future tech level, with the total ▲% versus now and the cumulative EXP cost to get there.'
    },

    // — Other pages —
    {
      id: 'training-warnings', group: 'Other pages', kind: 'display',
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

  // Shared feeder steps declare several owners; they run while ANY owner is on.
  function stepEnabled(f) {
    return Array.isArray(f) ? f.some(featureEnabled) : featureEnabled(f);
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

  const FEATURE_KIND_BADGES = {
    display: { text: '🖥 display only', tip: 'Only changes what you see — nothing is recorded or shared.' },
    sync: { text: '📡 alliance sync', tip: 'Records data into the shared alliance roster.' },
    both: { text: '🖥+📡 display + sync', tip: 'Changes what you see AND records data into the shared alliance roster.' }
  };

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

    const badgeInfo = FEATURE_KIND_BADGES[feat.kind] || FEATURE_KIND_BADGES.display;
    const badge = document.createElement('span');
    badge.textContent = badgeInfo.text;
    badge.title = badgeInfo.tip;
    badge.style.cssText = 'margin-left:auto;font-size:10px;color:#8b94a7;white-space:nowrap;';

    top.appendChild(cb);
    top.appendChild(name);
    top.appendChild(badge);
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
    title.innerHTML = '<b style="color:#e8edf5;">⚙ KoC Data Centre — Features</b> <span style="color:#8b94a7;font-size:10px;">v' + escapeHtml(VERSION) + '</span>';
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
    masterLabel.innerHTML = '<b style="color:#e8edf5;">All features</b> <span style="color:#8b94a7;">— master switch</span>';
    masterRow.appendChild(masterCb);
    masterRow.appendChild(masterLabel);
    body.appendChild(masterRow);

    // Feature groups
    const groups = [];
    for (const feat of FEATURES) {
      if (!groups.includes(feat.group)) groups.push(feat.group);
    }
    for (const group of groups) {
      const gh = document.createElement('div');
      gh.textContent = group;
      gh.style.cssText = 'padding:8px 12px 4px 12px;color:#7ea0c9;font-size:10px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;';
      body.appendChild(gh);
      for (const feat of FEATURES) {
        if (feat.group === group) body.appendChild(buildFeatureRow(feat));
      }
    }
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

  window.KoCDataCentre = {
    settings: openFeatureSettings,
    features: () => FEATURES.map(f => ({ id: f.id, name: f.name, enabled: featureEnabled(f.id) }))
  };

  // ==================== PAGE-SPECIFIC INITIALIZERS ====================

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

  // Execution order is behaviour: steps run top-to-bottom exactly as the old
  // per-page dispatcher did (e.g. Banking Mode's armory widget is injected
  // before the roster-API armory steps so it never waits on the network, and
  // competitions are loaded before their capture/panel steps).
  // `f` names the owning FEATURES entry; an array means the step is a shared
  // feeder that runs while ANY of the listed features is enabled.
  const FEATURE_STEPS = [
    { f: 'server-clock', label: 'startServerClock', when: () => true, run: () => startServerClock() },
    // Covert mission reports carry "Sabotage Again!" buttons, so capture everywhere
    { f: 'sab-tracker', label: 'hookSabFormCapture', when: () => true, run: () => hookSabFormCapture() },
    { f: 'slaying-comp', label: 'loadActiveCompetitions', when: () => onPage("base.php") || onPage("rewards.php"), run: async () => {
        const hasComps = await loadActiveCompetitions();
        if (hasComps) {
          debugLog(`✅ Loaded ${activeCompetitions.length} active competitions`);
        }
      } },
    { f: 'sidebar-calculator', label: 'initSidebarCalculator', when: () => onPage("base.php"), run: () => initSidebarCalculator() },
    { f: 'top-stats-panel', label: 'insertTopStatsPanel', when: () => onPage("base.php"), run: () => insertTopStatsPanel() },
    { f: 'base-collector', label: 'collectFromBasePage', when: () => onPage("base.php"), run: () => collectFromBasePage() },
    // Banking Mode: full recalibration (G0 / income / SPM) from the Command Centre
    { f: 'banking-mode', label: 'bankCollectCommandCentre', when: () => onPage("base.php"), run: () => bankCollectCommandCentre() },
    { f: 'slaying-comp', label: 'captureCompetitionStatsOnBase', when: () => onPage("base.php"), run: () => captureCompetitionStatsOnBase() },
    { f: 'sidebar-calculator', label: 'initSidebarCalculator (sidebar)', when: hasSidebar, run: () => initSidebarCalculator() },
    { f: 'sidebar-calculator', label: 'hookSidebarPopup', when: hasSidebar, run: () => hookSidebarPopup() },
    // Banking Mode: opportunistic G0 refresh from the sidebar Gold/Vault cells
    { f: 'banking-mode', label: 'bankCollectSidebarGold', when: hasSidebar, run: () => bankCollectSidebarGold() },
    // No-ops fast on pages without the "Rating For Previous/Next Rank Gain" table
    { f: 'rank-neighbor-links', label: 'enhanceRankNeighborLinks', when: () => true, run: () => enhanceRankNeighborLinks() },
    { f: 'attack-log-enhancer', label: 'enhanceAttackLog', when: () => onPage("attacklog.php"), run: () => enhanceAttackLog() },
    // Banking Mode: cache new "Attacks Against You" steals (keyed by attack_id)
    { f: 'banking-mode', label: 'bankCollectAttackLog', when: () => onPage("attacklog.php"), run: () => bankCollectAttackLog() },
    { f: 'recon-sharing', label: 'collectFromRewardsPage', when: () => onPage("rewards.php"), run: () => collectFromRewardsPage() },
    { f: 'slaying-comp', label: 'captureCompetitionStatsOnRewards', when: () => onPage("rewards.php"), run: () => captureCompetitionStatsOnRewards() },
    { f: 'recon-display', label: 'addMaxAttacksRecon', when: () => onPage("inteldetail.php"), run: () => addMaxAttacksRecon() },
    { f: 'recon-sharing', label: 'collectFromIntelDetailPage', when: () => onPage("inteldetail.php"), run: () => collectFromIntelDetailPage() },
    // Collect visible stats first (before filling ??? from API)
    { f: 'recon-sharing', label: 'collectFromStatsPage', when: () => onPage("stats.php"), run: () => collectFromStatsPage() },
    { f: 'recon-display', label: 'enhanceSharedReconInfoTable', when: () => onPage("stats.php"), run: () => enhanceSharedReconInfoTable() },
    { f: 'recon-display', label: 'fillSharedReconInfoFromAPI', when: () => onPage("stats.php") && !!new URLSearchParams(location.search).get('id'),
      run: () => fillSharedReconInfoFromAPI(new URLSearchParams(location.search).get('id')) },
    { f: 'battlefield-collector', label: 'collectFromBattlefield', when: () => onPage("battlefield.php"), run: () => collectFromBattlefield() },
    // One War List visit refreshes sentry + AAT for the whole list at once.
    // readOnly: the only step allowed to run on the War List (see runFeatures)
    // — it reads the page and never touches it.
    { f: 'recon-sharing', label: 'collectFromWarList', readOnly: true, when: () => onPage("warlist.php"), run: () => collectFromWarList() },
    // The game's own list of who is on vacation, and since exactly when.
    // loggedOut: the one step that also runs without a session (see runFeatures).
    { f: 'inactives-collector', label: 'collectFromInactives', loggedOut: true, when: () => onPage("inactives.php"), run: () => collectFromInactives() },
    { f: 'battlefield-collector', label: 'battlefieldObserver', when: () => onPage("battlefield.php"), run: () => startBattlefieldObserver() },
    { f: 'attack-collectors', label: 'collectTIVFromAttackPage', when: () => onPage("attack.php"), run: () => collectTIVFromAttackPage() },
    { f: 'sab-tracker', label: 'initSabTracker', when: () => onPage("attack.php"), run: () => initSabTracker() },
    // Every attack-page view is logged as a check, the address-less page the
    // game shows after refusing a sab on a maxed target included (fire-and-forget)
    { f: 'target-checks', label: 'sendTargetCheck', when: () => onPage("attack.php"), run: () => sendTargetCheck() },
    // Last on attack.php: the range rows wait on the roster for the target's ratings
    { f: 'attack-warnings', label: 'initAttackWarnings', when: () => onPage("attack.php"), run: () => initAttackWarnings() },
    // Intel file (per-target mission log) backfills the Sab Tracker with exact server times
    { f: 'sab-tracker', label: 'collectFromIntelFilePage', when: () => onPage("intelfile.php"), run: () => collectFromIntelFilePage() },
    // Mission history: the intel file, Intelligence, Poison / Theft / Attack
    // Log and sab-report pages, each read as the member opened it and sent as
    // ONE request. After every other step on those pages (the Sab Tracker's
    // intel-file read, Banking Mode's attack-log read, the recon collector on
    // inteldetail) and not awaited: nothing waits on it.
    { f: 'mission-log', label: 'sendMissionLog', when: () => missionLogSource() !== null, run: () => { sendMissionLog(); } },
    // detail.php also substring-matches inteldetail.php — the attack_id guard is what keeps this attack-only
    { f: 'attack-collectors', label: 'collectAttackLog', when: () => onPage("detail.php") && /attack_id=/.test(location.search), run: async () => {
        collectAttackLog();
        setTimeout(async () => await safeExecute('collectAttackLog (delayed)', () => collectAttackLog()), ATTACK_LOG_DELAY_MS);
      } },
    // Banking Mode first on armory: it only reads the DOM/localStorage, so inject the
    // inline widget promptly rather than making it wait behind the roster-API calls below.
    { f: 'banking-mode', label: 'bankOnArmory', when: () => onPage("armory.php"), run: () => bankOnArmory() },
    { f: 'purchase-alerts', label: 'scrapePurchaseConfirmation', when: () => onPage("armory.php"), run: () => scrapePurchaseConfirmation() },
    // DOM-only UI steps run before the roster-API collector so they never wait on the network
    { f: 'rank-up-costs', label: 'displayRankUpCosts', when: () => onPage("armory.php"), run: () => {
        const stats = collectMilitaryStats();
        const weapons = collectWeaponsFromArmory();
        displayRankUpCosts(stats, calculateWeaponEfficiency(weapons, stats));
      } },
    { f: 'armory-sliders', label: 'enhanceArmoryPrefsUI', when: () => onPage("armory.php"), run: () => enhanceArmoryPrefsUI() },
    { f: 'stat-reshuffler', label: 'initStatReshuffler', when: () => onPage("armory.php"), run: () => initStatReshuffler() },
    { f: 'armory-collector', label: 'collectTIVAndStatsFromArmory', when: () => onPage("armory.php"), run: () => collectTIVAndStatsFromArmory() },
    { f: 'training-warnings', label: 'enhanceTrainingPage', when: () => onPage("training.php"), run: () => enhanceTrainingPage() },
    // Shared feeder: deposit rate powers both SAFE forecasts and the upgrades-page readiness rows
    { f: ['safe-forecasts', 'upgrade-timers'], label: 'collectSafeDepositRate', when: () => onPage("safe.php"), run: () => collectSafeDepositRate() },
    { f: 'safe-forecasts', label: 'addSafeForecasts', when: () => onPage("safe.php"), run: () => addSafeForecasts() },
    { f: 'upgrade-timers', label: 'addExpUpgradeTimeRows', when: () => onPage("safe.php"), run: () => addExpUpgradeTimeRows() },
    { f: 'attack-alternative', label: 'addAttackAlternativeTable', when: () => onPage("safe.php"), run: () => addAttackAlternativeTable() },
    { f: 'tech-projector', label: 'enhanceTechLevelPicker', when: () => onPage("safe.php"), run: () => enhanceTechLevelPicker() },
    { f: 'upgrade-timers', label: 'collectExpPerTurn', when: () => onPage("upgrades.php"), run: () => collectExpPerTurn() },
    { f: 'upgrade-timers', label: 'addUpgradeReadyRows', when: () => onPage("upgrades.php"), run: () => addUpgradeReadyRows() }
  ];

  async function runFeatures() {
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
        // Check for Data Centre redirect first (before running other features)
        const isRedirecting = await handleDataCentreRedirect();

        // Only run features if we're not redirecting
        if (!isRedirecting) {
          await runFeatures();
          debugLog("✅ All features initialized");
        }
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

  // ==================== STYLING ====================

  // Not on read-only pages: even an unused <style> element is a change to the
  // page, and the War List / Farm List must be left exactly as the game drew them.
  if (!READ_ONLY_PAGE) {
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
  }

  // ==================== DEBUG HELPERS ====================

  window.showPlayer = function(id) {
    debugLog("🔍 showPlayer() called with id:", id);
    const map = getNameMap();

    if (!id) {
      debugLog("📊 Full NameMap:", map);
      return map;
    }

    debugLog("📊 Player record:", map[id]);
    return map[id] || null;
  };

  window.showTivLog = function() {
    debugLog("📊 Full TIV log requested");
    const log = getTivLog();
    debugLog("📊 Log:", log);
    return log;
  };

  window.showSabLog = function() {
    const log = getSabLog();
    debugLog("🕵️ Sab log:", log);
    return log;
  };

})();
