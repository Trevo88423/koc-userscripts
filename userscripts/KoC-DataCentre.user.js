// ==UserScript==
// @name         KoC Data Centre
// @namespace    trevo88423
// @version      2.2.3
// @description  Sweet Revenge alliance tool: tracks stats, syncs to API, adds dashboards, XP→Turn calculator, mini Top Stats panel. v2.1.0: Integrated slaying competition tracker (attack missions & gold stolen tracking, team competitions, leaderboards). v2.0.0: Optimized API architecture, previous versions deprecated. v1.47.0-1.47.1: Added weapon multiplier auto-learning, improved armory auto-fill with 3% buffer, training page warnings.
// @author       Blackheart
// @match        https://www.kingsofchaos.com/*
// @exclude      https://*.kingsofchaos.com/confirm.login.php*
// @exclude      https://*.kingsofchaos.com/confirm.login.php
// @exclude      https://*.kingsofchaos.com/security.php*
// @exclude      https://*.kingsofchaos.com/error.php*
// @exclude      https://*.kingsofchaos.com/recruit.php*
// @exclude      https://*.kingsofchaos.com/farmlist.php*
// @exclude      https://*.kingsofchaos.com/warlist.php*
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
  // Don't run on login/security pages or when logged out
  if (location.pathname.includes("login.php") ||
      location.pathname.includes("security.php") ||
      !document.querySelector("a[href='logout.php']")) {
    console.log("❌ DataCentre disabled (security page or not logged in)");
    return;
  }

  // ==================== SCRIPT MANAGER CHECK ====================
  // Check if this script is enabled in Script Manager
  if (window.KoC_ScriptManager && !window.KoC_ScriptManager.isEnabled('data-centre')) {
    console.log("❌ DataCentre disabled by Script Manager");
    return;
  }

  // ==================== VERSION CHECK ====================
  // Check if this script version is allowed to run
  const SCRIPT_NAME = 'koc-data-centre';
  const SCRIPT_VERSION = '2.2.2'; // Must match @version above
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

        // Stop script execution
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
    debugLog(...args);
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

      // Determine if EDT (UTC-4) or EST (UTC-5) applies
      // US DST: 2nd Sunday in March to 1st Sunday in November
      function isEasternDST(year, month, day) {
        // Get 2nd Sunday in March
        const marchFirst = new Date(year, 2, 1);
        const marchFirstDay = marchFirst.getDay();
        const dstStart = 8 + (7 - marchFirstDay) % 7;

        // Get 1st Sunday in November
        const novFirst = new Date(year, 10, 1);
        const novFirstDay = novFirst.getDay();
        const dstEnd = 1 + (7 - novFirstDay) % 7;

        const currentDate = new Date(year, month, day);
        const startDate = new Date(year, 2, dstStart);
        const endDate = new Date(year, 10, dstEnd);

        return currentDate >= startDate && currentDate < endDate;
      }

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

      // Determine if EDT (UTC-4) or EST (UTC-5) applies
      // US DST: 2nd Sunday in March to 1st Sunday in November
      function isEasternDST(year, month, day) {
        // Get 2nd Sunday in March
        const marchFirst = new Date(year, 2, 1);
        const marchFirstDay = marchFirst.getDay();
        const dstStart = 8 + (7 - marchFirstDay) % 7;

        // Get 1st Sunday in November
        const novFirst = new Date(year, 10, 1);
        const novFirstDay = novFirst.getDay();
        const dstEnd = 1 + (7 - novFirstDay) % 7;

        const currentDate = new Date(year, month, day);
        const startDate = new Date(year, 2, dstStart);
        const endDate = new Date(year, 10, dstEnd);

        return currentDate >= startDate && currentDate < endDate;
      }

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

      // Add animation
      const style = document.createElement('style');
      style.textContent = `
        @keyframes slideIn {
          from { transform: translateX(400px); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
      `;
      document.head.appendChild(style);
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

          if (!resp.ok) throw new Error("Refresh failed " + resp.status);

          const data = await resp.json();
          const token = data.token || data.accessToken;
          this.saveAuth(token, stored.id, stored.name);
          debugLog("🔄 Token refreshed successfully");
          return true;
        } catch (err) {
          console.warn("⚠️ Auto refresh failed:", err);
          this.clearAuth();
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

        // Look specifically for the "Name" row in the User Info table
        const nameRow = [...document.querySelectorAll("tr")]
          .find(tr => tr.textContent.includes("Name"));

        if (nameRow) {
          const link = nameRow.querySelector("a[href*='stats.php?id=']");
          if (link) {
            id = link.href.match(/id=(\d+)/)?.[1];
            name = link.textContent.trim();
          }
        }

        // Fallback: first stats.php link
        if (!id || !name) {
          const link = document.querySelector("a[href*='stats.php?id=']");
          if (link) {
            id = link.href.match(/id=(\d+)/)?.[1];
            name = link.textContent.trim();
          }
        }

        // Final fallback: localStorage
        if (!id) id = SafeStorage.get("KoC_MyId", null);
        if (!name) name = SafeStorage.get("KoC_MyName", null);

        if (!id || !name) {
          throw new Error("Could not detect your KoC ID/Name on this page");
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
        <tr><td align="center" style="color:black;">Avg Gold/Atk <a href="attacklog.php" id="xp-gold-link" style="color:black;"><span id="xp-gold">0</span></a></td></tr>
        <tr><td align="center" style="color:black;">Total Potential Gold <span id="xp-total">0</span></td></tr>
        <tr><td align="center" style="color:black;">Banked <span id="xp-banked">—</span></td></tr>
        <tr>
          <td align="center">
            <img src="https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/images/SR_Logo.png"
                 alt="Sweet Revenge"
                 style="max-width:110px; height:auto; margin-top:6px; display:block; margin-left:auto; margin-right:auto;">
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
      return parseInt(parts[1].replace(/[(),]/g, ""), 10) || 0;
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

                  // Save avg gold for Sidebar + Popup
                  if (txt.startsWith('Total By You Last 24 Hours')) {
                    SafeStorage.set('xpTool_avgGold', avg);
                    SafeStorage.set('xpTool_avgGold_time', Date.now());
                    debugLog("[XPTool] Avg Gold/Atk saved:", avg);
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
      const now = getKoCServerTimeUTC();

      rows.forEach(row => {
        const id = row.getAttribute("user_id");
        if (collectedPlayers.has(id)) return;

        const cells = row.querySelectorAll("td");

        // Build player object - ONLY alliance, name, id, rank (no timestamps - DB doesn't have those columns)
        const player = sanitizePlayerData({
          id,
          name: cells[2]?.innerText.trim() || "Unknown",
          alliance: cells[1]?.innerText.trim() || "",
          rank: cells[7]?.innerText.trim() || ""
        });

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

  // ==================== ATTACK TIV COLLECTOR ====================

  async function collectTIVFromAttackPage() {
    const idMatch = location.search.match(/id=(\d+)/);

    // Check for Invalid User ID error
    if (document.body.textContent.includes("Invalid User ID")) {
      if (idMatch) {
        const id = idMatch[1];
        console.warn(`⚠️ Invalid User ID detected for player ${id} - marking as deleted`);
        await auth.apiCall(`players/${id}/mark-inactive`, {
          status: "deleted",
          error: "Invalid User ID"
        });
      }
      return;
    }

    const tivMatch = document.body.textContent.match(/Total Invested Value:\s*\(([\d,]+)\)/i);
    if (!idMatch || !tivMatch) return;

    const id = idMatch[1];
    const tiv = parseInt(tivMatch[1].replace(/,/g, ""), 10);
    const now = getKoCServerTimeUTC();

    // TIV on attack.php IS fresh data - it loads when you visit the page
    // It's used to calculate sabotage limits, so it must be current
    // Save locally
    const log = getTivLog();
    log.push({ id, tiv, time: now });
    saveTivLog(log);

    updatePlayerInfo(id, { tiv, lastTivTime: now });

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

      // Extract rank number from "#117" format
      const rankMatch = rankText?.match(/#(\d+)/);
      const rank = rankMatch ? parseInt(rankMatch[1], 10) : null;

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

  // ==================== BASE PAGE COLLECTOR ====================

  function collectFromBasePage() {
    let myId = SafeStorage.get("KoC_MyId", null);
    let myName = SafeStorage.get("KoC_MyName", null);

    // ALWAYS use authenticated user's name from JWT token (most reliable)
    const authData = auth.getStoredAuth();
    if (authData && authData.name) {
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

  function collectFromRewardsPage() {
    // Extract "Unsuccessful Recons" from "Actions against you" table
    const rows = [...document.querySelectorAll("tr")];

    for (const row of rows) {
      const cells = row.querySelectorAll("td");
      if (cells.length >= 2) {
        const firstCell = cells[0]?.textContent.trim();

        // Look for "Unsuccessful Recons" row
        if (firstCell && firstCell.includes("Unsuccessful Recons")) {
          const secondCell = cells[1]?.textContent.trim();

          // Extract the number (e.g., "2508/1000" or "999/1000")
          const match = secondCell?.match(/^(\d+)\/(\d+)/);
          if (match) {
            const current = parseInt(match[1], 10);
            const max = parseInt(match[2], 10);

            // Only track if player has recons to clear (current < max)
            if (current < max) {
              const remaining = max - current;
              const myId = SafeStorage.get("KoC_MyId", "self");
              const myName = SafeStorage.get("KoC_MyName", "Me");

              // Store recon tracking data
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
            } else {
              // Player has cleared recons - remove tracking
              const myId = SafeStorage.get("KoC_MyId", "self");
              SafeStorage.remove(`reconTrack_${myId}`);
              debugLog("✅ Recons cleared - removed tracking");
            }

            break;
          }
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

    // Fetch recon tracking data from localStorage
    function getReconTracking() {
      const reconPlayers = [];
      const keys = Object.keys(localStorage);

      for (const key of keys) {
        if (key.startsWith("reconTrack_")) {
          try {
            const data = JSON.parse(localStorage.getItem(key));
            reconPlayers.push({
              id: data.id,
              rank: 0, // Will be set after sorting
              name: data.name,
              value: data.reconsRemaining.toLocaleString(),
              rawValue: data.reconsRemaining
            });
          } catch (err) {
            console.warn("Failed to parse recon data:", key, err);
          }
        }
      }

      // Sort by most recons remaining (descending)
      reconPlayers.sort((a, b) => b.rawValue - a.rawValue);

      // Assign ranks
      reconPlayers.forEach((p, i) => {
        p.rank = i + 1;
      });

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

    // Header with toggles and debug mode button
    const header = document.createElement("div");
    header.style.cssText = "margin-bottom:8px; color:gold; font-size:12px; font-weight:bold;";

    const debugIcon = DebugMode.isEnabled() ? "🐛" : "🔇";
    const debugTitle = DebugMode.isEnabled() ? "Debug ON (click to disable)" : "Debug OFF (click to enable)";

    header.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <span>Sweet Revenge Stats</span>
        <button id="koc-debug-toggle"
                title="${debugTitle}"
                style="cursor:pointer; background:#333; color:#ccc; border:1px solid #555; border-radius:3px; padding:2px 6px; font-size:10px;">
          ${debugIcon} Debug
        </button>
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

    // Generate all tables
    const allTables = [];
    statDefs.forEach(def => {
      // Use custom data source for recons
      const rows = def.custom && def.key === "recons"
        ? getReconTracking()
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

    // Add debug mode toggle event listener
    const debugToggleBtn = header.querySelector("#koc-debug-toggle");
    if (debugToggleBtn) {
      debugToggleBtn.addEventListener("click", () => {
        DebugMode.toggle();
        location.reload(); // Reload to update UI
      });
    }

    // Build cell
    cell.appendChild(header);
    cell.appendChild(tablesContainer);

    infoRow.parentNode.insertBefore(container, infoRow.nextSibling);
  }

  // ==================== RANK-UP COST DISPLAY ====================

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

    // Find the rank progression table - try multiple selectors
    const tables = [...document.querySelectorAll('table')];
    const rankTable = tables.find(table => {
      const header = table.querySelector('th');
      if (!header) return false;

      const headerText = header.textContent.trim();
      // Try multiple variations of the header text
      return headerText.includes('Rating For Previous/Next Rank Gain') ||
             headerText.includes('Rating For') ||
             headerText.includes('Previous/Next Rank') ||
             headerText.includes('Next Rank Gain');
    });

    if (!rankTable) {
      debugLog('⚠️ displayRankUpCosts: Could not find rank progression table');
      debugLog('Available table headers:', tables.map(t => t.querySelector('th')?.textContent.trim()).filter(Boolean));
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

  function addAutoFillButton() {
    // Find the armory preferences form
    const attackInput = document.querySelector('input[name="prefs[attack]"]');

    if (!attackInput) {
      debugLog('⚠️ Could not find armory preferences form - button not added');
      return;
    }

    const form = attackInput.closest('form');
    if (!form) {
      debugLog('⚠️ Could not find form container - button not added');
      return;
    }

    // Find insertion point - look for submit button
    const submitButton = form.querySelector('input[type="submit"]');
    let insertionPoint = submitButton?.closest('td') || submitButton?.parentElement;

    // Create button
    const autoFillBtn = document.createElement('button');
    autoFillBtn.type = 'button'; // Important: don't submit form
    autoFillBtn.textContent = '⚡ Auto-Fill (Cheapest First)';
    autoFillBtn.title = 'Automatically fill preferences based on cheapest rank upgrades first';
    autoFillBtn.style.cssText = `
      padding: 8px 16px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 4px;
      font-weight: bold;
      cursor: pointer;
      font-size: 14px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.2);
      transition: all 0.2s ease;
      margin-left: 10px;
    `;

    // Add hover effect
    autoFillBtn.addEventListener('mouseenter', () => {
      autoFillBtn.style.transform = 'scale(1.05)';
      autoFillBtn.style.boxShadow = '0 4px 8px rgba(0,0,0,0.3)';
    });

    autoFillBtn.addEventListener('mouseleave', () => {
      autoFillBtn.style.transform = 'scale(1)';
      autoFillBtn.style.boxShadow = '0 2px 4px rgba(0,0,0,0.2)';
    });

    // Add click handler
    autoFillBtn.addEventListener('click', () => {
      debugLog('🎯 Auto-fill button clicked');
      autoFillBtn.disabled = true;
      autoFillBtn.textContent = '⏳ Calculating...';

      try {
        autoFillArmoryPreferences();
      } catch (error) {
        debugLog('❌ Error during auto-fill:', error);
        showAutoFillMessage(`❌ Error: ${error.message}`, 'error');
      } finally {
        setTimeout(() => {
          autoFillBtn.disabled = false;
          autoFillBtn.textContent = '⚡ Auto-Fill (Cheapest First)';
        }, 500);
      }
    });

    // Insert button into form
    if (insertionPoint) {
      insertionPoint.appendChild(autoFillBtn);
      debugLog('✅ Auto-fill button added to armory form');
    } else {
      // Fallback: create a new row in the table
      const formTable = form.querySelector('table');
      if (formTable) {
        const lastRow = formTable.querySelector('tr:last-child');
        if (lastRow) {
          const buttonCell = lastRow.querySelector('td');
          if (buttonCell) {
            buttonCell.appendChild(autoFillBtn);
            debugLog('✅ Auto-fill button added to armory form (table row)');
          }
        }
      }
    }
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
    const tiv = tivCell ? parseInt(tivCell.textContent.replace(/,/g, "").trim(), 10) : 0;

    // Military Stats - use centralized parser
    const stats = collectMilitaryStats();

    // === WEAPONS INVENTORY COLLECTION ===
    const weapons = collectWeaponsFromArmory();

    // === CALCULATE GOLD-PER-POINT EFFICIENCY ===
    const efficiency = calculateWeaponEfficiency(weapons, stats);

    // === DISPLAY RANK-UP COSTS ===
    displayRankUpCosts(stats, efficiency);

    // === ADD AUTO-FILL BUTTON ===
    addAutoFillButton();

    const now = getKoCServerTimeUTC();

    // Save to TIV log
    if (tiv) {
      const log = getTivLog();
      log.push({ id: myId, tiv, time: now });
      saveTivLog(log);

      // Send TIV to API
      await auth.apiCall("tiv", { playerId: myId, tiv, time: now });
    }

    // Extract only real ranks from stats for API submission
    const realRanks = {
      attackRank: stats.attackRank,
      defenseRank: stats.defenseRank,
      spyRank: stats.spyRank,
      sentryRank: stats.sentryRank
    };

    // Send ONLY TIV and real ranks to API (no stats, weapons, or efficiency)
    const payload = {
      name: myName,
      tiv,
      ...realRanks,
      lastTivTime: now
    };

    // Save to localStorage (skip updatePlayerInfo to avoid duplicate API call)
    const map = getNameMap();
    map[myId] = { ...map[myId], ...sanitizePlayerData(payload) };
    saveNameMap(map);

    await auth.apiCall("players", { id: myId, ...payload });

    debugLog("📊 Armory data sent to API", { id: myId, name: myName, tiv, ...realRanks });
    debugLog("📊 Local stats captured for UI", { stats, weapons: weapons.length, efficiency });
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

          // Cell 1 is ignored (has unrelated values)

          // Cell 2 contains the QUANTITY
          const quantityText = cells[2]?.textContent.trim() || '';
          const quantity = parseInt(quantityText.replace(/,/g, ''), 10) || 0;

          // Cell 3 contains the STRENGTH (format: "1,000 / 1,000")
          const strengthText = cells[3]?.textContent.trim() || '';
          const strengthMatch = strengthText.match(/([\d,]+)\s*\/\s*([\d,]+)/);
          const minStrength = strengthMatch ? parseInt(strengthMatch[1].replace(/,/g, ''), 10) : 0;
          const maxStrength = strengthMatch ? parseInt(strengthMatch[2].replace(/,/g, ''), 10) : 0;

          // No longer need totalStrength - we calculate it from quantity × strength
          const totalStrength = quantity * maxStrength;

          if (weaponName && quantity > 0) {
            weapons.push({
              name: weaponName,
              category: category,
              quantity: quantity,
              minStrength: minStrength,
              maxStrength: maxStrength,
              totalStrength: totalStrength  // Use game's pre-calculated total
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

    // Find rows in tables with specific labels
    const rows = document.querySelectorAll('table.table_lines tr, table tr');

    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      if (cells.length < 2) return;

      const label = cells[0].textContent.trim().toLowerCase();
      const valueText = cells[1].textContent.trim();

      // Skip ??? values
      if (valueText === '???' || valueText === 'Unknown' || !valueText) return;

      const value = parseInt(valueText.replace(/,/g, ''), 10) || 0;

      // Match labels (case-insensitive, flexible)
      if (label.includes('trained attack soldiers') && !label.includes('merc')) {
        soldierData.trainedAttackSoldiers = value;
      }
      else if (label.includes('trained attack mercenaries')) {
        soldierData.trainedAttackMercenaries = value;
      }
      else if (label.includes('trained defense soldiers') && !label.includes('merc')) {
        soldierData.trainedDefenseSoldiers = value;
      }
      else if (label.includes('trained defense mercenaries')) {
        soldierData.trainedDefenseMercenaries = value;
      }
      else if (label.includes('untrained soldiers') && !label.includes('merc')) {
        soldierData.untrainedSoldiers = value;
      }
      else if (label.includes('untrained mercenaries')) {
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
   * Tries multiple insertion strategies
   */
  function insertWarningBox(warningBox) {
    if (!warningBox) return;

    // Strategy 1: Insert after the first table on the training page
    const firstTable = document.querySelector('table.table_lines');
    if (firstTable && firstTable.parentNode) {
      firstTable.parentNode.insertBefore(warningBox, firstTable.nextSibling);
      debugLog('[TrainingWarnings] Warning box inserted after first table');
      return;
    }

    // Strategy 2: Insert at the top of the main content area
    const contentCell = document.querySelector('td.content_cell');
    if (contentCell) {
      contentCell.insertBefore(warningBox, contentCell.firstChild);
      debugLog('[TrainingWarnings] Warning box inserted at top of content cell');
      return;
    }

    // Strategy 3: Insert after any header with "Training" text
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

          // Determine DST offset
          function isEasternDST(year, month, day) {
            const marchFirst = new Date(year, 2, 1);
            const marchFirstDay = marchFirst.getDay();
            const dstStart = 8 + (7 - marchFirstDay) % 7;

            const novFirst = new Date(year, 10, 1);
            const novFirstDay = novFirst.getDay();
            const dstEnd = 1 + (7 - novFirstDay) % 7;

            const currentDate = new Date(year, month, day);
            const startDate = new Date(year, 2, dstStart);
            const endDate = new Date(year, 10, dstEnd);

            return currentDate >= startDate && currentDate < endDate;
          }

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

  function parseSharedReconInfo() {
    const sharedRecon = {};

    try {
      // Find "Shared Recon Info" header
      const header = [...document.querySelectorAll("th, td")]
        .find(el => el.textContent.includes("Shared Recon Info"));

      if (!header) return sharedRecon;

      const table = header.closest("table");
      if (!table) return sharedRecon;

      // Parse each row in the table
      const rows = table.querySelectorAll("tr");
      rows.forEach(row => {
        const cells = row.querySelectorAll("td");

        // Debug: Log all rows to see TBG structure (COMMENTED OUT - too verbose)
        // const cellTexts = Array.from(cells).map(c => c.innerText.trim());
        // debugLog(`🔍 Row with ${cells.length} cells: [${cellTexts.join(' | ')}]`);

        // Check for TBG row FIRST (might have different structure)
        // TBG row might be: "TBG | 19,281,848 Gold (in 1 min) | ..." in a single cell or multiple cells
        if (cells.length >= 1) {
          const firstCellText = cells[0]?.innerText.trim().toLowerCase() || "";

          // Check if this is the TBG row
          if (firstCellText.includes("tbg")) {
            debugLog(`🔍 Found TBG row! Cell 0: "${cells[0]?.innerText.trim()}"`);

            // Try to parse from first cell (might contain entire TBG string)
            const cellText = cells[0]?.innerText.trim() || "";
            const match = cellText.match(/([0-9,]+)\s+Gold\s+\(in 1 min\)/i);
            if (match) {
              const goldPerMin = match[1];
              // Use previous row's timestamp if available (Last Recon timestamp)
              sharedRecon.projectedIncome = { value: goldPerMin, time: null };
              debugLog(`✅ Parsed TBG from first cell: ${goldPerMin} gold/min`);
              return; // Skip rest of processing for this row
            }

            // Try to parse from second cell
            if (cells.length >= 2) {
              const cellText = cells[1]?.innerText.trim() || "";
              const match = cellText.match(/([0-9,]+)\s+Gold\s+\(in 1 min\)/i);
              if (match) {
                const goldPerMin = match[1];
                sharedRecon.projectedIncome = { value: goldPerMin, time: null };
                debugLog(`✅ Parsed TBG from second cell: ${goldPerMin} gold/min`);
                return;
              }
            }

            debugLog(`⚠️ TBG row found but couldn't parse gold value`);
            return;
          }
        }

        if (cells.length < 3) return;

        const statName = cells[0]?.innerText.trim().toLowerCase();
        const statValue = cells[1]?.innerText.trim();
        const timestamp = cells[2]?.innerText.trim();

        if (!statName || !statValue || !timestamp) return;

        // Convert timestamp from "2025-10-13 06:36:06" (KoC Server Time = US Eastern) to UTC ISO format
        let isoTimestamp = null;
        try {
          // Parse as local time, then convert to UTC
          // KoC Server Time is US Eastern (EDT/EST)
          // EDT = UTC-4 (spring-fall), EST = UTC-5 (winter)

          // Parse the timestamp parts
          const parts = timestamp.match(/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
          if (parts) {
            const year = parseInt(parts[1]);
            const month = parseInt(parts[2]) - 1; // JS months are 0-indexed
            const day = parseInt(parts[3]);
            const hour = parseInt(parts[4]);
            const minute = parseInt(parts[5]);
            const second = parseInt(parts[6]);

            // Determine if EDT (UTC-4) or EST (UTC-5) applies
            // US DST: 2nd Sunday in March to 1st Sunday in November
            function isEasternDST(year, month, day) {
              // Get 2nd Sunday in March
              const marchFirst = new Date(year, 2, 1); // March is month 2
              const marchFirstDay = marchFirst.getDay();
              const dstStart = 8 + (7 - marchFirstDay) % 7; // 2nd Sunday

              // Get 1st Sunday in November
              const novFirst = new Date(year, 10, 1); // November is month 10
              const novFirstDay = novFirst.getDay();
              const dstEnd = 1 + (7 - novFirstDay) % 7; // 1st Sunday

              const currentDate = new Date(year, month, day);
              const startDate = new Date(year, 2, dstStart);
              const endDate = new Date(year, 10, dstEnd);

              return currentDate >= startDate && currentDate < endDate;
            }

            const isDST = isEasternDST(year, month, day);
            const offset = isDST ? 4 : 5; // EDT = UTC-4, EST = UTC-5

            // Create date object in Eastern Time, then convert to UTC by adding offset
            const date = new Date(Date.UTC(year, month, day, hour + offset, minute, second));

            isoTimestamp = date.toISOString();
            debugLog(`🕐 Converted KoC Server Time "${timestamp}" (${isDST ? 'EDT' : 'EST'}) to UTC: ${isoTimestamp}`);
          }
        } catch (e) {
          console.warn("⚠️ Failed to parse timestamp:", timestamp, e);
          isoTimestamp = null;
        }

        // Map stat names to our field names
        if (statName.includes("strike action")) {
          sharedRecon.strikeAction = { value: statValue, time: isoTimestamp };
        } else if (statName.includes("defensive action")) {
          sharedRecon.defensiveAction = { value: statValue, time: isoTimestamp };
        } else if (statName.includes("spy rating")) {
          sharedRecon.spyRating = { value: statValue, time: isoTimestamp };
        } else if (statName.includes("sentry rating")) {
          sharedRecon.sentryRating = { value: statValue, time: isoTimestamp };
        } else if (statName.includes("poison rating")) {
          sharedRecon.poisonRating = { value: statValue, time: isoTimestamp };
        } else if (statName.includes("antidote rating")) {
          sharedRecon.antidoteRating = { value: statValue, time: isoTimestamp };
        } else if (statName.includes("theft rating")) {
          sharedRecon.theftRating = { value: statValue, time: isoTimestamp };
        } else if (statName.includes("vigilance rating")) {
          sharedRecon.vigilanceRating = { value: statValue, time: isoTimestamp };
        }
        // Note: TBG is now handled earlier in the function (before the cells.length < 3 check)
      });

      debugLog("📡 Parsed Shared Recon Info:", sharedRecon);
    } catch (err) {
      console.warn("⚠️ Failed to parse Shared Recon Info:", err);
    }

    return sharedRecon;
  }

  function grabStat(id, key, cell, sharedReconData = {}) {
    const val = cell?.innerText.trim();
    const prev = getNameMap()[id] || {};

    // PRIORITY 1: Check if we have Shared Recon Info data (always prefer this - it's alliance-shared and timestamped)
    // This prevents corrupted partial values from main table when full values exist in Shared Recon
    const sharedData = sharedReconData[key];
    if (sharedData && sharedData.value && sharedData.time) {
      debugLog(`✅ Using shared recon for ${key}: ${sharedData.value} (${sharedData.time})`);
      return { value: sharedData.value, time: sharedData.time };
    }

    // PRIORITY 2: Use main table value (accept any value including low numbers like 0, 1, 2)
    // Low values are legitimate for new players or after being attacked
    if (val && val !== "???") {
      debugLog(`✅ Using main table for ${key}: ${val}`);
      return { value: val, time: getKoCServerTimeUTC() };
    }

    // PRIORITY 3: When recon shows "???" and no shared data available
    // DON'T return cached values to API - the cached values will still be used by UI enhancement
    // But we shouldn't send potentially stale/bad data to the API
    debugLog(`ℹ️ No valid data for ${key} (main table: "${val || 'empty'}", shared recon: none)`);
    return { value: "???", time: null };
  }

  async function collectFromReconPage() {
    // Get player ID - different method for inteldetail.php vs stats.php
    let id = null;

    if (location.pathname.includes("inteldetail.php")) {
      // On inteldetail.php, URL has report_id, not player id
      // Search for first stats.php link (works because there's only one player shown)
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
    } else {
      // On stats.php, use URL parameter to avoid grabbing commander ID
      const urlParams = new URLSearchParams(window.location.search);
      id = urlParams.get('id');

      if (!id) {
        debugLog("⚠️ Recon: Could not find player ID in URL");
        return;
      }
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

    // === COLLECT 8 STATS FROM SHARED RECON INFO TABLE ===
    const sharedReconData = parseSharedReconInfo();

    // Map shared recon data to stats object
    const statFields = [
      'strikeAction', 'defensiveAction', 'spyRating', 'sentryRating',
      'poisonRating', 'antidoteRating', 'theftRating', 'vigilanceRating'
    ];

    for (const field of statFields) {
      const sharedData = sharedReconData[field];
      if (sharedData && sharedData.value && sharedData.time) {
        // Parse value (remove commas)
        const value = parseInt(sharedData.value.replace(/,/g, ''), 10);
        if (!isNaN(value)) {
          stats[field] = value;
          stats[`${field}Time`] = sharedData.time;
        }
      }
    }

    // Count collected stats
    const statCount = Object.keys(stats).filter(key => !key.endsWith('Time') && key !== 'name' && key !== 'rank' && key !== 'race').length;

    if (statCount === 0 && !stats.name && !stats.rank && !stats.race) {
      debugLog(`ℹ️ No data collected for player ${id} - page may not have Shared Recon Info`);
      return;
    }

    // Save to localStorage and send to API
    updatePlayerInfo(id, stats);
    debugLog(`📊 Stats page collected for ${id}: ${statCount} combat stats, name: ${stats.name || 'N/A'}, rank: ${stats.rank || 'N/A'}, race: ${stats.race || 'N/A'}`);

    // Enhance UI with fresh stats
    enhanceReconUI(id, stats).catch(err => console.warn("enhanceReconUI failed:", err));
  }

  // Fill Shared Recon Info table with data from API for "???" values
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

  // Update Shared Recon Info table cells with our fresh collected data
  function updateSharedReconInfoWithFreshData(stats) {
    try {
      // Find "Shared Recon Info" table
      const header = [...document.querySelectorAll("th, td")]
        .find(el => el.textContent.includes("Shared Recon Info"));

      if (!header) return;

      const table = header.closest("table");
      if (!table) return;

      // Map our stat keys to the display names in the table
      const statMapping = {
        strikeAction: "strike action",
        defensiveAction: "defensive action",
        spyRating: "spy rating",
        sentryRating: "sentry rating",
        poisonRating: "poison rating",
        antidoteRating: "antidote rating",
        theftRating: "theft rating",
        vigilanceRating: "vigilance rating"
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

        // Find matching stat in our collected data
        for (const [key, displayName] of Object.entries(statMapping)) {
          if (statName.includes(displayName)) {
            const ourValue = stats[key];
            const ourTime = stats[key + "Time"];

            // If shared recon shows "???" but we have a value, replace it
            if (currentValue === "???" && ourValue && ourValue !== "???") {
              // Update value cell
              cells[1].innerText = ourValue;
              cells[1].style.color = "#6f6"; // Green for fresh

              // Update timestamp cell if we have one
              if (ourTime && timestampCell) {
                const date = new Date(ourTime);
                // Format as "2025-10-13 07:30:00" (KoC Server Time format)
                const formatted = date.toISOString().slice(0, 19).replace('T', ' ');
                timestampCell.innerText = formatted;
                timestampCell.style.color = "#6f6"; // Green for fresh
              }

              updatedCount++;
            }
            break;
          }
        }
      });

      if (updatedCount > 0) {
        debugLog(`✅ Updated ${updatedCount} "???" values in Shared Recon Info with fresh data`);
      }
    } catch (err) {
      console.warn("⚠️ Failed to update Shared Recon Info table:", err);
    }
  }

  // ==================== RECON UI ENHANCER ====================

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

      // Format large numbers with commas (e.g., 53019083823 → "53,019,083,823")
      let displayValue = cachedValue;
      if (typeof cachedValue === 'number' && cachedValue >= 1000) {
        displayValue = cachedValue.toLocaleString('en-US');
      }

      cell.innerHTML = `
        <div style="float:left;color:#FBC;font-size:0.8em;" title="${escapeHtml(abs)} • from cache">
          ${escapeHtml(rel)}
        </div>
        <div title="${escapeHtml(abs)} • from cache">${escapeHtml(displayValue)}</div>
      `;
    }
  }

  async function enhanceReconUI(id, freshStats = null) {
    let prev = {};

    // If we have fresh stats from collection, use them first (they include Shared Recon data with timestamps)
    if (freshStats && Object.keys(freshStats).length > 0) {
      // Merge fresh stats with any existing cached data
      const map = getNameMap();
      const cached = map[id] || {};
      prev = { ...cached, ...freshStats };
      debugLog("✅ Using fresh stats from collection for UI enhancement:", freshStats);
    } else {
      // Otherwise fetch from API
      try {
        const token = await auth.getToken();
        if (token) {
          const resp = await fetch(`${API_URL}/players/${id}`, {
            headers: {
              "Authorization": "Bearer " + token,
              "X-Script-Name": SCRIPT_NAME,
              "X-Script-Version": SCRIPT_VERSION
            }
          });
          if (resp.ok) {
            prev = await resp.json();
            debugLog("🌐 Recon fallback loaded from API:", prev);
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
    }

    // === FILL MILITARY STATS ===
    const ms = getTableByHeader("Military Stats")?.querySelectorAll("tr");
    if (!ms) return;

    fillMissingReconValue(ms?.[1]?.cells[1], prev.strikeAction, prev.strikeActionTime);
    fillMissingReconValue(ms?.[2]?.cells[1], prev.defensiveAction, prev.defensiveActionTime);
    fillMissingReconValue(ms?.[3]?.cells[1], prev.spyRating, prev.spyRatingTime);
    fillMissingReconValue(ms?.[4]?.cells[1], prev.sentryRating, prev.sentryRatingTime);
    fillMissingReconValue(ms?.[5]?.cells[1], prev.poisonRating, prev.poisonRatingTime);
    fillMissingReconValue(ms?.[6]?.cells[1], prev.antidoteRating, prev.antidoteRatingTime);
    fillMissingReconValue(ms?.[7]?.cells[1], prev.theftRating, prev.theftRatingTime);
    fillMissingReconValue(ms?.[8]?.cells[1], prev.vigilanceRating, prev.vigilanceRatingTime);
    fillMissingReconValue(ms?.[10]?.cells[1], prev.covertSkill, prev.covertSkillTime);
    fillMissingReconValue(ms?.[11]?.cells[1], prev.sentrySkill, prev.sentrySkillTime);
    fillMissingReconValue(ms?.[12]?.cells[1], prev.siegeTechnology, prev.siegeTechnologyTime);
    fillMissingReconValue(ms?.[13]?.cells[1], prev.toxicInfusionLevel, prev.toxicInfusionLevelTime);
    fillMissingReconValue(ms?.[14]?.cells[1], prev.viperbaneLevel, prev.viperbaneLevelTime);
    fillMissingReconValue(ms?.[15]?.cells[1], prev.shadowmeldLevel, prev.shadowmeldLevelTime);
    fillMissingReconValue(ms?.[16]?.cells[1], prev.sentinelVigilLevel, prev.sentinelVigilLevelTime);

    // Fill economy/technology (use parsed fields if available)
    if (prev.economyLevel && prev.goldPerTurn) {
      const economyValue = `${prev.economyLevel} ( ${prev.goldPerTurn} gold per turn)`;
      fillMissingReconValue(ms?.[17]?.cells[1], economyValue, prev.economyLevelTime);
    } else {
      fillMissingReconValue(ms?.[17]?.cells[1], prev.economy, prev.economyTime);
    }

    if (prev.technologyLevel && prev.technologyMultiplier) {
      const technologyValue = `${prev.technologyLevel} (x ${prev.technologyMultiplier})`;
      fillMissingReconValue(ms?.[18]?.cells[1], technologyValue, prev.technologyLevelTime);
    } else {
      fillMissingReconValue(ms?.[18]?.cells[1], prev.technology, prev.technologyTime);
    }

    fillMissingReconValue(ms?.[19]?.cells[1], prev.experiencePerTurn, prev.experiencePerTurnTime);
    fillMissingReconValue(ms?.[20]?.cells[1], prev.soldiersPerTurn, prev.soldiersPerTurnTime);
    fillMissingReconValue(ms?.[22]?.cells[1], prev.attackTurns, prev.attackTurnsTime);
    fillMissingReconValue(ms?.[23]?.cells[1], prev.experience, prev.experienceTime);

    // === FILL ARMY BREAKDOWN ===
    const armyTable = getTableByHeader("Army Breakdown");
    if (armyTable) {
      const armyRows = armyTable.querySelectorAll("tr");
      fillMissingReconValue(armyRows?.[5]?.cells[1], prev.attackSoldiers, prev.attackSoldiersTime);
      fillMissingReconValue(armyRows?.[6]?.cells[1], prev.attackMercenaries, prev.attackMercenariesTime);
      fillMissingReconValue(armyRows?.[7]?.cells[1], prev.defenseSoldiers, prev.defenseSoldiersTime);
      fillMissingReconValue(armyRows?.[8]?.cells[1], prev.defenseMercenaries, prev.defenseMercenariesTime);
      fillMissingReconValue(armyRows?.[9]?.cells[1], prev.covertSpies, prev.covertSpiesTime);
      fillMissingReconValue(armyRows?.[10]?.cells[1], prev.sentries, prev.sentriesTime);
      fillMissingReconValue(armyRows?.[11]?.cells[1], prev.venomweavers, prev.venomweaversTime);
      fillMissingReconValue(armyRows?.[12]?.cells[1], prev.serpentwardens, prev.serpentwardensTime);
      fillMissingReconValue(armyRows?.[13]?.cells[1], prev.thieves, prev.thievesTime);
      fillMissingReconValue(armyRows?.[14]?.cells[1], prev.rangers, prev.rangersTime);
      fillMissingReconValue(armyRows?.[15]?.cells[1], prev.hostageTotal, prev.hostageTotalTime);
      fillMissingReconValue(armyRows?.[16]?.cells[1], prev.hostageDeaths, prev.hostageDeathsTime);
      fillMissingReconValue(armyRows?.[17]?.cells[1], prev.untrained, prev.untrainedTime);
      fillMissingReconValue(armyRows?.[18]?.cells[1], prev.untrainedMercenaries, prev.untrainedMercenariesTime);
    }

    // === SHOW WEAPONS CACHE INFO ===
    const weaponsTable = getTableByHeader("Weapons");
    if (weaponsTable && prev.weapons) {
      try {
        const cachedWeapons = JSON.parse(prev.weapons);
        const weaponsAge = prev.weaponsTime ? reconTimeAgo(prev.weaponsTime) : "unknown";

        // Check if weapons table has lots of ???
        const weaponRows = Array.from(weaponsTable.querySelectorAll("tr")).slice(2);
        const emptyCount = weaponRows.filter(row => row.innerText.includes("???")).length;

        if (emptyCount > 3 && cachedWeapons.length > 0) {
          // Show cached weapon count
          const tbody = weaponsTable.querySelector("tbody");
          const cacheNotice = document.createElement("tr");
          cacheNotice.style.backgroundColor = "#222";
          cacheNotice.innerHTML = `
            <td colspan="4" style="text-align:center; padding:8px; color:#FBC; font-size:0.9em;">
              <div>📦 ${cachedWeapons.length} cached weapon${cachedWeapons.length !== 1 ? 's' : ''} from ${weaponsAge}</div>
              <div style="font-size:0.8em; color:#999; margin-top:4px;">
                <a href="#" onclick="console.table(${escapeHtml(prev.weapons)}); return false;" style="color:#9cf;">
                  View in console
                </a>
              </div>
            </td>
          `;
          tbody.appendChild(cacheNotice);
          debugLog(`📦 Cached weapons (${weaponsAge}):`, cachedWeapons);
        }
      } catch (e) {
        console.warn("Failed to parse cached weapons", e);
      }
    }
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

  // ==================== BUTTON INJECTION ====================

  function addButtons() {
    // Only inject if logged in
    if (!document.querySelector("a[href='logout.php']")) return;

    const infoRow = document.querySelector("a[href='info.php']")?.closest("tr");
    if (!infoRow) {
      setTimeout(addButtons, PAGE_LOAD_DELAY_MS);
      return;
    }

    // Don't clear the row - competition panel needs it
  }

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

  async function runFeatures() {
    // Load active competitions first (shared across base.php and rewards.php)
    const isBaseOrRewards = location.pathname.includes("base.php") || location.pathname.includes("rewards.php");
    if (isBaseOrRewards) {
      await safeExecute('loadActiveCompetitions', async () => {
        const hasComps = await loadActiveCompetitions();
        if (hasComps) {
          debugLog(`✅ Loaded ${activeCompetitions.length} active competitions`);
        }
      });
    }

    // Command Center (base.php)
    if (location.pathname.includes("base.php")) {
      await safeExecute('addButtons', () => addButtons());
      await safeExecute('initSidebarCalculator', () => initSidebarCalculator());
      await safeExecute('insertTopStatsPanel', () => insertTopStatsPanel());
      await safeExecute('collectFromBasePage', () => collectFromBasePage());

      // Competition tracking: capture gold stolen and add UI panels
      if (activeCompetitions.length > 0) {
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

        // Add competition panels to base.php
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
    }

    // Any page with sidebar (menu_cell)
    if (document.querySelector("td.menu_cell")) {
      await safeExecute('initSidebarCalculator', () => initSidebarCalculator());
      await safeExecute('hookSidebarPopup', () => hookSidebarPopup());
    }

    // Attack log
    if (location.pathname.includes("attacklog.php")) {
      await safeExecute('enhanceAttackLog', () => enhanceAttackLog());
    }

    // Rewards page (track recons)
    if (location.pathname.includes("rewards.php")) {
      await safeExecute('collectFromRewardsPage', () => collectFromRewardsPage());

      // Competition tracking: capture attack missions
      if (activeCompetitions.length > 0) {
        const attackMissions = extractAttackMissions();
        if (attackMissions !== null) {
          const now = Date.now();
          // Update stats for ALL active competitions
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
    }

    // Recon detail & Stats pages
    if (location.pathname.includes("inteldetail.php") || location.pathname.includes("stats.php")) {
      if (location.pathname.includes("inteldetail.php")) {
        await safeExecute('addMaxAttacksRecon', () => addMaxAttacksRecon());
      }
      await safeExecute('collectFromReconPage', () => collectFromReconPage());
      // Enhance Shared Recon Info table with age column on stats pages
      if (location.pathname.includes("stats.php")) {
        await safeExecute('enhanceSharedReconInfoTable', () => enhanceSharedReconInfoTable());
        // Fill missing ??? values from API
        const playerId = new URLSearchParams(location.search).get('id');
        if (playerId) {
          await safeExecute('fillSharedReconInfoFromAPI', () => fillSharedReconInfoFromAPI(playerId));
        }
      }
    }

    // Battlefield
    if (location.pathname.includes("battlefield.php")) {
      await safeExecute('collectFromBattlefield', () => collectFromBattlefield());
      await safeExecute('battlefieldObserver', () => {
        const table = document.querySelector("table.battlefield") || document.querySelector("table.table_lines");
        if (table) {
          // Debounce the collector to prevent excessive calls during rapid DOM updates
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
      });
    }

    // Attack page
    if (location.pathname.includes("attack.php")) {
      await safeExecute('collectTIVFromAttackPage', () => collectTIVFromAttackPage());
    }

    // Attack detail
    if (location.pathname.includes("detail.php") && /attack_id=/.test(location.search)) {
      await safeExecute('collectAttackLog', async () => {
        collectAttackLog();
        setTimeout(async () => await safeExecute('collectAttackLog (delayed)', () => collectAttackLog()), ATTACK_LOG_DELAY_MS);
      });
    }

    // Armory
    if (location.pathname.includes("armory.php")) {
      // Check for weapon purchases first (auto-learns multipliers)
      await safeExecute('scrapePurchaseConfirmation', () => scrapePurchaseConfirmation());
      await safeExecute('collectTIVAndStatsFromArmory', () => collectTIVAndStatsFromArmory());
    }

    // Training
    if (location.pathname.includes("training.php")) {
      await safeExecute('enhanceTrainingPage', () => enhanceTrainingPage());
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

})();
