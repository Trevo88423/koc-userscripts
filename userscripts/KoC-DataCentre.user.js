// ==UserScript==
// @name         KoC Data Centre
// @namespace    trevo88423
// @version      1.42.0
// @description  Sweet Revenge alliance tool: tracks stats, syncs to API, adds dashboards, XP→Turn calculator, mini Top Stats panel, comprehensive recon data collection, Shared Recon Info parsing, KoC Server Time synchronization, and stats.php collection. NEW: Login/Logout button in sidebar for easy auth refresh!
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

  // ==================== VERSION CHECK ====================
  // Check if this script version is allowed to run
  const SCRIPT_NAME = 'koc-data-centre';
  const SCRIPT_VERSION = '1.42.0'; // Must match @version above
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
      const authData = {
        token,
        id,
        name,
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
        box.innerHTML = `
          <h2>🔒 KoC Data Centre Login</h2>
          <p>You must log in with SR to enable the script.</p>
          <button id="srLoginBtn" style="padding:6px 12px;cursor:pointer;">Login to SR</button>
          <button id="srShowTokenBtn" style="padding:6px 12px;margin-left:10px;cursor:pointer;">Show Token</button>
        `;
        document.body.prepend(box);

        document.getElementById("srLoginBtn").addEventListener("click", () => auth.login());
        document.getElementById("srShowTokenBtn").addEventListener("click", () => auth.showToken());
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
            <a href="stats.php?id=datacentre">
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
      const goldUpdates = [];

      rows.forEach(row => {
        const id = row.getAttribute("user_id");
        if (collectedPlayers.has(id)) return;

        const cells = row.querySelectorAll("td");
        const treasuryText = cells[5]?.innerText.trim() || "";
        const { gold, ageMinutes } = parseGoldWithAge(treasuryText);

        const player = sanitizePlayerData({
          id,
          name: cells[2]?.innerText.trim() || "Unknown",
          alliance: cells[1]?.innerText.trim() || "",
          army: cells[3]?.innerText.trim() || "",
          race: cells[4]?.innerText.trim() || "",
          treasury: gold,
          recon: cells[6]?.innerText.trim() || "",
          rank: cells[7]?.innerText.trim() || ""
        });

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
        debugLog(`[DataCentre] Captured ${newCount} new players from battlefield`);
      }

      // Send bulk gold updates to API
      if (goldUpdates.length > 0) {
        debugLog(`[DataCentre] Sending ${goldUpdates.length} gold updates to API`);
        await auth.apiCall("battlefield/bulk-gold-update", { updates: goldUpdates });
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
    const now = getKoCServerTimeUTC();

    table.querySelectorAll("tr").forEach(row => {
      const cells = row.querySelectorAll("td");
      if (cells.length < 2) return;

      const label = cells[0].innerText.trim().toLowerCase();
      const value = cells[1].innerText.trim();

      if (label.startsWith("strike")) {
        stats.strikeAction = value;
        stats.strikeActionTime = now;
      }
      if (label.startsWith("defense")) {
        stats.defensiveAction = value;
        stats.defensiveActionTime = now;
      }
      if (label.startsWith("spy")) {
        stats.spyRating = value;
        stats.spyRatingTime = now;
      }
      if (label.startsWith("sentry")) {
        stats.sentryRating = value;
        stats.sentryRatingTime = now;
      }
      if (label.startsWith("poison")) {
        stats.poisonRating = value;
        stats.poisonRatingTime = now;
      }
      if (label.startsWith("antidote")) {
        stats.antidoteRating = value;
        stats.antidoteRatingTime = now;
      }
      if (label.startsWith("theft")) {
        stats.theftRating = value;
        stats.theftRatingTime = now;
      }
      if (label.startsWith("vigilance")) {
        stats.vigilanceRating = value;
        stats.vigilanceRatingTime = now;
      }
    });

    return stats;
  }

  // ==================== BASE PAGE COLLECTOR ====================

  function collectFromBasePage() {
    let myId = SafeStorage.get("KoC_MyId", null);
    let myName = SafeStorage.get("KoC_MyName", null);

    // Capture my ID/Name if missing
    const myLink = document.querySelector("a[href*='stats.php?id=']");
    if (myLink) {
      myId = myLink.href.match(/id=(\d+)/)?.[1] || myId || "self";
      myName = myLink.textContent.trim() || myName || "Me";

      // FIX: If scraped name is "Me" (viewing own page), use authenticated user's name from token
      if (myName === "Me") {
        const authData = auth.getStoredAuth();
        if (authData && authData.name) {
          myName = authData.name;
          debugLog("📊 Replaced 'Me' with authenticated name:", myName);
        }
      }

      SafeStorage.set("KoC_MyId", myId);
      SafeStorage.set("KoC_MyName", myName);
      debugLog("📊 Stored my KoC ID/Name:", myId, myName);
    }

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

    const payload = {
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
      lastSeen: getKoCServerTimeUTC()
    };

    // Save locally
    updatePlayerInfo(myId, payload);
    debugLog("📊 Base.php self stats captured", payload);

    // Push to API
    auth.apiCall("players", { id: myId, ...payload });
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
        const resp = await fetch(`${API_URL}/players`, {
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
      players = Object.values(getNameMap());
    }

    // Only Sweet Revenge
    players = players.filter(p => p.alliance === "Sweet Revenge");

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

      // Format gold amount
      const formatGold = (gold) => {
        if (gold >= 1e9) return (gold / 1e9).toFixed(1) + 'B';
        if (gold >= 1e6) return (gold / 1e6).toFixed(1) + 'M';
        if (gold >= 1e3) return (gold / 1e3).toFixed(1) + 'K';
        return gold.toFixed(0);
      };

      const goldFormatted = formatGold(goldNeeded);

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
      costSpan.textContent = `(${goldFormatted})`;
      costSpan.title = tooltipText;

      cells[2].appendChild(costSpan);
      processedCount++;
      debugLog(`✅ ${actionText}: Added cost display (${goldFormatted})`);
    });

    debugLog(`✅ displayRankUpCosts: Processed ${processedCount} rank cost displays`);
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

    const now = getKoCServerTimeUTC();

    // Save to TIV log
    if (tiv) {
      const log = getTivLog();
      log.push({ id: myId, tiv, time: now });
      saveTivLog(log);

      // Send TIV to API
      await auth.apiCall("tiv", { playerId: myId, tiv, time: now });
    }

    // Transform weapons array to match API schema
    const weaponsForAPI = weapons.map(w => ({
      weapon_name: w.name,
      weapon_type: w.category,
      quantity: w.quantity,
      current_strength: w.minStrength,
      max_strength: w.maxStrength
    }));

    // Merge into NameMap + API push
    const payload = {
      name: myName,
      tiv,
      ...stats,
      weapons: weaponsForAPI.length > 0 ? weaponsForAPI : undefined,
      weaponsTime: weapons.length > 0 ? now : undefined,
      ...efficiency, // Add gold-per-point metrics
      lastTivTime: now,
      lastRecon: now
    };

    updatePlayerInfo(myId, payload);

    // Send self stats to API
    await auth.apiCall("players", { id: myId, ...payload });

    debugLog("📊 Armory self stats captured", { id: myId, name: myName, tiv, weapons: weapons.length, ...stats });
  }

  function calculateWeaponEfficiency(weapons, stats) {
    // Weapon purchase prices (from armory buying table)
    const weaponPrices = {
      // Attack weapons
      'Sarumans Ball': 100,
      'Heavy Steed': 50000,
      'Chariot': 450000,
      'Blackpowder Missile': 1000000,

      // Defense weapons
      'Spider': 5000,
      'Mithril': 50000,
      'Ebony Platemail': 450000,
      'Invisibility Shield': 1000000,

      // Spy Tools
      'Cloak': 140000,
      'Grappling Hook': 250000,
      'Skeleton Key': 600000,
      'Nunchaku': 1000000,

      // Sentry Tools
      'Horn': 140000,
      'Tripwire': 250000,
      'Guard Dog': 600000,
      'Lookout Tower': 1000000,

      // Poison Tools
      'Toxic Needle Dagger': 140000,
      'Venomfang Staff': 250000,
      'Blightbane Bow': 600000,
      'Plaguebringer Scythe': 1000000,

      // Antidote Tools
      'Viperfang Dirk': 140000,
      'Basiliskbane Halberd': 250000,
      'Wyrmclaw Longsword': 600000,
      'Serpentbane Arbalest': 1000000,

      // Theft Tools
      'Greasy Gloves': 140000,
      'Rusty Lockpick': 250000,
      'Shadow Cloak': 600000,
      'Ethereal Grasp': 1000000,

      // Vigilance Tools
      'Wooden Whistle': 140000,
      'Steel Shackles': 250000,
      'Silver Scepter': 600000,
      'Adamantine Bastion': 1000000
    };

    // Calculate total gold invested per category
    const categoryGold = {
      attack: 0,
      defense: 0,
      spy: 0,
      sentry: 0,
      poison: 0,
      antidote: 0,
      theft: 0,
      vigilance: 0
    };

    weapons.forEach(weapon => {
      const price = weaponPrices[weapon.name];
      if (!price) {
        console.warn(`⚠️ No price found for weapon: "${weapon.name}"`);
        return;
      }

      const category = weapon.category;
      if (!(category in categoryGold)) {
        console.warn(`⚠️ Unknown category: ${category}`);
        return;
      }

      const goldInvested = weapon.quantity * price;
      categoryGold[category] += goldInvested;
    });

    // Parse stat values (remove commas and convert to numbers)
    const parseStatValue = (val) => {
      if (!val) return 0;
      return parseInt(String(val).replace(/,/g, ''), 10) || 0;
    };

    const statValues = {
      attack: parseStatValue(stats.strikeAction),
      defense: parseStatValue(stats.defensiveAction),
      spy: parseStatValue(stats.spyRating),
      sentry: parseStatValue(stats.sentryRating),
      poison: parseStatValue(stats.poisonRating),
      antidote: parseStatValue(stats.antidoteRating),
      theft: parseStatValue(stats.theftRating),
      vigilance: parseStatValue(stats.vigilanceRating)
    };

    // Calculate gold-per-point: totalGoldInvested ÷ currentStatValue
    const efficiency = {};
    for (const category in categoryGold) {
      const gold = categoryGold[category];
      const statValue = statValues[category];

      if (gold > 0 && statValue > 0) {
        const goldPerPoint = gold / statValue;
        efficiency[`goldPer${category.charAt(0).toUpperCase() + category.slice(1)}Point`] =
          Math.round(goldPerPoint * 1000) / 1000; // Round to 3 decimals
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

    // Parse Shared Recon Info table first (alliance-shared recon data)
    const sharedReconData = parseSharedReconInfo();

    const ms = getTableByHeader("Military Stats")?.querySelectorAll("tr");
    const treasury = getTableByHeader("Treasury")?.querySelectorAll("tr");
    const armyTable = getTableByHeader("Army Breakdown")?.querySelectorAll("tr");

    // Validate that we have the essential tables with enough rows
    // Military Stats should have at least 9 rows (header + 8 combat stats)
    if (!ms || ms.length < 9) {
      debugLog(`⚠️ Recon page for player ${id} missing Military Stats table or has insufficient data (found ${ms?.length || 0} rows, need 9+)`);
      // Still allow collection if we have Treasury or Army data from Shared Recon
      if (!treasury && !armyTable && !sharedReconData) {
        debugLog(`⚠️ No valid data tables found for player ${id}, aborting collection`);
        return;
      }
    }

    const stats = {};
    const now = getKoCServerTimeUTC();

    function set(key, row) {
      const { value, time } = grabStat(id, key, row?.cells[1], sharedReconData);
      // Don't save "???" values - this would overwrite cached data with no value
      // The UI enhancement will still show cached values for "???" cells
      if (value !== "???") {
        stats[key] = value;
        if (time) stats[key + "Time"] = time;
      }
    }

    // === MILITARY STATS (Ratings) ===
    set("strikeAction", ms?.[1]);
    set("defensiveAction", ms?.[2]);
    set("spyRating", ms?.[3]);
    set("sentryRating", ms?.[4]);
    set("poisonRating", ms?.[5]);
    set("antidoteRating", ms?.[6]);
    set("theftRating", ms?.[7]);
    set("vigilanceRating", ms?.[8]);

    // === MILITARY STATS (Upgrade Levels) ===
    set("covertSkill", ms?.[10]);
    set("sentrySkill", ms?.[11]);
    set("siegeTechnology", ms?.[12]);
    set("toxicInfusionLevel", ms?.[13]);
    set("viperbaneLevel", ms?.[14]);
    set("shadowmeldLevel", ms?.[15]);
    set("sentinelVigilLevel", ms?.[16]);

    // === ECONOMY & TECHNOLOGY (Enhanced Parsing) ===
    // Parse economy: "Industrial ( 9,536,800 gold per turn)"
    if (ms?.[17]?.cells[1]) {
      const economyText = ms[17].cells[1].innerText;
      const economyMatch = economyText.match(/^([^(]+)\(\s*([0-9,]+)\s*gold per turn\)/);
      if (economyMatch) {
        stats.economyLevel = economyMatch[1].trim();
        stats.economyLevelTime = now;
        stats.goldPerTurn = economyMatch[2];
        stats.goldPerTurnTime = now;
      } else {
        // Fallback to old behavior
        set("economy", ms?.[17]);
      }
    }

    // Parse technology: "Assembly Line (x 7.04)"
    if (ms?.[18]?.cells[1]) {
      const technologyText = ms[18].cells[1].innerText;
      const technologyMatch = technologyText.match(/^([^(]+)\(x\s*([0-9.]+)\)/);
      if (technologyMatch) {
        stats.technologyLevel = technologyMatch[1].trim();
        stats.technologyLevelTime = now;
        stats.technologyMultiplier = technologyMatch[2];
        stats.technologyMultiplierTime = now;
      } else {
        // Fallback to old behavior
        set("technology", ms?.[18]);
      }
    }

    set("experiencePerTurn", ms?.[19]);
    set("soldiersPerTurn", ms?.[20]);
    set("attackTurns", ms?.[22]);
    set("experience", ms?.[23]);

    // === ARMY BREAKDOWN ===
    if (armyTable) {
      set("attackSoldiers", armyTable?.[5]);
      set("attackMercenaries", armyTable?.[6]);
      set("defenseSoldiers", armyTable?.[7]);
      set("defenseMercenaries", armyTable?.[8]);
      set("covertSpies", armyTable?.[9]);
      set("sentries", armyTable?.[10]);
      set("venomweavers", armyTable?.[11]);
      set("serpentwardens", armyTable?.[12]);
      set("thieves", armyTable?.[13]);
      set("rangers", armyTable?.[14]);
      set("hostageTotal", armyTable?.[15]);
      set("hostageDeaths", armyTable?.[16]);
      set("untrained", armyTable?.[17]);
      set("untrainedMercenaries", armyTable?.[18]);
    }

    // === TREASURY ===
    if (treasury) {
      stats.treasury = treasury[1]?.cells[0]?.innerText.split(" ")[0];
      stats.treasuryTime = now;

      // Parse Projected Income (1 min only) - MUST contain "(in 1 min)" to be valid
      const projectedIncomeText = treasury[3]?.innerText || "";
      // Format: "13,292,958 Gold (in 1 min) | 199,394,370 Gold (in 15 mins) | 398,788,740 Gold (in 30 mins)"

      const match1min = projectedIncomeText.match(/([0-9,]+)\s*Gold\s*\(in 1 min\)/);

      if (match1min) {
        stats.projectedIncome = match1min[1];
        stats.projectedIncomeTime = now;
      } else if (sharedReconData.projectedIncome) {
        // Fallback to Shared Recon Info TBG if direct recon is unavailable
        stats.projectedIncome = sharedReconData.projectedIncome.value;
        stats.projectedIncomeTime = sharedReconData.projectedIncome.time;
        debugLog(`✅ Using shared recon TBG for projectedIncome: ${stats.projectedIncome} at ${stats.projectedIncomeTime}`);
      }
      // REMOVED: Dangerous fallback that could grab wrong row data
      // Only set projectedIncome if we have a confirmed "(in 1 min)" match
    }

    // === WEAPONS INVENTORY ===
    const weaponsTable = getTableByHeader("Weapons");
    if (weaponsTable) {
      const weaponRows = Array.from(weaponsTable.querySelectorAll("tr")).slice(2); // Skip header rows
      const weapons = [];

      weaponRows.forEach(row => {
        const cells = row.querySelectorAll("td");
        if (cells.length >= 4) {
          const name = cells[0]?.innerText.trim();
          const type = cells[1]?.innerText.trim();
          const quantity = cells[2]?.innerText.trim();
          const strength = cells[3]?.innerText.trim();

          // Only add if we have name and quantity (and quantity is not ???)
          if (name && quantity && quantity !== "???") {
            // Parse strength (format: "998.78/1,000" or "1,000/1,000")
            let currentStrength = null;
            let maxStrength = null;

            if (strength && strength !== "???") {
              const strengthMatch = strength.match(/([0-9.,]+)\/([0-9,]+)/);
              if (strengthMatch) {
                currentStrength = strengthMatch[1].replace(/,/g, '');
                maxStrength = strengthMatch[2].replace(/,/g, '');
              }
            }

            weapons.push({
              name: name,
              type: type === "???" ? null : type,
              quantity: quantity.replace(/,/g, ''),
              currentStrength: currentStrength,
              maxStrength: maxStrength
            });
          }
        }
      });

      if (weapons.length > 0) {
        stats.weapons = JSON.stringify(weapons);
        stats.weaponsTime = now;
        debugLog(`📦 Captured ${weapons.length} weapons from recon`);
      }
    }

    // Count how many fields we successfully scraped (not "???")
    const fieldCount = Object.keys(stats).filter(key =>
      !key.endsWith('Time') && stats[key] !== "???"
    ).length;

    // Save to localStorage and send to API (updatePlayerInfo handles both)
    updatePlayerInfo(id, stats);
    debugLog(`📊 Recon data saved (${fieldCount} fields):`, stats);

    if (stats.tiv) {
      await auth.apiCall("tiv", { playerId: id, tiv: stats.tiv, time: stats.tivTime });
    }

    // Send gold update to battlefield tracker (fresh recon = age 0)
    if (stats.treasury && stats.treasury !== "???") {
      const goldValue = parseInt(stats.treasury.replace(/,/g, ''), 10);
      if (!isNaN(goldValue)) {
        await auth.apiCall("battlefield/gold-update", {
          playerId: id,
          gold: goldValue,
          ageMinutes: 0,
          source: "recon"
        });
      }
    }

    // Update Shared Recon Info table with our fresh data
    if (location.pathname.includes("stats.php")) {
      updateSharedReconInfoWithFreshData(stats);
      // Also try to fill in any remaining "???" from API
      fillSharedReconInfoFromAPI(id);
    }

    // Enhance UI with fresh stats we just collected
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

            // If shared recon shows "???" but we have API data, replace it
            if (currentValue === "???" && apiValue && apiTime) {
              // Update value cell
              cells[1].innerText = apiValue.toLocaleString();
              cells[1].style.color = "#99f"; // Blue for API data (not fresh recon)

              // Update timestamp cell
              const date = new Date(apiTime);
              // Format as "2025-10-13 07:30:00" (KoC Server Time format)
              const formatted = date.toISOString().slice(0, 19).replace('T', ' ');
              timestampCell.innerText = formatted;
              timestampCell.style.color = "#99f"; // Blue for API data

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
    // Command Center (base.php)
    if (location.pathname.includes("base.php")) {
      await safeExecute('addButtons', () => addButtons());
      await safeExecute('initSidebarCalculator', () => initSidebarCalculator());
      await safeExecute('insertTopStatsPanel', () => insertTopStatsPanel());
      await safeExecute('collectFromBasePage', () => collectFromBasePage());
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
      await safeExecute('collectTIVAndStatsFromArmory', () => collectTIVAndStatsFromArmory());
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
