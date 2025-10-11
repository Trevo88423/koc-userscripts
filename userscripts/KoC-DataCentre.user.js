// ==UserScript==
// @name         KoC Data Centre
// @namespace    trevo88423
// @version      1.18.4
// @description  Sweet Revenge alliance tool: tracks stats, syncs to API, adds dashboards, XP→Turn calculator, mini Top Stats panel, and comprehensive recon data collection.
// @author       Blackheart
// @match        https://www.kingsofchaos.com/*
// @icon         https://www.kingsofchaos.com/favicon.ico
// @grant        none
// @updateURL    https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js
// @downloadURL  https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js
// ==/UserScript==

(function() {
  'use strict';

  // ==================== SECURITY CHECK ====================
  // Don't run on login/security pages or when logged out
  if (location.pathname.includes("login.php") ||
      location.pathname.includes("security.php") ||
      !document.querySelector("a[href='logout.php']")) {
    console.log("❌ DataCentre disabled (security page or not logged in)");
    return;
  }

  // ==================== CONSTANTS ====================

  // Version & API
  const VERSION = (typeof GM_info !== "undefined" && GM_info.script && GM_info.script.version)
    ? GM_info.script.version : "dev";
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

  console.log(`✅ DataCentre+XPTool v${VERSION} loaded on`, location.pathname);

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
          console.log(`${prefix} 🔍`, message, logData);
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
    const num = parseFloat(value);

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
          console.log("🔒 No stored auth found");
          return false;
        }

        // Check if still valid
        if (Date.now() < stored.expiry) {
          this.token = stored.token;
          this.authData = stored;
          console.log("✅ Using cached token for:", stored.id, stored.name);
          return true;
        }

        // Try to refresh
        console.log("🔄 Token expired, attempting refresh for:", stored.id, stored.name);
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
          console.log("🔄 Token refreshed successfully");
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

        console.log("🔍 Attempting login with:", { id, name });

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
      console.log("📜 Full token object:", auth);
    }

    // Make authenticated API call with auto-retry
    async apiCall(endpoint, data, retries = RETRY_ATTEMPTS) {
      const token = await this.getToken();

      if (!token) {
        console.warn("⚠️ No valid token for API call");
        return null;
      }

      console.log(`🌐 API call → ${endpoint}`, data);

      for (let attempt = 1; attempt <= retries; attempt++) {
        try {
          const resp = await fetch(`${API_URL}/${endpoint}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": "Bearer " + token
            },
            body: JSON.stringify(data)
          });

          // Handle 401 - token expired
          if (resp.status === 401 && attempt === 1) {
            console.log("🔄 Token expired (401), refreshing...");
            const refreshed = await this.initialize();
            if (refreshed) {
              continue; // Retry with new token
            } else {
              throw new Error("Token refresh failed");
            }
          }

          const json = await resp.json().catch(() => ({ error: "Invalid JSON" }));
          console.log(`🌐 API response from ${endpoint}:`, json);
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

  // ==================== STORAGE HELPERS ====================

  function getTivLog() {
    return SafeStorage.get(TIV_KEY, []);
  }

  function saveTivLog(arr) {
    return SafeStorage.set(TIV_KEY, arr);
  }

  function getNameMap() {
    return SafeStorage.get(MAP_KEY, {});
  }

  function saveNameMap(map) {
    return SafeStorage.set(MAP_KEY, map);
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

    console.log("✅ Authenticated with SR, initializing features...");
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

    // Merge and save
    const updated = { ...prev, ...cleanPatch, lastSeen: new Date().toISOString() };
    map[id] = updated;
    saveNameMap(map);

    // Send to API if changed
    if (JSON.stringify(prev) !== JSON.stringify(updated)) {
      const apiPayload = {};
      for (const [k, v] of Object.entries(updated)) {
        if (v !== "Unknown" && v !== "" && v != null) {
          apiPayload[k] = v;
        }
      }
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
    console.log("[XPTool] initSidebarCalculator called");
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
    console.log("[XPTool] Sidebar box inserted into page");
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

      console.log('[Calculator] Validated input:', validation.values, '→ Output:', { maxAttacks, potGold });
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
    console.log("[XPTool] enhanceAttackLog called");

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
                    console.log("[XPTool] Avg Gold/Atk saved:", avg);
                  }
                }
              }

              // Gold Lost (On You) for Banking Efficiency
              if (txt.startsWith('Total On You Last 24 Hours') && label === 'total') {
                const goldLost = parseInt(cells[2].innerText.replace(/,/g, ''), 10) || 0;
                SafeStorage.set("KoC_GoldLost24h", goldLost);
                SafeStorage.set("KoC_GoldLost24h_time", new Date().toISOString());
                console.log("📊 Banking: Gold lost (24h) saved:", goldLost);
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

    console.log("[XPTool] Recon Max Attacks row added:", maxAttacks);
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
        console.log(`[DataCentre] Captured ${newCount} new players from battlefield`);
      }

      // Send bulk gold updates to API
      if (goldUpdates.length > 0) {
        console.log(`[DataCentre] Sending ${goldUpdates.length} gold updates to API`);
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
    const now = new Date().toISOString();

    // Save locally
    const log = getTivLog();
    log.push({ id, tiv, time: now });
    saveTivLog(log);

    updatePlayerInfo(id, { tiv, lastTivTime: now });

    console.log("📊 Attack TIV saved", { id, tiv });

    // Push to API
    await auth.apiCall("tiv", { playerId: id, tiv, time: now });
  }

  // ==================== ATTACK LOG COLLECTOR ====================

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

    table.querySelectorAll("tr").forEach(row => {
      const cells = row.querySelectorAll("td");
      if (cells.length < 2) return;

      const label = cells[0].innerText.trim().toLowerCase();
      const value = cells[1].innerText.trim();

      if (label.startsWith("strike")) stats.strikeAction = value;
      if (label.startsWith("defense")) stats.defensiveAction = value;
      if (label.startsWith("spy")) stats.spyRating = value;
      if (label.startsWith("sentry")) stats.sentryRating = value;
      if (label.startsWith("poison")) stats.poisonRating = value;
      if (label.startsWith("antidote")) stats.antidoteRating = value;
      if (label.startsWith("theft")) stats.theftRating = value;
      if (label.startsWith("vigilance")) stats.vigilanceRating = value;
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
      SafeStorage.set("KoC_MyId", myId);
      SafeStorage.set("KoC_MyName", myName);
      console.log("📊 Stored my KoC ID/Name:", myId, myName);
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
      lastSeen: new Date().toISOString()
    };

    // Save locally
    updatePlayerInfo(myId, payload);
    console.log("📊 Base.php self stats captured", payload);

    // Push to API
    auth.apiCall("players", { id: myId, ...payload });
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
          headers: { "Authorization": "Bearer " + token }
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
      { key: "vigilanceRating", label: "🔎 Vigilance", id: "vigilance" }
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

    // Header with toggles
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
      const table = makeRBTable(def, sortedBy(def.key, def.asc));
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

    const now = new Date().toISOString();

    // Save to TIV log
    if (tiv) {
      const log = getTivLog();
      log.push({ id: myId, tiv, time: now });
      saveTivLog(log);

      // Send TIV to API
      await auth.apiCall("tiv", { playerId: myId, tiv, time: now });
    }

    // Merge into NameMap + API push
    const payload = {
      name: myName,
      tiv,
      ...stats,
      weapons: weapons.length > 0 ? weapons : undefined,
      weaponsTime: weapons.length > 0 ? now : undefined,
      lastTivTime: now,
      lastRecon: now
    };

    updatePlayerInfo(myId, payload);

    // Send self stats to API
    await auth.apiCall("players", { id: myId, ...payload });

    console.log("📊 Armory self stats captured", { id: myId, name: myName, tiv, weapons: weapons.length, ...stats });
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
      console.log('⚠️ No weapon inventory tables found on armory page');
      return weapons;
    }

    console.log(`🔍 Found ${inventoryTables.length} inventory table(s) in armory`);

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
      console.log(`📦 Processing inventory table ${idx + 1}`);

      // Find all category headers within this inventory table only
      const categoryHeaders = [...inventoryTable.querySelectorAll("th.subh")]
        .filter(th => {
          const text = th.textContent.replace(/<br>/gi, ' ').trim();
          return validCategories.some(cat => text.includes(cat));
        });

      console.log(`  Found ${categoryHeaders.length} weapon/tool categories in this table`);

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

      console.log(`  ${category}: Found ${weaponRows.length} potential weapon rows`);

      // Parse weapon rows (they come in pairs: name row + stats row)
      for (let i = 0; i < weaponRows.length; i += 2) {
        const nameRow = weaponRows[i];
        const statsRow = weaponRows[i + 1];

        if (!nameRow || !statsRow) continue;

        try {
          // Extract weapon name from first cell
          const nameCell = nameRow.querySelector('td');
          let weaponName = nameCell?.textContent.trim().split('\n')[0].trim();

          // Extract quantity and strength from stats row
          const statsCells = statsRow.querySelectorAll('td');
          const quantityText = statsCells[0]?.textContent.trim() || '';
          const strengthText = statsCells[1]?.textContent.trim() || '';

          // Parse quantity (e.g., "2,675")
          const quantityMatch = quantityText.match(/^([\d,]+)/);
          const quantity = quantityMatch ? parseInt(quantityMatch[1].replace(/,/g, ''), 10) : 0;

          // Parse strength range (e.g., "278-557")
          const strengthMatch = strengthText.match(/^([\d,]+)-([\d,]+)/);
          const minStrength = strengthMatch ? parseInt(strengthMatch[1].replace(/,/g, ''), 10) : 0;
          const maxStrength = strengthMatch ? parseInt(strengthMatch[2].replace(/,/g, ''), 10) : 0;

          if (weaponName && quantity > 0) {
            weapons.push({
              name: weaponName,
              category: category,
              quantity: quantity,
              minStrength: minStrength,
              maxStrength: maxStrength
            });

            console.log(`    ✅ ${weaponName}: ${quantity} qty, ${minStrength}-${maxStrength} str`);
          }
        } catch (err) {
          console.warn(`⚠️ Failed to parse weapon row in ${category}:`, err);
        }
      }
    });
    }); // Close inventoryTables.forEach

    console.log(`📦 Total weapons collected: ${weapons.length}`);
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

  function grabStat(id, key, cell) {
    const val = cell?.innerText.trim();
    const prev = getNameMap()[id] || {};

    if (val && val !== "???") {
      return { value: val, time: new Date().toISOString() };
    } else {
      // When recon shows "???", DON'T return cached values to API
      // The cached values will still be used by UI enhancement (fillMissingReconValue)
      // But we shouldn't send potentially stale/bad data to the API
      return { value: "???", time: null };
    }
  }

  async function collectFromReconPage() {
    // Find player stats link, excluding the Data Centre link
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
    const id = match ? match[1] : null;

    if (!id) {
      console.log("⚠️ Recon: Could not find player ID");
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

    const ms = getTableByHeader("Military Stats")?.querySelectorAll("tr");
    const treasury = getTableByHeader("Treasury")?.querySelectorAll("tr");
    const armyTable = getTableByHeader("Army Breakdown")?.querySelectorAll("tr");

    const stats = {};
    const now = new Date().toISOString();

    function set(key, row) {
      const { value, time } = grabStat(id, key, row?.cells[1]);
      stats[key] = value;
      if (time) stats[key + "Time"] = time;
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

      // Parse Projected Income (1 min only)
      const projectedIncomeText = treasury[3]?.innerText || "";
      // Format: "13,292,958 Gold (in 1 min) | 199,394,370 Gold (in 15 mins) | 398,788,740 Gold (in 30 mins)"

      const match1min = projectedIncomeText.match(/([0-9,]+)\s*Gold\s*\(in 1 min\)/);

      if (match1min) {
        stats.projectedIncome = match1min[1];
        stats.projectedIncomeTime = now;
      } else {
        // Fallback if format doesn't match
        stats.projectedIncome = treasury[3]?.innerText.split(" Gold")[0];
        stats.projectedIncomeTime = now;
      }
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
        console.log(`📦 Captured ${weapons.length} weapons from recon`);
      }
    }

    // Count how many fields we successfully scraped (not "???")
    const fieldCount = Object.keys(stats).filter(key =>
      !key.endsWith('Time') && stats[key] !== "???"
    ).length;

    // Save + push
    updatePlayerInfo(id, stats);
    console.log(`📊 Recon data saved (${fieldCount} fields):`, stats);

    // Send to API
    await auth.apiCall("players", { id, ...stats });

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

    // Enhance UI with cached data
    enhanceReconUI(id).catch(err => console.warn("enhanceReconUI failed:", err));
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

      cell.innerHTML = `
        <div style="float:left;color:#FBC;font-size:0.8em;" title="${escapeHtml(abs)} • from cache">
          ${escapeHtml(rel)}
        </div>
        <div title="${escapeHtml(abs)} • from cache">${escapeHtml(cachedValue)}</div>
      `;
    }
  }

  async function enhanceReconUI(id) {
    let prev = {};

    // API-first
    try {
      const token = await auth.getToken();
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
          console.log(`📦 Cached weapons (${weaponsAge}):`, cachedWeapons);
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

    console.log("[DataCentre] Redirecting to React app...");

    const authData = auth.getAuthForRedirect();
    console.log("[DataCentre] Auth data:", authData ? "✅ Available" : "❌ Not available");

    if (authData) {
      console.log("[DataCentre] Valid auth found, using URL parameter method");

      // Encode auth data as base64 for URL
      const authEncoded = btoa(JSON.stringify(authData));
      const redirectUrl = `https://koc-roster-client-production.up.railway.app?auth=${authEncoded}`;

      console.log("[DataCentre] Redirecting with auth in URL");
      window.location.href = redirectUrl;
    } else {
      console.log("[DataCentre] No valid auth found, redirecting without token");
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

    // Recon detail
    if (location.pathname.includes("inteldetail.php")) {
      await safeExecute('addMaxAttacksRecon', () => addMaxAttacksRecon());
      await safeExecute('collectFromReconPage', () => collectFromReconPage());
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
          console.log("[DataCentre] Battlefield observer active (debounced)");
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
          console.log("✅ All features initialized");
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
    console.log("🔍 showPlayer() called with id:", id);
    const map = getNameMap();

    if (!id) {
      console.log("📊 Full NameMap:", map);
      return map;
    }

    console.log("📊 Player record:", map[id]);
    return map[id] || null;
  };

  window.showTivLog = function() {
    console.log("📊 Full TIV log requested");
    const log = getTivLog();
    console.log("📊 Log:", log);
    return log;
  };

})();
