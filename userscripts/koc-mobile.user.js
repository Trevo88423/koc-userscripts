// ==UserScript==
// @name         KoC Mobile Skin
// @namespace    trevo88423
// @version      1.5.0
// @description  Makes kingsofchaos.com usable one-handed on a phone: hamburger nav drawer, sticky stats bar (tap to expand), full-width content. v1 = sidebar only. No-op on desktop.
// @author       Trevor
// @match        *://*.kingsofchaos.com/*
// @icon         https://www.kingsofchaos.com/kingsofchaos_favicon.svg
// @updateURL    https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/koc-mobile.user.js
// @downloadURL  https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/koc-mobile.user.js
// @run-at       document-start
// @grant        GM_addStyle
// @noframes
// ==/UserScript==

/*
 * v1 scope (sidebar only, site-wide):
 *   1. Nav menu (Command Center → Log Out) → slide-in hamburger drawer, 44px+ rows.
 *   2. Stats panel → slim sticky top bar (Gold · Turns · Attacks Left/Rank),
 *      tap to expand the full panel. "Attacks Left" only exists when another
 *      script injects it, so the bar re-reads the (hidden) stats table via a
 *      MutationObserver and shows Rank until it appears.
 *   3. Message center → drawer section with an unread badge (counts "N New").
 *   The original sidebar <td class="menu_cell">, the empty 120px right-rail
 *   <td>, and the 164px top banner are hidden; td.content reflows full width.
 *   Banner links (Forum/Chat/Store/Help/Rankings) move into the drawer, and
 *   Recent Logs + Server Time land in the drawer footer so nothing the
 *   sidebar showed is lost.
 *
 * v1.1: other userscripts (SR's Turn Trading Calculator etc.) inject whole
 *   panels into the sidebar column — hiding the column ate them. Now only the
 *   chunks replicated by this skin are hidden (tagged .kocm-replicated);
 *   anything unrecognized stays in the DOM untouched and the sidebar cell is
 *   re-shown full-width BELOW the page content as a "Sidebar Tools" section
 *   (flex reorder, no DOM moves). A sidebar observer catches late injection,
 *   and the drawer gets a jump link when the section exists.
 *
 * v1.2 (from live-DOM inspection of the logged-in game + DataCentre source):
 *   - DataCentre inserts #koc-xp-box INSIDE the stats repeater cell (right
 *     after the inner stats table), so tagging the outer box table hid it.
 *     Tagging is now per inner table by text signature (Gold:/Message
 *     Center/Recent Logs); anything else inside the boxed cells survives.
 *   - The logged-out login form lives INSIDE td.menu_cell, so the skin was
 *     hiding it. The skin now fully deactivates on logged-out pages (no
 *     a[href="logout.php"]) and widens the viewport back to 980.
 *   - Desktop-view toggle: drawer row sets localStorage kocmDesktop=1 → skin
 *     no-ops; a floating 📱 chip switches back.
 *   - Third bar chip reads DataCentre's #xp-attacks (Attacks Left) when
 *     present, else the stats-table row, else Rank.
 *
 * v1.3 (v2 scope — Training page): the two 50% columns (Train Your Troops /
 *   Personnel) stack vertically. The page's malformed wrapper markup recovers
 *   to [empty tr, tr(left td, right td)] — the wrapper is JS-tagged
 *   .kocm-cols (detected by the training-only train[...] inputs, not URL),
 *   the orphan cell hidden, quantity inputs and Max-Train buttons fattened to
 *   44px+, and cell padding tightened so the troop table fits phone width.
 *
 * v1.4 (base.php + shared machinery): Command Center columns stack the same
 *   way (mode by URL or the stylechanger form). Residual too-wide tables get
 *   .kocm-scroll — display:block + width:0/min-width:100% (max-width is
 *   ignored during intrinsic sizing) so each scrolls internally instead of
 *   panning the page; tagging is min-content-measured, deepest-first, run to
 *   a fixpoint and re-run late for async panels. DataCentre's Sweet Revenge
 *   Stats rows (#sr-stats-row1/2) get flex-wrap with ~40% basis boxes: 2 per
 *   row on a phone instead of 6 (styling only, no DataCentre DOM touched).
 *
 * v1.5 (armory.php): mode by URL or the buywep/curwep table classes. The
 *   5-column weapon grids get tight 3px cells, 12px grid text, and 4.5em
 *   quantity inputs (grid-scoped so vault amount fields keep room) — the BUY
 *   grid then fits phone width inline (548→~354); the inventory grids, TIV
 *   breakdown, and rating table stay wide and fall through to .kocm-scroll.
 *
 * Page anatomy this is written against (view-source of training.php, Era 23):
 *   <table height=164 background=".../small_repeater.gif">   ← decorative banner
 *   <table width=100% cellpadding=5><tr>
 *     <td class="menu_cell" width=140>                       ← sidebar (nav imgs,
 *         boxes = td.menu_cell_repeater_vert: stats / messages / recent logs)
 *     <td class="content">                                   ← page content
 *     <td width=120>                                         ← empty right rail
 *
 * Hands-off rule: never touches other userscripts' DOM. Rows they inject into
 * the stats table are harvested by text and shown in the bar/panel. Known
 * limitation: any *whole panel* another script injects into the sidebar is
 * hidden along with the column.
 *
 * Desktop gate: everything (viewport meta, CSS, UI) is skipped unless the
 * device screen is phone-sized. innerWidth is useless at document-start here —
 * with no viewport meta the layout viewport is ~980px — so we gate on
 * screen.width (device CSS px) + a UA hint.
 */

(function () {
  'use strict';

  // ---------------------------------------------------------------- gate --
  var MOBILE_MAX = 768;
  var isMobile =
    Math.min(screen.width, screen.height) <= MOBILE_MAX ||
    /Android|iPhone|iPod|Mobile/i.test(navigator.userAgent);
  if (!isMobile) return; // desktop: total no-op

  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
    del: function (k) { try { localStorage.removeItem(k); } catch (e) {} }
  };

  function onReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn, { once: true });
    } else {
      fn();
    }
  }

  // user toggled "Desktop view": skin no-ops except a floating chip to return
  if (store.get('kocmDesktop') === '1') {
    onReady(function () {
      // No viewport meta here, so the ~980px layout is zoomed out to fit the
      // screen — a 46px chip would paint at ~18 physical px. Scale it by the
      // layout/screen ratio so it lands around 46 physical px.
      var scale = Math.max(1, Math.min(3.2, window.innerWidth / Math.min(screen.width, screen.height)));
      var size = Math.round(46 * scale);
      addStyle(
        '#kocm-restore { position: fixed; right: 12px; bottom: 12px; z-index: 2147483000;' +
        '  width: ' + size + 'px; height: ' + size + 'px; border-radius: 50%; border: 2px solid #a08c5f;' +
        '  background: rgba(20,16,12,.92); font-size: ' + Math.round(size * 0.5) + 'px; line-height: 1;' +
        '  box-shadow: 0 2px 12px rgba(0,0,0,.6); cursor: pointer; }'
      );
      var chip = document.createElement('button');
      chip.id = 'kocm-restore';
      chip.textContent = '📱';
      chip.title = 'Switch back to mobile view';
      chip.addEventListener('click', function () {
        store.del('kocmDesktop');
        location.reload();
      });
      document.body.appendChild(chip);
    });
    return;
  }

  // ------------------------------------------------------- viewport meta --
  // KoC ships no viewport meta, so phones render the 980px layout viewport.
  // Inject one as early as possible; head may not exist yet at document-start.
  // Kept referenced: logged-out pages widen it back to the desktop layout.
  var viewportMeta = (function injectViewport() {
    var meta = document.createElement('meta');
    meta.setAttribute('name', 'viewport');
    meta.setAttribute('content', 'width=device-width, initial-scale=1');
    if (document.head) {
      document.head.appendChild(meta);
    } else {
      new MutationObserver(function (_muts, obs) {
        if (document.head) {
          document.head.appendChild(meta);
          obs.disconnect();
        }
      }).observe(document.documentElement, { childList: true, subtree: true });
    }
    return meta;
  })();

  // ------------------------------------------------------------------ css --
  var CSS = [
    /* ---- kill fixed-width chrome, reflow content full-width ---- */
    /* decorative 164px top banner (its links live in the drawer now) */
    'html.kocm-on table[background*="small_repeater"] { display: none !important; }',
    /* the sidebar column: hidden until build() finds unrecognized content in
     * it (script-injected panels) — then html.kocm-extras re-shows it as a
     * full-width section reordered below the page content */
    'html.kocm-on td.menu_cell { display: none !important; }',
    'html.kocm-on.kocm-extras td.menu_cell {',
    '  display: block !important;',
    '  order: 2;',
    '  width: 100% !important;',
    '  box-sizing: border-box !important;',
    '  padding: 12px 10px 28px !important;',
    '  border-top: 2px solid #3a2d1c;',
    '  scroll-margin-top: 60px;', // drawer jump link lands below the fixed bar
    '}',
    'html.kocm-on.kocm-extras td.menu_cell::before {',
    '  content: "Sidebar Tools";',
    '  display: block;',
    '  margin: 0 0 10px;',
    '  font: 600 10px/1 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;',
    '  letter-spacing: .12em; text-transform: uppercase;',
    '  color: #8b7a55; text-align: center;',
    '}',
    /* leftover (script-injected) panels: stretch their 137px tables, cap imgs */
    'html.kocm-on.kocm-extras td.menu_cell table { width: 100% !important; }',
    'html.kocm-on.kocm-extras td.menu_cell img { max-width: 100%; height: auto; }',
    /* the site's 137px parchment texture + menubar caps look broken stretched;
     * keep panels on the dark theme and remap parchment-black text */
    'html.kocm-on.kocm-extras td.menu_cell .menu_cell_repeater_vert {',
    '  background-image: none !important; background-color: transparent !important;',
    '}',
    'html.kocm-on.kocm-extras td.menu_cell img[src*="menubar/top."],',
    'html.kocm-on.kocm-extras td.menu_cell img[src*="menubar/bottom."] { display: none !important; }',
    'html.kocm-on.kocm-extras td.menu_cell font[color="BLACK" i],',
    'html.kocm-on.kocm-extras td.menu_cell [style*="color:black" i],',
    'html.kocm-on.kocm-extras td.menu_cell [style*="color: black" i] { color: #e9ddc0 !important; }',
    /* sidebar chunks this skin replicates (nav/stats/messages/logs/times) */
    'html.kocm-on .kocm-replicated { display: none !important; }',

    /* ---- two-column stacking (page modes tag wrappers .kocm-cols) ---- */
    'html.kocm-on table.kocm-cols,',
    'html.kocm-on table.kocm-cols > tbody,',
    'html.kocm-on table.kocm-cols > tbody > tr,',
    'html.kocm-on table.kocm-cols > tbody > tr > td[width="50%"] {',
    '  display: block !important;',
    '  width: 100% !important;',
    '  box-sizing: border-box !important;',
    '}',
    /* parser-orphaned empty cell from malformed wrapper markup
     * (must out-specify the block rule above) */
    'html.kocm-on table.kocm-cols > tbody > tr > td.kocm-blank[width="50%"] {',
    '  display: none !important;',
    '}',
    /* comfortable one-handed inputs: 44px+ targets, 16px text */
    'html.kocm-on.kocm-training td.content input[type="number"],',
    'html.kocm-on.kocm-training td.content input[type="text"] {',
    '  min-height: 44px;',
    '  width: 5em !important;',
    '  font-size: 16px;',
    '  padding: 4px 6px;',
    '  box-sizing: border-box;',
    '}',
    'html.kocm-on.kocm-training td.content input[type="button"] {',
    '  min-height: 44px;',
    '  font-size: 12px;',
    '  padding: 6px 5px;',
    '}',
    'html.kocm-on.kocm-training td.content input[type="submit"] { min-height: 48px; }',
    /* tighter cells inside the stacked columns so tables fit phone width */
    'html.kocm-on table.kocm-cols td[width="50%"] table td,',
    'html.kocm-on table.kocm-cols td[width="50%"] table th {',
    '  padding: 3px !important;',
    '}',

    /* residual wide tables become their own horizontal scrollers (JS-tagged
     * after stacking; deepest wide table only). width:0 + min-width:100%
     * zeroes the intrinsic width contribution (max-width:100% would be
     * IGNORED in the intrinsic pass and keep propagating min-content). */
    'html.kocm-on table.kocm-scroll {',
    '  display: block !important;',
    '  width: 0 !important;',
    '  min-width: 100% !important;',
    '  overflow-x: auto !important;',
    '  box-sizing: border-box !important;',
    '}',

    /* DataCentre "Sweet Revenge Stats" boxes (#sr-stats-*): the rows are
     * inline no-wrap flex with 130px-min boxes — 6 across needs ~780px.
     * Let them wrap, ~2 per row on a phone. Styling only, per the brief. */
    'html.kocm-on #sr-stats-row1,',
    'html.kocm-on #sr-stats-row2 { flex-wrap: wrap !important; }',
    'html.kocm-on #sr-stats-tables [class*="sr-stat-"] {',
    '  flex: 1 1 40% !important;',
    '  box-sizing: border-box !important;',
    '}',

    /* ---- Command Center (base.php) ---- */
    /* fat inputs; no width clamp — the gold deposit field needs digits */
    'html.kocm-on.kocm-base td.content input[type="text"],',
    'html.kocm-on.kocm-base td.content input[type="number"] {',
    '  min-height: 44px;',
    '  font-size: 16px;',
    '  padding: 4px 6px;',
    '  box-sizing: border-box;',
    '}',
    'html.kocm-on.kocm-base td.content input[type="submit"],',
    'html.kocm-on.kocm-base td.content select { min-height: 44px; font-size: 15px; }',

    /* ---- Armory (armory.php) ---- */
    /* dense 5-col weapon grids: tight cells + clamped quantity inputs pull
     * the BUY grid under phone width (548→~354); inventory grids that stay
     * wide fall through to .kocm-scroll automatically */
    'html.kocm-on.kocm-armory table.buywep td, html.kocm-on.kocm-armory table.buywep th,',
    'html.kocm-on.kocm-armory table.curwep td, html.kocm-on.kocm-armory table.curwep th,',
    'html.kocm-on.kocm-armory table.curtool td, html.kocm-on.kocm-armory table.curtool th {',
    '  padding: 3px !important;',
    '  font-size: 12px;',
    '}',
    'html.kocm-on.kocm-armory table.buywep input,',
    'html.kocm-on.kocm-armory table.curwep input,',
    'html.kocm-on.kocm-armory table.curtool input {',
    '  width: 4.5em !important;', // weapon-grid quantities only — vault amounts keep room
    '  box-sizing: border-box;',
    '}',
    'html.kocm-on.kocm-armory td.content input[type="number"],',
    'html.kocm-on.kocm-armory td.content input[type="text"] {',
    '  min-height: 44px;',
    '  font-size: 16px;',
    '  padding: 4px 6px;',
    '  box-sizing: border-box;',
    '}',
    'html.kocm-on.kocm-armory td.content input[type="submit"] { min-height: 48px; }',
    'html.kocm-on.kocm-armory td.content input[type="button"], ',
    'html.kocm-on.kocm-armory td.content button { min-height: 44px; }',
    /* empty right rail: any td after td.content in the same layout row */
    'html.kocm-on td.content ~ td { display: none !important; }',
    /* Linearize the layout table (table→tbody→tr→content cell all block) so
     * the page itself never grows past device width — otherwise one wide
     * content table (e.g. Training's two-column wrapper, min-content ~880px)
     * expands the mobile layout viewport and the fixed bar pans off-screen.
     * Wide tables scroll horizontally INSIDE td.content instead.
     * :has() works from document-start; build() also tags .kocm-layout as a
     * fallback for engines without it. */
    'html.kocm-on body > table:has(td.menu_cell),',
    'html.kocm-on table.kocm-layout { display: block !important; width: 100% !important; }',
    'html.kocm-on body > table:has(td.menu_cell) > tbody,',
    'html.kocm-on table.kocm-layout > tbody { display: block !important; width: 100% !important; }',
    /* the row goes flex-column so the sidebar cell can be ORDERED below the
     * content cell when it re-appears as the Sidebar Tools section */
    'html.kocm-on body > table:has(td.menu_cell) > tbody > tr,',
    'html.kocm-on table.kocm-layout > tbody > tr {',
    '  display: flex !important;',
    '  flex-direction: column !important;',
    '  width: 100% !important;',
    '}',
    'html.kocm-on td.content {',
    '  display: block !important;',
    '  order: 1;',
    '  width: 100% !important;',
    '  overflow-x: auto !important;',
    '  padding: 8px 6px 24px !important;',
    '  box-sizing: border-box !important;',
    '}',
    /* room for the fixed bar (only when our UI actually built) */
    'html.kocm-ui body { padding-top: 52px !important; }',
    /* scroll lock while drawer/panel open */
    'html.kocm-lock, html.kocm-lock body { overflow: hidden !important; }',

    /* ---- shared UI tokens ---- */
    '#kocm-bar, #kocm-panel, #kocm-drawer, #kocm-backdrop {',
    '  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;',
    '  -webkit-text-size-adjust: 100%;',
    '  touch-action: manipulation;',
    '  box-sizing: border-box;',
    '}',
    '#kocm-bar *, #kocm-panel *, #kocm-drawer * { box-sizing: border-box; }',
    /* app chrome shouldn't text-select on tap (panel stays selectable: it is data) */
    '#kocm-bar, #kocm-drawer, #kocm-backdrop { -webkit-user-select: none; user-select: none; }',

    /* ---- sticky top bar ---- */
    '#kocm-bar {',
    '  position: fixed; top: 0; left: 0; right: 0; height: 52px; z-index: 100003;',
    '  display: flex; align-items: stretch;',
    '  background: #14100c; border-bottom: 1px solid #3a2d1c;',
    '  box-shadow: 0 1px 6px rgba(0,0,0,.6);',
    '}',
    '#kocm-menu-btn {',
    '  width: 52px; min-width: 52px; border: 0; margin: 0; position: relative;',
    '  background: none; color: #ffd766; font-size: 24px; line-height: 1;',
    '  cursor: pointer;',
    '}',
    '#kocm-menu-btn:active { background: #241c12; }',
    '#kocm-menu-badge {',
    '  position: absolute; top: 6px; right: 4px; min-width: 18px; height: 18px;',
    '  padding: 0 5px; border-radius: 9px; background: #d03325; color: #fff;',
    '  font-size: 11px; font-weight: 700; line-height: 18px; text-align: center;',
    '}',
    '#kocm-stats {',
    '  flex: 1; min-width: 0; display: flex; align-items: stretch;',
    '  border: 0; margin: 0; padding: 0 2px; background: none; cursor: pointer;',
    '}',
    '#kocm-stats:active { background: #241c12; }',
    '.kocm-chip {',
    '  flex: 1; min-width: 0; display: flex; flex-direction: column;',
    '  align-items: center; justify-content: center; gap: 1px; padding: 0 4px;',
    '}',
    '.kocm-chip[hidden] { display: none; }',
    '.kocm-chip-label {',
    '  font-size: 9px; letter-spacing: .08em; text-transform: uppercase;',
    '  color: #a08c5f; white-space: nowrap; overflow: hidden; max-width: 100%;',
    '}',
    '.kocm-chip-value {',
    '  font-size: 15px; font-weight: 700; color: #ffd766; white-space: nowrap;',
    '  overflow: hidden; text-overflow: ellipsis; max-width: 100%;',
    '}',
    '#kocm-caret {',
    '  align-self: center; width: 24px; text-align: center; color: #a08c5f;',
    '  font-size: 12px; transition: transform .18s;',
    '}',
    'html.kocm-panel-open #kocm-caret { transform: rotate(180deg); }',

    /* ---- expanding stats panel ---- */
    '#kocm-panel {',
    '  position: fixed; top: 52px; left: 0; right: 0; z-index: 100002;',
    '  max-height: calc(100% - 52px); overflow-y: auto;',
    '  background: #171310; border-bottom: 2px solid #3a2d1c;',
    '  box-shadow: 0 8px 20px rgba(0,0,0,.7);',
    '}',
    '#kocm-panel[hidden] { display: none; }',
    '.kocm-panel-row {',
    '  display: flex; align-items: center; justify-content: space-between;',
    '  min-height: 44px; padding: 4px 16px; gap: 12px;',
    '  color: inherit; text-decoration: none;',
    '  border-bottom: 1px solid #241d15;',
    '}',
    'a.kocm-panel-row:active { background: #241c12; }',
    '.kocm-panel-label { font-size: 14px; color: #cbb98d; white-space: nowrap; }',
    '.kocm-panel-value { font-size: 15px; font-weight: 700; color: #ffd766; text-align: right; overflow-wrap: anywhere; }',
    '.kocm-panel-row.kocm-muted .kocm-panel-label,',
    '.kocm-panel-row.kocm-muted .kocm-panel-value { color: #8b7a55; font-weight: 400; font-size: 12px; }',

    /* ---- drawer ---- */
    '#kocm-drawer {',
    '  position: fixed; top: 0; left: 0; bottom: 0; z-index: 100005;',
    '  width: 84vw; max-width: 340px; height: 100%; height: 100dvh;',
    '  overflow-y: auto; overscroll-behavior: contain;',
    '  background: #171310; border-right: 1px solid #3a2d1c;',
    '  box-shadow: 4px 0 24px rgba(0,0,0,.8);',
    '  transform: translateX(-105%); transition: transform .22s ease-out;',
    '  visibility: hidden;',
    '}',
    'html.kocm-drawer-open #kocm-drawer { transform: translateX(0); visibility: visible; }',
    '#kocm-drawer-head {',
    '  display: flex; align-items: center; justify-content: space-between;',
    '  padding: 6px 6px 6px 16px; border-bottom: 1px solid #3a2d1c;',
    '  position: sticky; top: 0; background: #14100c; z-index: 1;',
    '}',
    '#kocm-drawer-title { font-size: 15px; font-weight: 700; letter-spacing: .12em; color: #ffd766; }',
    '#kocm-drawer-close {',
    '  width: 44px; height: 44px; border: 0; background: none; color: #a08c5f;',
    '  font-size: 22px; cursor: pointer;',
    '}',
    '#kocm-drawer-close:active { color: #ffd766; }',
    '.kocm-section {',
    '  padding: 10px 16px 4px; font-size: 10px; letter-spacing: .12em;',
    '  text-transform: uppercase; color: #8b7a55;',
    '}',
    '.kocm-row {',
    '  display: flex; align-items: center; justify-content: space-between;',
    '  min-height: 48px; padding: 4px 16px; gap: 10px;',
    '  font-size: 15px; color: #e9ddc0; text-decoration: none;',
    '  border-bottom: 1px solid #221b13;',
    '}',
    '.kocm-row:active { background: #241c12; }',
    '.kocm-row.kocm-current { border-left: 3px solid #ffd766; padding-left: 13px; background: #1f1810; color: #ffd766; }',
    '.kocm-row.kocm-danger { color: #e0705f; }',
    '.kocm-row-value { font-size: 13px; color: #a08c5f; white-space: nowrap; }',
    '.kocm-badge {',
    '  min-width: 20px; padding: 1px 6px; border-radius: 10px;',
    '  background: #d03325; color: #fff; font-size: 12px; font-weight: 700;',
    '  text-align: center;',
    '}',
    '.kocm-foot {',
    '  padding: 12px 16px 20px; font-size: 12px; color: #8b7a55; line-height: 1.7;',
    '}',

    /* ---- backdrop ---- */
    '#kocm-backdrop {',
    '  position: fixed; inset: 0; z-index: 100004; background: rgba(0,0,0,.55);',
    '  opacity: 0; transition: opacity .2s; visibility: hidden;',
    '}',
    /* below the bar while the stats panel is open, above it for the drawer */
    'html.kocm-panel-open #kocm-backdrop { z-index: 100001; opacity: 1; visibility: visible; }',
    'html.kocm-drawer-open #kocm-backdrop { z-index: 100004; opacity: 1; visibility: visible; }',

    '@media (prefers-reduced-motion: reduce) {',
    '  #kocm-drawer, #kocm-backdrop, #kocm-caret { transition: none !important; }',
    '}'
  ].join('\n');

  function addStyle(css) {
    if (typeof GM_addStyle === 'function') { GM_addStyle(css); return; }
    var s = document.createElement('style');
    s.textContent = css;
    (document.head || document.documentElement).appendChild(s);
  }

  document.documentElement.classList.add('kocm-on');
  addStyle(CSS);
  onReady(build);

  // -------------------------------------------------------------- helpers --
  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text != null) n.textContent = text;
    return n;
  }

  function debounce(fn, ms) {
    var t;
    return function () {
      clearTimeout(t);
      t = setTimeout(fn, ms);
    };
  }

  // "Gold:\n 495,682,703" style cells → {label, value, href}
  function readRows(box) {
    var rows = [];
    box.querySelectorAll('tr').forEach(function (tr) {
      var td = tr.querySelector('td, th');
      if (!td) return;
      var text = td.textContent.replace(/\s+/g, ' ').trim();
      var i = text.indexOf(':');
      if (i <= 0) return;
      var label = text.slice(0, i).trim();
      var value = text.slice(i + 1).trim();
      if (!label) return;
      var a = td.querySelector('a[href]');
      rows.push({ label: label, value: value, href: a ? a.getAttribute('href') : null });
    });
    return rows;
  }

  // Parses "495,682,703", "17,300", "1,234M" (site abbreviates ≥1B), "623".
  function parseKocNumber(s) {
    var m = String(s).replace(/,/g, '').match(/^([\d.]+)\s*([KMBT])?$/i);
    if (!m) return NaN;
    var mult = { K: 1e3, M: 1e6, B: 1e9, T: 1e12 }[(m[2] || '').toUpperCase()] || 1;
    return parseFloat(m[1]) * mult;
  }

  function compact(s) {
    var n = parseKocNumber(s);
    if (!isFinite(n)) return s.length > 10 ? s.slice(0, 10) + '…' : s; // "45 / 200" etc: show raw
    var sig = function (v) {
      return String(v >= 100 ? Math.round(v) : v >= 10 ? v.toFixed(1) : v.toFixed(2))
        .replace(/\.0+$/, '');
    };
    if (n >= 1e12) return sig(n / 1e12) + 'T';
    if (n >= 1e9) return sig(n / 1e9) + 'B';
    if (n >= 1e6) return sig(n / 1e6) + 'M';
    if (n >= 1e4) return sig(n / 1e3) + 'K';
    return n.toLocaleString('en-US');
  }

  function countNew(rows) {
    var n = 0;
    rows.forEach(function (r) {
      var m = r.value.match(/(\d+)\s*new/i);
      if (m) n += parseInt(m[1], 10);
    });
    return n;
  }

  // ---------------------------------------------------------------- build --
  function build() {
    // Logged out? The login form lives INSIDE td.menu_cell, so the skin must
    // fully stand down or it hides the way back in. Every logged-in page has
    // the Log Out nav link; its absence is the logged-out signal.
    if (!document.querySelector('a[href="logout.php"]')) {
      document.documentElement.classList.remove('kocm-on');
      viewportMeta.setAttribute('content', 'width=980'); // desktop-style zoomable login
      return;
    }

    var sidebar = document.querySelector('td.menu_cell');
    if (!sidebar) return; // odd pages keep viewport + banner CSS only

    // --- harvest the sidebar ---
    var navItems = [];
    var navTable = sidebar.querySelector('table');
    if (navTable) {
      navTable.querySelectorAll('a').forEach(function (a) {
        var img = a.querySelector('img[alt]');
        var label = (img ? img.getAttribute('alt') : a.textContent).trim();
        var href = a.getAttribute('href');
        if (label && href) navItems.push({ label: label, href: href });
      });
    }

    var statsBox = null, msgBox = null, logsBox = null;

    // re-runnable: other scripts may add/replace sidebar content after load
    function findBoxes() {
      statsBox = msgBox = logsBox = null;
      sidebar.querySelectorAll('td.menu_cell_repeater_vert').forEach(function (box) {
        var text = box.textContent;
        if (/message center/i.test(text)) msgBox = msgBox || box;
        else if (/recent logs/i.test(text)) logsBox = logsBox || box;
        else if (/gold\s*:/i.test(text)) statsBox = statsBox || box;
      });
    }

    // Tag everything this skin replicates elsewhere; whatever is NOT tagged
    // (panels injected by other userscripts) survives into Sidebar Tools.
    // Tag the boxed cells' ORIGINAL inner tables individually, never the
    // outer box tables — DataCentre inserts #koc-xp-box as a SIBLING of the
    // inner stats table, inside the box, and it must stay visible.
    function tagReplicated() {
      findBoxes();
      var tag = function (n) { if (n) n.classList.add('kocm-replicated'); };
      tag(navTable);
      sidebar.querySelectorAll('td.menu_cell_repeater_vert').forEach(function (cell) {
        Array.prototype.forEach.call(cell.children, function (ch) {
          if (ch.tagName !== 'TABLE') return;
          var t = ch.textContent;
          if (/gold\s*:/i.test(t) || /message center/i.test(t) || /recent logs/i.test(t)) tag(ch);
        });
      });
      // Game Time / Server Time header tables + their value tables
      sidebar.querySelectorAll('th').forEach(function (th) {
        if (!/^(game|server) time$/i.test(th.textContent.trim())) return;
        var t = th.closest('table');
        tag(t);
        var next = t && t.nextElementSibling;
        while (next && next.tagName !== 'TABLE') next = next.nextElementSibling;
        tag(next);
      });
    }

    function hasVisibleContent(node) {
      var clone = node.cloneNode(true);
      clone.querySelectorAll('script, style, .kocm-replicated').forEach(function (n) { n.remove(); });
      if (clone.textContent.trim()) return true;
      // the 1px setres tracking img and the menubar cap/banner décor (hidden
      // in the extras section anyway) must not count as content
      return !!clone.querySelector('img:not([width="1"]):not([src*="/images/menubar/"]), input, button, select, iframe');
    }

    function updateExtras() {
      var has = false;
      Array.prototype.forEach.call(sidebar.children, function (ch) {
        if (has || ch.nodeType !== 1) return;
        if (ch.classList.contains('kocm-replicated')) return;
        if (/^(SCRIPT|STYLE|LINK)$/.test(ch.tagName)) return;
        if (hasVisibleContent(ch)) has = true;
      });
      document.documentElement.classList.toggle('kocm-extras', has);
    }

    tagReplicated();

    function serverTime() {
      var ths = sidebar.querySelectorAll('th');
      for (var i = 0; i < ths.length; i++) {
        if (!/server time/i.test(ths[i].textContent)) continue;
        var next = ths[i].closest('table');
        next = next && next.nextElementSibling;
        while (next && next.tagName !== 'TABLE') next = next.nextElementSibling;
        if (next && /\d{4}-\d{2}-\d{2}/.test(next.textContent)) {
          return next.textContent.trim();
        }
      }
      return null;
    }

    if (!navItems.length && !statsBox) return; // nothing recognizable — bail

    document.documentElement.classList.add('kocm-ui');

    // fallback hook for the linearize rules where :has() is unavailable
    var layoutTable = sidebar.closest('table');
    if (layoutTable) layoutTable.classList.add('kocm-layout');

    updateExtras();

    // ---- per-page modes: stack two-column wrappers, page-specific CSS ----
    // Pages are detected by content signatures rather than URL alone so the
    // logic also works against saved copies of the pages (and the harness).
    var contentCell = document.querySelector('td.content');

    function stackTwoColumnWrappers() {
      contentCell.querySelectorAll('td[width="50%"]').forEach(function (td) {
        var wrapper = td.closest('table');
        if (wrapper) wrapper.classList.add('kocm-cols');
        if (!td.textContent.trim() && !td.querySelector('*')) td.classList.add('kocm-blank');
      });
    }

    // After stacking, any table still wider than the viewport becomes its own
    // horizontal scroller (deepest wide table only — tagging an ancestor would
    // pan whole sections sideways). Re-run late for slow images/async panels.
    function tagWideScrollers() {
      var limit = contentCell.clientWidth + 4;
      if (limit < 100) return;
      // MIN-CONTENT decides wideness — rendered width lies (every width:100%
      // child of a wide container measures wide). Tag deepest culprits, then
      // re-check: ancestors shrink once a child stops propagating min-content.
      var minContentWidth = function (t) {
        var prev = t.style.cssText;
        t.style.cssText += ';width:min-content !important;';
        var w = t.getBoundingClientRect().width;
        t.style.cssText = prev;
        return w;
      };
      for (var pass = 0; pass < 4; pass++) {
        if (contentCell.scrollWidth <= limit) break;
        var tables = Array.prototype.slice.call(
          contentCell.querySelectorAll('table:not(.kocm-scroll)'));
        var wide = tables.filter(function (t) { return minContentWidth(t) > limit; });
        var deepest = wide.filter(function (t) {
          return !wide.some(function (o) { return o !== t && t.contains(o); });
        });
        if (!deepest.length) break;
        deepest.forEach(function (t) { t.classList.add('kocm-scroll'); });
      }
    }

    if (contentCell) {
      var pageMode = null;
      if (document.querySelector('input[name^="train["]')) {          // training.php
        pageMode = 'kocm-training';
      } else if (/\/base\.php/i.test(location.pathname) ||            // base.php
                 contentCell.querySelector('form[action="stylechanger.php"]')) {
        pageMode = 'kocm-base';
      } else if (/\/armory\.php/i.test(location.pathname) ||          // armory.php
                 contentCell.querySelector('table.buywep, table.curwep')) {
        pageMode = 'kocm-armory';
      }
      if (pageMode) {
        document.documentElement.classList.add(pageMode);
        stackTwoColumnWrappers();
        requestAnimationFrame(tagWideScrollers);
        window.addEventListener('load', tagWideScrollers, { once: true });
        setTimeout(tagWideScrollers, 2500);
      }
    }

    // --- sticky bar ---
    var bar = el('div');
    bar.id = 'kocm-bar';

    var menuBtn = el('button', null, '☰');
    menuBtn.id = 'kocm-menu-btn';
    menuBtn.setAttribute('aria-label', 'Menu');
    var menuBadge = el('span');
    menuBadge.id = 'kocm-menu-badge';
    menuBadge.hidden = true;
    menuBtn.appendChild(menuBadge);

    var statsBtn = el('button');
    statsBtn.id = 'kocm-stats';
    statsBtn.setAttribute('aria-label', 'Show full stats');
    var chips = [0, 1, 2].map(function () {
      var chip = el('span', 'kocm-chip');
      chip.appendChild(el('span', 'kocm-chip-label'));
      chip.appendChild(el('span', 'kocm-chip-value'));
      statsBtn.appendChild(chip);
      return chip;
    });
    var caret = el('span', null, '▾');
    caret.id = 'kocm-caret';
    statsBtn.appendChild(caret);

    bar.appendChild(menuBtn);
    bar.appendChild(statsBtn);

    // --- stats panel, drawer, backdrop shells ---
    var panel = el('div');
    panel.id = 'kocm-panel';
    panel.hidden = true;

    var drawer = el('nav');
    drawer.id = 'kocm-drawer';
    drawer.setAttribute('aria-label', 'Site menu');

    var backdrop = el('div');
    backdrop.id = 'kocm-backdrop';

    document.body.appendChild(bar);
    document.body.appendChild(panel);
    document.body.appendChild(drawer);
    document.body.appendChild(backdrop);

    // --- chip rendering (re-run when other scripts add rows, e.g. Attacks Left) ---
    function setChip(chip, label, row, fallbackLabel) {
      if (!row) { chip.hidden = true; return; }
      chip.hidden = false;
      chip.firstChild.textContent = label || fallbackLabel || row.label;
      chip.lastChild.textContent = compact(row.value);
    }

    function renderChips() {
      var rows = statsBox ? readRows(statsBox) : [];
      var find = function (re) {
        for (var i = 0; i < rows.length; i++) if (re.test(rows[i].label)) return rows[i];
        return null;
      };
      setChip(chips[0], 'Gold', find(/^gold$/i));
      setChip(chips[1], 'Turns', find(/^turns$/i));
      // Attacks Left: a stats-table row if some script adds one, else
      // DataCentre's #xp-attacks span (read-only peek), else Rank
      var third = find(/^attacks?\s*left/i);
      if (!third) {
        var xpSpan = sidebar.querySelector('#xp-attacks');
        if (xpSpan && xpSpan.textContent.trim() !== '') {
          third = { label: 'Atk Left', value: xpSpan.textContent.trim(), href: null };
        }
      }
      setChip(chips[2], null, third || find(/^rank$/i));
    }

    function renderPanel() {
      panel.textContent = '';
      var rows = statsBox ? readRows(statsBox) : [];
      rows.forEach(function (r) {
        var row = el(r.href ? 'a' : 'div', 'kocm-panel-row');
        if (r.href) row.href = r.href;
        row.appendChild(el('span', 'kocm-panel-label', r.label));
        row.appendChild(el('span', 'kocm-panel-value', r.value));
        panel.appendChild(row);
      });
      var time = serverTime();
      if (time) {
        var trow = el('div', 'kocm-panel-row kocm-muted');
        trow.appendChild(el('span', 'kocm-panel-label', 'Server Time'));
        trow.appendChild(el('span', 'kocm-panel-value', time));
        panel.appendChild(trow);
      }
    }

    // --- drawer content ---
    function renderDrawer() {
      drawer.textContent = '';

      var head = el('div');
      head.id = 'kocm-drawer-head';
      head.appendChild(el('span', null, 'KINGS OF CHAOS')).id = 'kocm-drawer-title';
      var close = el('button', null, '✕');
      close.id = 'kocm-drawer-close';
      close.setAttribute('aria-label', 'Close menu');
      close.addEventListener('click', closeAll);
      head.appendChild(close);
      drawer.appendChild(head);

      var here = location.pathname.replace(/^\//, '');
      navItems.forEach(function (item) {
        var row = el('a', 'kocm-row', item.label);
        row.href = item.href;
        if (/log ?out/i.test(item.label)) row.className += ' kocm-danger';
        if (item.href.split('?')[0] === here) row.className += ' kocm-current';
        drawer.appendChild(row);
      });

      var msgRows = msgBox ? readRows(msgBox).filter(function (r) { return r.value; }) : [];
      if (msgRows.length) {
        drawer.appendChild(el('div', 'kocm-section', 'Messages'));
        msgRows.forEach(function (r) {
          var row = el(r.href ? 'a' : 'div', 'kocm-row', r.label);
          if (r.href) row.href = r.href;
          var m = r.value.match(/(\d+)\s*new/i);
          if (m && +m[1] > 0) row.appendChild(el('span', 'kocm-badge', m[1]));
          else row.appendChild(el('span', 'kocm-row-value', r.value));
          drawer.appendChild(row);
        });
      }

      // the hidden top banner's links, so they stay reachable
      drawer.appendChild(el('div', 'kocm-section', 'Site'));
      [
        { label: 'Rankings', href: 'battlefield.php?start=0' },
        { label: 'Forum', href: 'http://forums.kingsofchaos.com/index.php' },
        { label: 'Chat (Discord)', href: 'https://discord.gg/aDQTjWE' },
        { label: 'Store', href: 'https://kingsofchaos.secure-decoration.com/shop' },
        { label: 'Help', href: 'help.php' }
      ].forEach(function (item) {
        var row = el('a', 'kocm-row', item.label);
        row.href = item.href;
        if (/^https?:/.test(item.href)) {
          row.target = '_blank';
          row.rel = 'noopener';
        }
        drawer.appendChild(row);
      });

      // jump to script-injected panels relocated below the content
      if (document.documentElement.classList.contains('kocm-extras')) {
        var jump = el('a', 'kocm-row', 'Sidebar Tools');
        jump.href = '#';
        jump.appendChild(el('span', 'kocm-row-value', '▾ below content'));
        jump.addEventListener('click', function (e) {
          e.preventDefault();
          closeAll();
          sidebar.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        drawer.appendChild(jump);
      }

      // escape hatch: stock desktop layout until toggled back via the 📱 chip
      var desktopRow = el('a', 'kocm-row', 'Desktop view');
      desktopRow.href = '#';
      desktopRow.appendChild(el('span', 'kocm-row-value', '📱 bottom-right to return'));
      desktopRow.addEventListener('click', function (e) {
        e.preventDefault();
        store.set('kocmDesktop', '1');
        location.reload();
      });
      drawer.appendChild(desktopRow);

      var logRows = logsBox ? readRows(logsBox).filter(function (r) { return r.value; }) : [];
      if (logRows.length) {
        drawer.appendChild(el('div', 'kocm-section', 'Recent Logs'));
        logRows.forEach(function (r) {
          var row = el(r.href ? 'a' : 'div', 'kocm-row', r.label);
          if (r.href) row.href = r.href;
          row.appendChild(el('span', 'kocm-row-value', r.value));
          drawer.appendChild(row);
        });
      }

      var time = serverTime();
      if (time) drawer.appendChild(el('div', 'kocm-foot', 'Server time: ' + time));
    }

    function renderBadge() {
      var total = msgBox ? countNew(readRows(msgBox)) : 0;
      menuBadge.hidden = total <= 0;
      menuBadge.textContent = total > 99 ? '99+' : String(total);
    }

    // --- open/close state ---
    var root = document.documentElement;

    function openDrawer() {
      root.classList.remove('kocm-panel-open');
      panel.hidden = true;
      renderDrawer();
      renderBadge();
      root.classList.add('kocm-drawer-open', 'kocm-lock');
    }

    function togglePanel() {
      if (root.classList.contains('kocm-panel-open')) return closeAll();
      root.classList.remove('kocm-drawer-open');
      renderPanel();
      panel.hidden = false;
      root.classList.add('kocm-panel-open', 'kocm-lock');
    }

    function closeAll() {
      root.classList.remove('kocm-drawer-open', 'kocm-panel-open', 'kocm-lock');
      panel.hidden = true;
    }

    menuBtn.addEventListener('click', openDrawer);
    statsBtn.addEventListener('click', togglePanel);
    backdrop.addEventListener('click', closeAll);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeAll();
    });

    // --- first paint + keep everything in sync with other scripts' DOM work ---
    renderChips();
    renderBadge();

    // One observer over the whole (hidden) sidebar: late-injected panels show
    // up in Sidebar Tools, and stat-row changes refresh the chips/panel.
    // Attributes aren't observed, so our own class tagging can't retrigger it.
    new MutationObserver(debounce(function () {
      tagReplicated();
      updateExtras();
      renderChips();
      renderBadge();
      if (!panel.hidden) renderPanel();
    }, 200)).observe(sidebar, { childList: true, subtree: true, characterData: true });
  }
})();
