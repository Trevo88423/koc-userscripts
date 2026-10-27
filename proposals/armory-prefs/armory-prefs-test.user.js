// ==UserScript==
// @name         KoC Armory Preference Sliders (test)
// @namespace    trevo88423
// @version      1.1
// @author       Blackheart
// @description  Tries the armory-prefs.js proposal on the live Armory page, exactly as the site would load it. Turn off "Armory preference sliders" in the Data Centre settings while testing, or the two slider UIs clash.
// @match        https://www.kingsofchaos.com/armory.php*
// @match        https://www.kingsofchaos.org/armory.php*
// @grant        none
// @require      https://raw.githubusercontent.com/Trevo88423/koc-userscripts/ccr-8544f4b0-aq2rj4/proposals/armory-prefs/armory-prefs.js
// ==/UserScript==

// Everything is in the @require above, which runs against the page's own
// jQuery just as a <script> tag in armory.php would.
