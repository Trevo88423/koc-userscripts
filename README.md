# Kings of Chaos Userscripts

![Sweet Revenge Logo](./images/SR_Logo.png)

Userscripts for [Kings of Chaos](https://www.kingsofchaos.com), made for the Sweet Revenge alliance.

## KoC Data Centre

**Version:** 3.0.1

[Install KoC Data Centre](https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/KoC-DataCentre.user.js)

Data Centre adds panels and calculators to the game's pages. It works from the pages you open yourself:
- it never presses a button, submits a form or fetches a game page for you;
- it never takes you off the game site.

Every feature and every piece of data it can send has its own switch under **⚙ Data Centre** in the sidebar.

### What it shows

**On every page**
- Live Server Time clock and an era day counter.
- A warning before each vault tax while your Vault holds gold.
- The sidebar calculator: how many attacks your Experience and Turns are worth, and the gold they could bring in.
- Rank-neighbour links on the Rank Gain numbers.

**Command Center**
- The Sweet Revenge Top Stats panel: alliance leaderboards and recon progress.
- Slaying competition panels.

**Armory**
- **Estimated Funds:** your last known gold plus the income earned since. It gives no advice.
- Rank-up costs and a Gold per Stat Point panel.
- Armory preference sliders.
- The Stat Reshuffler, a what-if calculator. It never buys or sells.
- A note when a purchase went unheld.

**Attack and Intel pages**
- The Sabotage Tracker: attempts left, the next slot, and damage left before the target is maxed.
- Range warnings from the alliance's last known ratings.
- Your average gold per attack on the Attack Log.
- Recon extras that fill "???" with the alliance's last known values.
- Alt Watch badges.

**Safe, Upgrades and Training**
- Safe forecasts and upgrade timers.
- The "Attacked Instead" comparison and the Tech Level Projector.
- Training page warnings about unheld weapons and missing mercenaries.

### What it can send, and how to switch it off

The ⚙ panel lists every share with exactly what it sends and when. Each share is sent only from a page you opened yourself. The shares are:
- your own Command Center and Armory stats;
- your account history;
- banked-% snapshots;
- recon and stats pages;
- the War List;
- attack pages and your own battle reports;
- target checks and sabotage caps;
- mission history;
- the battlefield and the Inactive Accounts page;
- competitions;
- Alt Watch flags.

The panel also has two hard switches:
- **Send data** turns every share off at once.
- **Read alliance data** stops the script fetching anything from the alliance server. The panels that need that data stay empty.

With both off, the script only shows things on your own pages. The only requests left are your login and a version check, which sends just the script's name and version.

### Logging in

The Command Center has a Sweet Revenge login box under User Info:
1. Press **Login**. The box shows a code.
2. Send that code to Blackheart-SR or Tobi-SR in an in-game message yourself.
3. The box logs you in once an admin has approved it.

You do this once per browser. Login sends your Stats ID, your name and a key made in your browser. It never asks for your game password.

---

## KoC Mobile Skin

**Version:** 1.9.3

[Install KoC Mobile Skin](https://raw.githubusercontent.com/Trevo88423/koc-userscripts/main/userscripts/koc-mobile.user.js)

Makes Kings of Chaos comfortable to play one-handed on a phone. It has no effect on desktop browsers. It only changes how pages look and are laid out.
- **Hamburger menu:** sidebar navigation in a slide-in drawer, with an unread-mail badge.
- **Sticky stats bar:** Gold, Turns and Attacks Left always on screen. Tap it to expand the full panel.
- **Phone-width pages:** Training, Command Center, Armory, Battlefield and player Stats pages reflow to fit.
- **Swipe columns:** two-column pages flip between columns with a sideways swipe, or stack.
- **Big touch targets:** larger buttons and inputs, with numeric keyboards for numbers.
- **Desktop view toggle:** switch back to the stock layout from the menu at any time.

---

## KoC Slaying Competition Tracker

No longer maintained. Competition panels are part of KoC Data Centre now.

---

## Installation

1. Install a userscript manager:
   - **Chrome / Edge:** [Tampermonkey](https://chrome.google.com/webstore/detail/tampermonkey/dhdgffkkebhmkfjojejmpbldmpobfkfo)
   - **Firefox:** [Tampermonkey](https://addons.mozilla.org/en-US/firefox/addon/tampermonkey/) or [Greasemonkey](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/)
   - **Safari / iOS:** [Userscripts](https://apps.apple.com/us/app/userscripts/id1463298887)
2. Click an install link above, and confirm in your userscript manager.
3. Open [Kings of Chaos](https://www.kingsofchaos.com).

**Updates:** your userscript manager checks for new versions and asks before installing one.

## Support

For questions or problems, contact the Sweet Revenge leadership or open an issue in this repository.

**Author:** Blackheart · **Alliance:** Sweet Revenge
