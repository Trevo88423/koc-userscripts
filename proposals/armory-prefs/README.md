# Armory Preference Sliders (proposal for armory.php)

A drop-in upgrade for the Armory Preferences form, written to match the site's
own code: jQuery (already loaded on every page) and plain ES5, wrapped the same
way as `action-monitor.js`.

## What it does

- Adds a 0–100% slider beside every percentage box. **The boxes stay and can
  still be typed in**, decimals included (they are `step="any"`); the box and
  its slider always show the same value.
- Live total under the table: green at 100%, yellow when some is unassigned,
  red when it is over.
- Auto-balance (on by default, can be unticked): raising one type lowers the
  others in proportion, keeping whole numbers whole unless a decimal is
  already involved. When you type, it balances once you leave the box (Tab or
  click away; the page already blocks Enter), so typing "50" does not first
  balance against "5".
- A Lock tick box per type, so auto-balance never touches it.
- Preset buttons: Even Split, All Attack, All Defense, All Spy, All Sentry.
- Works with the existing "Clear Percentage Prefills" button
  (`ClearPrefillPerc()`).

## What it does not change

- No server changes. The form posts the same `prefs[...]` fields to the same
  "Update Preferences" button, so the existing validation still applies.
- Nothing is submitted automatically.
- With JavaScript off, the form looks and works exactly as it does today.

## Installing

Add one line to armory.php after the `prefillform` form:

```html
<script src="armory-prefs.js?v=1.0"></script>
```

It finds the form by `name="prefillform"` and each box by its `prefs[...]`
name, and adds one row above the Update Preferences row.

## Trying it

Open `demo.html` here in a browser. It is the Armory Preferences form copied
from the live armory.php (Era 23), styled with the live site's stylesheets.
