# Armory Preference Sliders (proposal for armory.php)

A drop-in upgrade for the Armory Preferences form, written to match the site's
own code: jQuery (already loaded on every page) and plain ES5, wrapped the same
way as `action-monitor.js`.

## What it does

- Adds a 0–100% slider beside every percentage box. **The boxes stay and can
  still be typed in**; the box and its slider always show the same value.
- Live total under the table: green at 100%, yellow when some is unassigned,
  red when it is over.
- Auto-balance (on by default, can be unticked): raising one type lowers the
  others in proportion. When you type, it balances once you finish (Enter, Tab
  or click away), so typing "50" does not first balance against "5".
- A Lock tick box per type, so auto-balance never touches it.
- Preset buttons: Even Split, All Attack, All Defense, All Spy, All Sentry.
- Picks up the existing "Clear Percentage Prefills" button.

## What it does not change

- No server changes. The form posts the same `prefs[...]` fields to the same
  "Update Preferences" button, so the existing validation still applies.
- Nothing is submitted automatically.
- With JavaScript off, the form looks and works exactly as it does today.

## Installing

Add one line at the end of armory.php, after the form:

```html
<script src="armory-prefs.js?v=1.0"></script>
```

It finds the form by its `prefs[attack]` field, so it does not depend on the
table layout around it.

## Trying it

Open `demo.html` here in a browser. It is a mock of the form; the real markup
may differ.
