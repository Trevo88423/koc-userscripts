(function ($) {
    'use strict';

    // =====================================================
    // ARMORY PREFERENCE SLIDERS v1.0
    // =====================================================
    //
    // Adds a slider beside every percentage box in the Armory
    // Preferences form. The boxes stay where they are and can
    // still be typed in; the slider and the box always show the
    // same value. Nothing here submits anything: the existing
    // "Update Preferences" button saves the same prefs[...]
    // fields as before. With JavaScript off the form is unchanged.

    var TYPES = ['attack', 'defend', 'spy', 'sentry',
                 'poison', 'medicine', 'theft', 'vigilance'];

    var PRESETS = [
        { label: 'Even Split',  alloc: null },
        { label: 'All Attack',  alloc: { attack: 100 } },
        { label: 'All Defense', alloc: { defend: 100 } },
        { label: 'All Spy',     alloc: { spy: 100 } },
        { label: 'All Sentry',  alloc: { sentry: 100 } }
    ];

    function toPct(value) {
        var n = parseInt(String(value).replace(/[^0-9]/g, ''), 10);

        if (isNaN(n)) {
            return 0;
        }
        return Math.max(0, Math.min(100, n));
    }

    function ArmoryPrefs(form) {
        this.form = form;
        this.rows = [];
        this.autoBalance = true;
    }

    ArmoryPrefs.prototype.init = function () {
        var self = this;

        $.each(TYPES, function (i, type) {
            var box = self.form.find('input[name="prefs[' + type + ']"]');

            if (box.length) {
                self.rows.push(self.buildRow(type, box));
            }
        });

        if (!self.rows.length) {
            return;
        }

        self.buildTotalRow();
        self.watchClearButton();
        self.refresh();
    };

    ArmoryPrefs.prototype.buildRow = function (type, box) {
        var self = this;
        var row = { type: type, box: box, locked: false };

        row.slider = $('<input type="range" min="0" max="100" step="1">')
            .addClass('prefs-slider')
            .val(toPct(box.val()));

        row.lock = $('<input type="checkbox">')
            .addClass('prefs-lock')
            .attr('title', 'Lock this percentage');

        box.after(
            $('<span class="prefs-controls"></span>')
                .append(' % ', row.slider, ' ',
                        $('<label class="prefs-lock-label"></label>')
                            .append(row.lock, ' Lock'))
        );

        // Dragging: the box follows the slider, and the others make room.
        row.slider.on('input', function () {
            self.setValue(row, toPct(row.slider.val()));
        });

        // Typing: follow along while typing, balance once the value is
        // finished (Enter, Tab or clicking away), so typing "50" does
        // not first balance against "5".
        box.on('input', function () {
            row.slider.val(toPct(box.val()));
            self.refresh();
        });

        box.on('change', function () {
            self.setValue(row, toPct(box.val()));
        });

        row.lock.on('change', function () {
            row.locked = row.lock.prop('checked');
            row.slider.prop('disabled', row.locked);
            box.prop('readonly', row.locked);
        });

        return row;
    };

    ArmoryPrefs.prototype.buildTotalRow = function () {
        var self = this;
        var lastRow = self.rows[self.rows.length - 1].box.closest('tr');
        var cells = lastRow.children('td, th').length || 1;
        var presets = $('<span class="prefs-presets"></span>');

        self.total = $('<b class="prefs-total"></b>');

        self.balance = $('<input type="checkbox" checked>')
            .on('change', function () {
                self.autoBalance = $(this).prop('checked');
            });

        $.each(PRESETS, function (i, preset) {
            $('<input type="button">')
                .val(preset.label)
                .on('click', function () {
                    self.applyPreset(preset.alloc);
                })
                .appendTo(presets);
            presets.append(' ');
        });

        lastRow.after(
            $('<tr class="prefs-total-row"></tr>').append(
                $('<td align="center"></td>')
                    .attr('colspan', cells)
                    .append('Total: ', self.total, '<br>',
                            $('<label></label>').append(
                                self.balance,
                                ' Auto-balance (raising one lowers the others)'),
                            '<br>', presets)
            )
        );
    };

    ArmoryPrefs.prototype.sum = function () {
        var total = 0;

        $.each(this.rows, function (i, row) {
            total += toPct(row.box.val());
        });
        return total;
    };

    ArmoryPrefs.prototype.setValue = function (row, value) {
        row.box.val(value);
        row.slider.val(value);

        if (this.autoBalance && this.sum() > 100) {
            this.takeFromOthers(row, this.sum() - 100);
        }
        this.refresh();
    };

    // Lowers the unlocked rows (largest first, in proportion to their
    // size) until the total is back to 100. If there is not enough to
    // take, the row being changed is capped instead.
    ArmoryPrefs.prototype.takeFromOthers = function (changed, over) {
        var pool = [];
        var available = 0;

        $.each(this.rows, function (i, row) {
            var pct = toPct(row.box.val());

            if (row !== changed && !row.locked && pct > 0) {
                pool.push(row);
                available += pct;
            }
        });

        if (over >= available) {
            $.each(pool, function (i, row) {
                row.box.val(0);
            });
            changed.box.val(toPct(changed.box.val()) - (over - available));
            return;
        }

        pool.sort(function (a, b) {
            return toPct(b.box.val()) - toPct(a.box.val());
        });

        var taken = 0;
        var cuts = $.map(pool, function (row) {
            var cut = Math.floor(over * toPct(row.box.val()) / available);
            taken += cut;
            return cut;
        });

        for (var k = 0; taken < over; k++) {
            cuts[k % pool.length]++;
            taken++;
        }

        $.each(pool, function (i, row) {
            row.box.val(toPct(row.box.val()) - cuts[i]);
        });
    };

    ArmoryPrefs.prototype.applyPreset = function (alloc) {
        var rows = this.rows;
        var even = Math.floor(100 / rows.length);
        var extra = 100 - even * rows.length;

        $.each(rows, function (i, row) {
            var value = alloc ? (alloc[row.type] || 0)
                              : even + (i < extra ? 1 : 0);

            row.locked = false;
            row.lock.prop('checked', false);
            row.slider.prop('disabled', false);
            row.box.prop('readonly', false).val(value);
        });
        this.refresh();
    };

    ArmoryPrefs.prototype.refresh = function () {
        var total = this.sum();
        var color = total === 100 ? '#33cc33'
                  : (total < 100 ? '#ffcc00' : '#ff3333');

        $.each(this.rows, function (i, row) {
            row.slider.val(toPct(row.box.val()));
        });

        this.total
            .text(total + '%' + (total === 100 ? ''
                  : (total < 100 ? ' (' + (100 - total) + '% unassigned)'
                                 : ' (' + (total - 100) + '% over)')))
            .css('color', color);
    };

    // The page's own "Clear Percentage Prefills" button empties the
    // boxes; pick up the new values once it has run.
    ArmoryPrefs.prototype.watchClearButton = function () {
        var self = this;

        self.form.find('input[type="submit"], input[type="button"], button')
            .filter(function () {
                return /Clear Percentage Prefills/i
                    .test($(this).val() || $(this).text());
            })
            .on('click', function () {
                setTimeout(function () {
                    self.applyLocks(false);
                    self.refresh();
                }, 0);
            });
    };

    ArmoryPrefs.prototype.applyLocks = function (locked) {
        $.each(this.rows, function (i, row) {
            row.locked = locked;
            row.lock.prop('checked', locked);
            row.slider.prop('disabled', locked);
            row.box.prop('readonly', locked);
        });
    };

    $(function () {
        var form = $('input[name="prefs[attack]"]').closest('form');

        if (form.length) {
            new ArmoryPrefs(form).init();
        }
    });
})(jQuery);
