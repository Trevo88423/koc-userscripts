(function ($) {
    'use strict';

    // =====================================================
    // ARMORY PREFERENCE SLIDERS v1.0
    // =====================================================
    //
    // Adds a slider beside every percentage box in the Armory
    // Preferences form (prefillform). The boxes stay where they are
    // and can still be typed in, decimals included; the slider and
    // the box always show the same value. Nothing here submits anything: the existing
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

    // The boxes take decimals (step="any"), so the balancing works in
    // hundredths of a percent to keep the total at exactly 100.
    function toUnits(value) {
        var n = parseFloat(value);

        if (isNaN(n)) {
            return 0;
        }
        return Math.max(0, Math.min(10000, Math.round(n * 100)));
    }

    function toPct(units) {
        return units / 100;
    }

    function getUnits(row) {
        return toUnits(row.box.val());
    }

    function setUnits(row, units) {
        row.box.val(toPct(units));
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
            .val(toPct(getUnits(row)));

        row.lock = $('<input type="checkbox">')
            .addClass('prefs-lock')
            .attr('title', 'Lock this percentage');

        // The cell already reads "[box] %", so the slider goes after that.
        box.parent().append(
            $('<span class="prefs-controls"></span>')
                .append(' ', row.slider, ' ',
                        $('<label class="prefs-lock-label"></label>')
                            .append(row.lock, ' Lock'))
        );

        // Dragging: the box follows the slider, and the others make room.
        row.slider.on('input', function () {
            self.setValue(row, toUnits(row.slider.val()));
        });

        // Typing: follow along while typing, balance once the value is
        // finished (Tab or clicking away; the page blocks Enter), so
        // typing "50" does not first balance against "5".
        box.on('input', function () {
            self.refresh();
        });

        box.on('change', function () {
            self.setValue(row, getUnits(row));
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
            $('<input type="button" class="buy_weap">')
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
            total += getUnits(row);
        });
        return total;
    };

    ArmoryPrefs.prototype.setValue = function (row, units) {
        setUnits(row, units);

        if (this.autoBalance && this.sum() > 10000) {
            this.takeFromOthers(row, this.sum() - 10000);
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
            var units = getUnits(row);

            if (row !== changed && !row.locked && units > 0) {
                pool.push(row);
                available += units;
            }
        });

        if (over >= available) {
            $.each(pool, function (i, row) {
                setUnits(row, 0);
            });
            setUnits(changed, getUnits(changed) - (over - available));
            return;
        }

        pool.sort(function (a, b) {
            return getUnits(b) - getUnits(a);
        });

        // Keep whole percentages whole: only cut in hundredths when a
        // decimal is already involved.
        var step = 100;

        $.each(pool.concat(changed), function (i, row) {
            if (getUnits(row) % 100 !== 0) {
                step = 1;
            }
        });

        var taken = 0;
        var cuts = $.map(pool, function (row) {
            var cut = Math.floor(over * getUnits(row) / available / step) * step;
            taken += cut;
            return cut;
        });

        for (var k = 0; taken < over; k++) {
            cuts[k % pool.length] += step;
            taken += step;
        }

        $.each(pool, function (i, row) {
            setUnits(row, getUnits(row) - cuts[i]);
        });
    };

    ArmoryPrefs.prototype.applyPreset = function (alloc) {
        var rows = this.rows;
        var even = Math.floor(100 / rows.length);
        var extra = 100 - even * rows.length;

        this.applyLocks(false);

        $.each(rows, function (i, row) {
            row.box.val(alloc ? (alloc[row.type] || 0)
                              : even + (i < extra ? 1 : 0));
        });
        this.refresh();
    };

    ArmoryPrefs.prototype.refresh = function () {
        var total = this.sum();
        var color = total === 10000 ? '#33cc33'
                  : (total < 10000 ? '#ffcc00' : '#ff3333');

        $.each(this.rows, function (i, row) {
            row.slider.val(toPct(getUnits(row)));
        });

        this.total
            .text(toPct(total) + '%' + (total === 10000 ? ''
                  : (total < 10000 ? ' (' + toPct(10000 - total) + '% unassigned)'
                                   : ' (' + toPct(total - 10000) + '% over)')))
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
        var form = $('form[name="prefillform"]');

        if (form.length) {
            new ArmoryPrefs(form).init();
        }
    });
})(jQuery);
