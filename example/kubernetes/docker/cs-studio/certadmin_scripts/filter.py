# Narrow one certificate table, in a script, over the table already received.
#
# The table widget can neither sort nor filter and offers no search, so everything below the
# table is done here. Each update from the certificate manager carries the whole table, so a
# filter applied once is wiped by the next post: this script is triggered by the served channel
# as well as by the three filter inputs, and re-applies the filter every time. That is the one
# way this display can silently go wrong - showing rows that no longer match while looking
# correct - so it is arranged to be impossible rather than left to remember.
#
# Triggers, in order: the served view channel, the search box, the after date, the before date.
# The date bound applies to the column named by the widget's date_column macro: Issued on the
# awaiting-decision table, where every row is pending and nothing else is meaningful, and
# Expires on the issued table, which is the question asked of an issued certificate.

from org.csstudio.display.builder.runtime.script import PVUtil, ValueUtil, ScriptUtil

served = pvs[0].read()
search = PVUtil.getString(pvs[1]).strip().lower()
after = PVUtil.getString(pvs[2]).strip()
before = PVUtil.getString(pvs[3]).strip()

date_column = widget.getEffectiveMacros().getValue("date_column")
if date_column is None or date_column == "":
    date_column = "Expires"

if served is None:
    widget.setValue([])
else:
    labels = list(ValueUtil.getLabels(served))
    rows = ValueUtil.getTable(served)

    def column_of(name):
        return labels.index(name) if name in labels else -1

    subject_at = column_of("Subject")
    cert_at = column_of("Certificate")
    request_at = column_of("Request")
    date_at = column_of(date_column)

    def matches(row):
        # The three inputs combine with an implicit "and", and an empty input places no
        # condition at all.
        if search:
            hit = False
            for at in (subject_at, cert_at, request_at):
                if at >= 0 and search in str(row[at]).lower():
                    hit = True
                    break
            if not hit:
                return False
        if (after or before) and date_at >= 0:
            # A plain string comparison against the rendered column. The layout is fixed width
            # and year first, so a partial bound such as 2026-07 works by prefix and no date
            # parsing is needed anywhere.
            rendered = str(row[date_at])
            if after and rendered < after:
                return False
            if before and rendered > before:
                return False
        return True

    kept = [[str(cell) for cell in row] for row in rows if matches(row)]
    widget.setValue(kept)

    try:
        count = ScriptUtil.findWidgetByName(widget, str(widget.getName()) + "_count")
        count.setPropertyValue("text", "%d of %d shown" % (len(kept), len(rows)))
    except Exception:
        pass  # the count label is a convenience, not a condition of filtering
