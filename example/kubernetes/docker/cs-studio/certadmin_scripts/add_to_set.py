# Add the rows currently selected in a table to that table's set.
#
# This is what replaces boolean composition. The monitored views carry no filter expression, so
# an administrator who wants "these three from one search and those two from another" cannot ask
# the server for it. Instead they narrow, pick, narrow again, pick again, and the picks
# accumulate here until they act once on everything picked.
#
# The set is held in a local string array process variable so it survives both a filter change
# and a monitor update - which is the whole reason it is held separately from the table rather
# than read back off the selection when the decision is made.
#
# Triggers: the button. Reads: the table's selection channel. Writes: the set channel.

from org.csstudio.display.builder.runtime.script import PVUtil, ValueUtil

selection = pvs[0].read()
set_pv = pvs[1]

if selection is not None:
    labels = list(ValueUtil.getLabels(selection))
    rows = ValueUtil.getTable(selection)

    # The selection carries real cell values and the headers rather than row indices, so the
    # certificate identifier is read straight out of it and is byte-identical to the column.
    cert_at = labels.index("Certificate") if "Certificate" in labels else -1
    reason_at = labels.index("Not offered") if "Not offered" in labels else -1

    if cert_at >= 0:
        current = PVUtil.getStringArray(set_pv)
        held = [str(x) for x in current if str(x).strip() != ""]

        for row in rows:
            cert_id = str(row[cert_at]).strip()
            if cert_id == "":
                continue
            # A row the server would refuse is marked on the table and cannot be added, so the
            # administrator is never asked to confirm a write that is going to come back refused.
            if reason_at >= 0 and str(row[reason_at]).strip() != "":
                continue
            # An identifier already held is skipped, so two overlapping searches both added
            # leave one entry per certificate.
            if cert_id not in held:
                held.append(cert_id)

        set_pv.write(held if held else [""])
