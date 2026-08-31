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
# Macros: selection_pv (the table's selection channel), set_pv (this table's set).

from org.csstudio.display.builder.runtime.script import PVUtil, ValueUtil, ScriptUtil
from org.phoebus.pv import PVPool


def named(macro):
    name = widget.getEffectiveMacros().getValue(macro)
    return PVPool.getPV(name) if name else None


selection_pv = named("selection_pv")
set_pv = named("set_pv")
try:
    selection = selection_pv.read() if selection_pv is not None else None
    if selection is None:
        ScriptUtil.showMessageDialog(widget, "Select one or more rows in the table first.")
    else:
        labels = list(ValueUtil.getLabels(selection))
        rows = ValueUtil.getTable(selection)

        # The selection carries real cell values and the headers rather than row indices, so the
        # certificate identifier is read straight out of it and is byte-identical to the column.
        cert_at = labels.index("Certificate") if "Certificate" in labels else -1
        reason_at = labels.index("Not offered") if "Not offered" in labels else -1

        if cert_at < 0:
            ScriptUtil.showErrorDialog(widget, "The selection carries no Certificate column.")
        else:
            held = [str(x) for x in PVUtil.getStringArray(set_pv) if str(x).strip() != ""]
            refused = []
            for row in rows:
                cert_id = str(row[cert_at]).strip()
                if cert_id == "":
                    continue
                # A row the server refuses is marked on the table and cannot be added.
                if reason_at >= 0 and str(row[reason_at]).strip() != "":
                    refused.append("%s: %s" % (cert_id, str(row[reason_at]).strip()))
                    continue
                # An identifier already held is skipped, so two overlapping searches both added
                # leave one entry per certificate.
                if cert_id not in held:
                    held.append(cert_id)
            set_pv.write(held if held else [""])
            if refused:
                ScriptUtil.showMessageDialog(widget, "Not added:\n\n" + "\n".join(refused))
finally:
    for channel in (selection_pv, set_pv):
        if channel is not None:
            PVPool.releasePV(channel)
