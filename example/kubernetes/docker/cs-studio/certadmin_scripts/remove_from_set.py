# Take the rows currently selected in a table out of that table's set.
#
# The counterpart of add_to_set.py. It acts on the set alone and never touches the filter, so
# an administrator can correct a mistaken pick without losing the search that found it.
#
# Triggers: the button. Reads: the table's selection channel. Writes: the set channel.

from org.csstudio.display.builder.runtime.script import PVUtil, ValueUtil

selection = pvs[0].read()
set_pv = pvs[1]

if selection is not None:
    labels = list(ValueUtil.getLabels(selection))
    cert_at = labels.index("Certificate") if "Certificate" in labels else -1
    if cert_at >= 0:
        drop = set(str(row[cert_at]).strip() for row in ValueUtil.getTable(selection))
        held = [str(x) for x in PVUtil.getStringArray(set_pv)
                if str(x).strip() != "" and str(x).strip() not in drop]
        set_pv.write(held if held else [""])
