# Take the rows currently selected in a table out of that table's set.
#
# The counterpart of add_to_set.py. It acts on the set alone and never touches the filter, so
# an administrator can correct a mistaken pick without losing the search that found it.
#
# Macros: selection_pv, set_pv.

from org.csstudio.display.builder.runtime.script import PVUtil, ValueUtil
from org.phoebus.pv import PVPool


def named(macro):
    name = widget.getEffectiveMacros().getValue(macro)
    return PVPool.getPV(name) if name else None


selection_pv = named("selection_pv")
set_pv = named("set_pv")
try:
    selection = selection_pv.read() if selection_pv is not None else None
    if selection is not None:
        labels = list(ValueUtil.getLabels(selection))
        cert_at = labels.index("Certificate") if "Certificate" in labels else -1
        if cert_at >= 0:
            drop = set(str(row[cert_at]).strip() for row in ValueUtil.getTable(selection))
            held = [str(x) for x in PVUtil.getStringArray(set_pv)
                    if str(x).strip() != "" and str(x).strip() not in drop]
            set_pv.write(held if held else [""])
finally:
    for channel in (selection_pv, set_pv):
        if channel is not None:
            PVPool.releasePV(channel)
