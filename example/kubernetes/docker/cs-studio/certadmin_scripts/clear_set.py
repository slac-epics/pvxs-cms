# Empty one table's set, leaving the filter exactly as it is.
#
# Macros: set_pv.

from org.phoebus.pv import PVPool

name = widget.getEffectiveMacros().getValue("set_pv")
if name:
    set_pv = PVPool.getPV(name)
    try:
        set_pv.write([""])
    finally:
        PVPool.releasePV(set_pv)
