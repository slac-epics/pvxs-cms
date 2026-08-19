# Hide every control this zone cannot use.
#
# A gateway makes its upstream connection as itself, so from the internet zone the certificate
# manager sees the gateway rather than the administrator behind it: the view of certificates
# awaiting a decision is refused at channel creation and a decision write is refused. Rather
# than show controls that are going to come back refused, the display is opened there with
# decisions turned off and those controls are removed from it.
#
# Triggers: the local process variable carrying the display's decisions macro.

from org.csstudio.display.builder.runtime.script import PVUtil, ScriptUtil

carries_decisions = PVUtil.getString(pvs[0]).strip().lower() in ("yes", "true", "1")

hide_when_off = ["PendingTab", "IssuedActions", "IssuedSet", "IssuedSetLabel",
                 "IssuedAdd", "IssuedRemove", "IssuedClear", "IssuedRevoke"]

for name in hide_when_off:
    try:
        ScriptUtil.findWidgetByName(widget, name).setPropertyValue("visible", carries_decisions)
    except Exception:
        pass  # a widget this display does not carry is not an error

try:
    note = ScriptUtil.findWidgetByName(widget, "ZoneNote")
    note.setPropertyValue("visible", not carries_decisions)
except Exception:
    pass
