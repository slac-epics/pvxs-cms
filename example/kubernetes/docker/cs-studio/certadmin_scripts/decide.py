# Apply one decision to every certificate in a set, after one confirmation.
#
# A decision is a write of `state` to that certificate's status channel, built by concatenating
# the certificate identifier onto the status prefix. The three values are APPROVED, DENIED and
# REVOKED, which are what the certificate manager accepts; nothing else is written.
#
# Nothing is written before the confirmation, which lists every certificate, its current status
# and the status it changes to. Declining writes nothing at all. That is the same rule the
# command line tool settles, implemented here rather than shelled out to.
#
# Triggers: the action button. The action itself is the widget's `action` macro.

from org.csstudio.display.builder.runtime.script import PVUtil, ValueUtil, ScriptUtil
action = widget.getEffectiveMacros().getValue("action")
prefix = widget.getEffectiveMacros().getValue("cert_prefix")
if prefix is None or prefix == "":
    prefix = "CERT"

# A button's script is handed the widget and nothing else - no channel list - so the channels
# this decision works on are named in the button's own macros.
from org.phoebus.pv import PVPool

set_pv = PVPool.getPV(widget.getEffectiveMacros().getValue("set_pv"))
table_pv = PVPool.getPV(widget.getEffectiveMacros().getValue("table_pv"))

state_for = {"approve": "APPROVED", "deny": "DENIED", "revoke": "REVOKED"}
new_state = state_for.get(action)

held = [str(x).strip() for x in PVUtil.getStringArray(set_pv) if str(x).strip() != ""]


def now_rendered():
    # The current time in the same fixed-width year-first layout the columns are rendered in,
    # so every comparison below is a plain string comparison and nothing is parsed.
    from java.time import ZonedDateTime, ZoneOffset
    from java.time.format import DateTimeFormatter
    stamp = ZonedDateTime.now(ZoneOffset.UTC)
    return stamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + " UTC"


def outcome_of(row, labels):
    """The status this decision produces, worked out the way the server works it out."""
    if action == "revoke":
        return "REVOKED"
    if action == "deny":
        # The server writes REVOKED for a denial, so that is what is shown. Saying DENIED here
        # would name a status the certificate never reaches.
        return "REVOKED"

    def cell(name):
        return str(row[labels.index(name)]).strip() if name in labels else ""

    now = now_rendered()
    expires, issued, renew_by = cell("Expires"), cell("Issued"), cell("Renew by")
    if expires and now > expires:
        return "EXPIRED"
    if issued and now < issued:
        return "PENDING"
    if renew_by and now > renew_by:
        return "PENDING_RENEWAL"
    return "VALID"


if new_state is None:
    ScriptUtil.showErrorDialog(widget, "This button has no decision on it. That is a fault in the display.")
elif not held:
    ScriptUtil.showMessageDialog(widget, "Nothing is selected. Search for certificates and add them first.")
else:
    served = table_pv.read()
    labels = list(ValueUtil.getLabels(served)) if served is not None else []
    rows = ValueUtil.getTable(served) if served is not None else []
    cert_at = labels.index("Certificate") if "Certificate" in labels else -1
    status_at = labels.index("Status") if "Status" in labels else -1

    by_id = {}
    for row in rows:
        if cert_at >= 0:
            by_id[str(row[cert_at]).strip()] = row

    lines = ["%d certificate(s) will change:" % len(held), ""]
    for cert_id in held:
        row = by_id.get(cert_id)
        if row is None:
            lines.append("  %s  (no longer listed)" % cert_id)
        else:
            current = str(row[status_at]).strip() if status_at >= 0 else "?"
            lines.append("  %s  %s -> %s" % (cert_id, current, outcome_of(row, labels)))
    if action == "approve":
        lines += ["", "The certificate manager decides the final value for an approval,",
                  "from the certificate's own dates."]
    if action == "revoke":
        lines += ["", "A revocation cannot be undone."]

    if ScriptUtil.showConfirmationDialog(widget, "\n".join(lines)):
        # One write per certificate in listed order. A failure is reported against the
        # certificate it belongs to and does not stop the ones after it, and nothing is
        # rolled back: a decision already applied is applied.
        failures = []
        for cert_id in held:
            channel = None
            try:
                # The field is named in the channel name, which is how this client addresses a
                # structure element, rather than by writing a structure.
                channel = PVPool.getPV("pva://%s:STATUS:%s/state" % (prefix, cert_id))
                channel.write(new_state)
            except Exception as failure:
                failures.append("%s: %s" % (cert_id, failure))
            finally:
                if channel is not None:
                    PVPool.releasePV(channel)

        if failures:
            ScriptUtil.showErrorDialog(widget, "Applied %d of %d. These were refused:\n\n%s"
                                       % (len(held) - len(failures), len(held), "\n".join(failures)))
        else:
            ScriptUtil.showMessageDialog(widget, "Applied to %d certificate(s)." % len(held))
            set_pv.write([""])

PVPool.releasePV(set_pv)
PVPool.releasePV(table_pv)
