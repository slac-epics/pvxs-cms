# Make both departments' certificate issuer ids available to every interactive login.
#
# This is the two-department counterpart of epics-issuer.sh next to it. A pod that serves one
# department is given one issuer id and a pod-level EPICS_PVA_AUTH_ISSUER; a pod that carries a
# user per department cannot have a pod-level value, because the right answer differs by user.
# Such a pod mounts both ids under /etc/epics/issuers/ and each user's profile selects one.
#
# A login shell (su - <user>) resets the environment, so the values are read from the files
# rather than inherited.
for _issuer_key in LAB_ISSUER ML_ISSUER; do
    _issuer_file="/etc/epics/issuers/${_issuer_key}"
    if [ -r "${_issuer_file}" ]; then
        eval "${_issuer_key}=\$(cat \"\${_issuer_file}\")"
        export "${_issuer_key}"
    fi
done
unset _issuer_key _issuer_file
