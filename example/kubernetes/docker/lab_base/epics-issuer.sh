# Make the department's certificate issuer available to every interactive login.
#
# The issuer id (the hex identifier of the department's intermediate certificate
# authority) is generated per deployment by the ca-keygen job and delivered to each
# pod as the file /etc/epics/issuer. A login shell (su - <user>) resets the
# environment, so the pod-level EPICS_PVA_AUTH_ISSUER is not visible to the user;
# reading it from the file here restores it for authnkrb / authnstd / pvxcert.
if [ -z "${EPICS_PVA_AUTH_ISSUER:-}" ] && [ -r /etc/epics/issuer ]; then
    EPICS_PVA_AUTH_ISSUER="$(cat /etc/epics/issuer)"
    export EPICS_PVA_AUTH_ISSUER
fi
