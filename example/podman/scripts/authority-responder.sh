#!/bin/sh
# Answer for the facility root, and keep answering.
#
# `openssl ocsp -port` is a single-threaded responder written for trying things by hand. It
# serves one caller at a time, and a caller that connects and then goes away - which any client
# with a deadline will eventually do - leaves it blocked on a read it will never finish. It
# stops answering from that moment, and nothing tells it to stop: the process is alive, the port
# is open, and every connection is accepted and then ignored.
#
# The consequence in a laboratory is severe out of all proportion to the cause. Both certificate
# managers stop being able to establish the authority, every certificate beneath it is reported
# unusable, and administration stops with it - so the thing that would let you look into it is
# the thing that has stopped. Restarting the laboratory does not help for long, because the next
# caller that gives up wedges the new one.
#
# So it is watched. A caller that gets no answer is the definition of the fault, so that is the
# test: ask it, and if it does not answer, replace it. Nothing here tries to be clever about why.
set -eu

INDEX=/ocsp/index.txt
CA=/ocsp/ca.pem
SIGNER=/ocsp/signer.pem
KEY=/ocsp/signer.key
PORT=8888

# How long to give an answer before calling the responder wedged. Generous: a slow answer is
# not a fault, and replacing a working responder costs a caller its answer.
PROBE_TIMEOUT=8

# How often to ask. Often enough that a wedge is cleared well inside the fifteen seconds a
# certificate manager waits before asking again, so an outage stays invisible.
PROBE_INTERVAL=10

start_responder() {
    openssl ocsp -index "${INDEX}" -CA "${CA}" -rsigner "${SIGNER}" -rkey "${KEY}" \
                 -port "${PORT}" -nmin 1 &
    responder=$!
}

answers() {
    timeout "${PROBE_TIMEOUT}" \
        openssl ocsp -issuer "${CA}" -cert "${CA}" -url "http://127.0.0.1:${PORT}" \
                     -CAfile "${CA}" >/dev/null 2>&1
}

stop_responder() {
    kill "${responder}" 2>/dev/null || true
    wait "${responder}" 2>/dev/null || true
}

trap 'stop_responder; exit 0' TERM INT

while :; do
    start_responder
    echo "authority responder: listening on ${PORT}"

    # Let it bind before the first question, so the first probe is not the one that fails.
    sleep 2

    while :; do
        if ! kill -0 "${responder}" 2>/dev/null; then
            echo "authority responder: exited, starting another"
            break
        fi
        if ! answers; then
            echo "authority responder: stopped answering, replacing it"
            stop_responder
            break
        fi
        sleep "${PROBE_INTERVAL}"
    done
done
