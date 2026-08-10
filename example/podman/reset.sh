#!/bin/bash
# Return the laboratory to the state it is in immediately after a fresh build, so a
# demonstration can be run from the top.
#
# Every certificate the laboratory has issued is discarded, along with every keychain the
# services hold, so nothing is trusted by anything until the certificates are issued again.
# The two departmental certificate authorities are kept, so the issuer ids stay the same and
# anything written down about them still applies.
#
# The certificates are issued too, and everything is restarted in the order that makes them
# take effect, so what you get back is a laboratory that works rather than one that needs a
# remembered sequence run after it.
#
#   ./reset.sh                discard the certificates, keep the authorities
#   ./reset.sh --authorities  mint new authorities as well; the issuer ids change
#   ./reset.sh --no-certs     stop after starting, issue nothing (the old behaviour)
#
set -euo pipefail
cd "$(dirname "$0")"

new_authorities=no
issue_certs=yes
for arg in "$@"; do
    case "${arg}" in
        --authorities) new_authorities=yes ;;
        --no-certs)    issue_certs=no ;;
        *) echo "usage: ./reset.sh [--authorities] [--no-certs]" >&2; exit 2 ;;
    esac
done

echo "==> stopping the laboratory and discarding its volumes"
# The volumes hold every issued keychain, the certificate databases, and the administrator
# identity each certificate manager created for itself.
podman-compose down -v >/dev/null 2>&1 || true

if [ "${new_authorities}" = yes ]; then
    echo "==> minting new certificate authorities"
    # Authorities only. The images are already built and nothing here changes them, so a
    # full bootstrap would recompile EPICS Base, pvxs, pvxs-cms and p4p to hand out a new
    # pair of keys, which is where the Kerberos and gateway output people see comes from.
    ./bootstrap.sh --certs-only >/dev/null
else
    [ -s certs/lab_intermediate.p12 ] || {
        echo "no certificate authorities in ./certs - run ./bootstrap.sh first" >&2; exit 1; }
    echo "==> keeping the existing certificate authorities"
fi

# A demonstration may have left the facility root revoked, and a laboratory that starts with a
# revoked authority issues nothing. Put it back.
if [ -s ocsp/index.txt ] && [ "$(cut -f1 ocsp/index.txt)" != V ]; then
    echo "==> putting the facility root back"
    awk -F'\t' 'BEGIN{OFS="\t"} {print "V", $2, "", $4, $5, $6}' ocsp/index.txt > ocsp/index.new
    mv ocsp/index.new ocsp/index.txt
fi

echo "==> starting the laboratory"
podman-compose up -d >/dev/null 2>&1

# Each certificate manager creates its own administrator identity on first start, and the
# controllers need a moment before anything should be asked of them.
echo "==> waiting for the certificate managers"
for i in $(seq 1 30); do
    if podman exec podman_pvxs-lab-pvacms_1 test -s /home/idm/.config/pva/1.5/admin.p12 2>/dev/null \
    && podman exec podman_pvxs-lab-ml_1     test -s /home/idm/.config/pva/1.5/admin.p12 2>/dev/null; then
        break
    fi
    sleep 2
done

# A gateway that starts before its department is serving does not retry, so the gateways go
# last, once everything they forward to is up.
echo "==> restarting the gateways"
podman-compose restart pvxs-lab-gateway pvxs-lab-ml-gateway >/dev/null 2>&1
sleep 10

# The authority has to be established before anything can be issued, and a laboratory that
# looks up but cannot establish it is the worst state to hand back: every certificate is
# reported unusable, and administration stops with them, so the tools that would show you why
# have stopped too. Prove it works rather than assume it.
echo "==> checking the facility root can be established"
authority_ok=no
for i in $(seq 1 12); do
    if podman exec podman_pvxs-lab-authority-status_1 \
        timeout 8 openssl ocsp -issuer /ocsp/ca.pem -cert /ocsp/ca.pem \
                               -url http://127.0.0.1:8888 -CAfile /ocsp/ca.pem >/dev/null 2>&1; then
        authority_ok=yes
        break
    fi
    sleep 5
done
if [ "${authority_ok}" != yes ]; then
    echo "    the responder for the facility root is not answering." >&2
    echo "    Nothing can be issued until it does. Look at:" >&2
    echo "        podman logs podman_pvxs-lab-authority-status_1" >&2
    exit 1
fi

# The managers ask again every fifteen seconds after a failure, so give them one round to
# notice, then check the thing a person would actually try first.
echo "==> waiting for the certificate managers to agree"
listing_ok=no
for i in $(seq 1 12); do
    if podman exec podman_pvxs-lab-pvacms_1 \
        bash -lc 'EPICS_PVA_TLS_KEYCHAIN=/home/idm/.config/pva/1.5/admin.p12 pvxcert -l' >/dev/null 2>&1; then
        listing_ok=yes
        break
    fi
    sleep 5
done
if [ "${listing_ok}" != yes ]; then
    echo "    the certificate manager will not answer its administrator." >&2
    echo "    That is what a facility root nobody can establish looks like. Look at:" >&2
    echo "        podman logs podman_pvxs-lab-pvacms_1 | grep -i 'authority status'" >&2
    exit 1
fi

# Named the way a shell names them, which is not how the file spells them.
# shellcheck source=helpers.sh
. ./helpers.sh
lab_ids_show
echo
if [ "${new_authorities}" = yes ]; then
    # A shell that read the old ones still holds them, and nothing here can reach into it.
    echo "These are new. A shell that already read the old ones still holds them, so in each"
    echo "one that has, run:"
    echo "    lab_ids"
    echo
fi

# ------------------------------------------------------------------ issue the certificates
# Everything below is what a person would otherwise have to remember to run after a reset,
# in the one order that works. Two things make the order matter, and neither announces
# itself: a service that is handed its first certificate while it is running does not load
# it until it restarts, and a name server address is resolved once at startup, so anything
# pointing at a gateway has to restart after that gateway does.
if [ "${issue_certs}" = yes ]; then
    lab_ids >/dev/null 2>&1 || true
    echo "==> issuing the certificates"
    run_in testioc as testioc authnstd -u ioc >/dev/null 2>&1 || true
    run_in tstioc  as tstioc  authnstd -u ioc >/dev/null 2>&1 || true
    run_in ml-ioc  as mlioc   authnstd -u ioc >/dev/null 2>&1 || true
    run_in lab-manager as admin pvxcert --review-pending --all approve --yes >/dev/null 2>&1 || true
    run_in ml-manager  as admin pvxcert --review-pending --all approve --yes >/dev/null 2>&1 || true

    run_in gateway    as gateway authnstd -u ioc >/dev/null 2>&1 || true
    run_in ml-gateway as gateway authnstd -u ioc -n ml-gateway >/dev/null 2>&1 || true

    run_in lab       as operator    authnstd -u client --ou lab --issuer "${LAB_SKID}" >/dev/null 2>&1 || true
    run_in ml        as guest       authnstd -u client >/dev/null 2>&1 || true
    run_in perimeter as operator    authnstd -u client --issuer "${ML_SKID}" >/dev/null 2>&1 || true
    run_in lab       as ml/operator authnstd -u client --ou ml --issuer "${ML_SKID}" >/dev/null 2>&1 || true

    run_in lab-manager as admin pvxcert --review-pending --all approve --yes >/dev/null 2>&1 || true
    run_in ml-manager  as admin pvxcert --review-pending --all approve --yes >/dev/null 2>&1 || true

    # The controllers first, so they hold what they were just issued, then the gateways once
    # the controllers are serving again. The workstations need nothing: a command is a fresh
    # process that reads its keychain and resolves its name servers when it runs.
    echo "==> restarting so each service holds what it was issued"
    podman restart podman_pvxs-lab-testioc_1 podman_pvxs-lab-tstioc_1 podman_pvxs-lab-ml-ioc_1 >/dev/null 2>&1
    sleep 8
    podman restart podman_pvxs-lab-gateway_1 podman_pvxs-lab-ml-gateway_1 >/dev/null 2>&1
    sleep 10

    echo
    echo "The laboratory is running, with every identity issued and in place."
    echo "Two of them are deliberately left without one, for the sections that need that:"
    echo "    the lab guest, and the perimeter guest."
else
    echo
    echo "The laboratory is running with no certificates issued."
fi

echo "Reading works now, from anywhere, over plain TCP:"
echo "    podman exec podman_lab-client_1       bash -c 'pvxget test:aiExample'"
echo "    podman exec podman_perimeter-client_1 bash -c 'pvxget ml:aiExample'"
echo
if [ "${issue_certs}" = yes ]; then
    echo "Writing works for anyone holding an identity:"
    echo "    run_in lab as operator pvxput test:open 5"
else
    echo "Writing is refused until an identity is issued. Follow 'Issue the certificates'."
fi
