#!/bin/bash
# Return the laboratory to the state it is in immediately after a fresh build, so a
# demonstration can be run from the top.
#
# Every certificate the laboratory has issued is discarded, along with every keychain the
# services hold, so nothing is trusted by anything until the certificates are issued again.
# The two departmental certificate authorities are kept, so the issuer ids stay the same and
# anything written down about them still applies.
#
#   ./reset.sh              discard the certificates, keep the authorities
#   ./reset.sh --authorities  mint new authorities as well; the issuer ids change
#
set -euo pipefail
cd "$(dirname "$0")"

new_authorities=no
[ "${1:-}" = "--authorities" ] && new_authorities=yes

echo "==> stopping the laboratory and discarding its volumes"
# The volumes hold every issued keychain, the certificate databases, and the administrator
# identity each certificate manager created for itself.
podman-compose down -v >/dev/null 2>&1 || true

if [ "${new_authorities}" = yes ]; then
    echo "==> minting new certificate authorities"
    ./bootstrap.sh >/dev/null
else
    [ -s certs/lab_intermediate.p12 ] || {
        echo "no certificate authorities in ./certs - run ./bootstrap.sh first" >&2; exit 1; }
    echo "==> keeping the existing certificate authorities"
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

# A gateway that starts before its department is serving does not retry, so it is started
# last, once everything it forwards to is up.
echo "==> restarting the gateways"
podman-compose restart pvxs-lab-gateway pvxs-lab-ml-gateway >/dev/null 2>&1
sleep 10

echo
echo "The laboratory is running with no certificates issued."
sed 's/^/    /' .env 2>/dev/null || true
echo
echo "Reading works now, from anywhere, over plain TCP:"
echo "    podman exec podman_lab-client_1       bash -c 'pvxget test:aiExample'"
echo "    podman exec podman_perimeter-client_1 bash -c 'pvxget ml:aiExample'"
echo
echo "Writing is refused until an identity is issued. Follow 'Issue the certificates'."
