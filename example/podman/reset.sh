#!/bin/bash
# Return the laboratory to the state it is in immediately after a fresh build, so a
# demonstration can be run from the top.
#
# Every certificate the laboratory has issued is discarded, along with every keychain the
# services hold, so nothing is trusted by anything until the certificates are issued again.
# The two departmental certificate authorities are kept, so the issuer ids stay the same and
# anything written down about them still applies.
#
#   ./reset.sh                discard the certificates, keep the authorities
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

echo
echo "The laboratory is running with no certificates issued."
sed 's/^/    /' .env 2>/dev/null || true
echo
echo "Reading works now, from anywhere, over plain TCP:"
echo "    podman exec podman_lab-client_1       bash -c 'pvxget test:aiExample'"
echo "    podman exec podman_perimeter-client_1 bash -c 'pvxget ml:aiExample'"
echo
echo "Writing is refused until an identity is issued. Follow 'Issue the certificates'."
