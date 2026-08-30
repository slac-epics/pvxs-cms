#!/usr/bin/env python3
# The simple topology plus a gateway, as Kubernetes renders it: everything the simple
# picture shows, plus an ingress zone holding the one gateway pod behind two Services -
# its own name and 'facility', the name the outside knows - and an internet segment holding
# a workstation that reaches the laboratory only through that gateway, over TLS alone.
# Every coordinate is computed here. See topology_kit for the primitives.
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'podman', 'topology'))
from topology_kit import (C, CH, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
# The three places in the zone share one address list.
ADDR1 = 'EPICS_PVA_ADDR_LIST: pvxs-lab-pvacms'
ADDR2 = '    pvxs-lab-testioc pvxs-lab-tstioc'

client_l = fields('Labels: app=lab-client zone=lab',
 'Image: lab',
 'Logins: guest, operator',
 'EPICS_PVA_AUTO_ADDR_LIST: NO', ADDR1, ADDR2,
 'Claim: lab-client-config',
 'Mounts: ConfigMaps lab-scripts, lab-issuer')
pvacms_l = fields('Labels: app=pvacms zone=lab',
 'Image: idm',
 'Mints its own authority at first start:',
 '    cert_auth.p12 on claim idm-data',
 'Access file from ConfigMap lab-acf',
 'Claims: idm-config, idm-data',
 'EPICS_PVA_AUTO_ADDR_LIST: NO', ADDR1, ADDR2,
 'Serves:',
 '    CERT:CREATE, CERT:LIST',
 '    CERT:STATUS:<issuer>:<serial>')
testioc_l = fields('Labels: app=testioc zone=lab',
 'Image: testioc',
 'EPICS_PVA_AUTO_ADDR_LIST: NO', ADDR1, ADDR2,
 'Access file from ConfigMap lab-acf',
 'Claim: testioc-config',
 'Serves:',
 '    test:aiExample, test:stringExample',
 '    test:longExample, test:enumExample',
 '    test:spec (SPECIAL), test:open (OPEN)')
tstioc_l = fields('Labels: app=tstioc zone=lab',
 'Image: tstioc',
 'EPICS_PVA_AUTO_ADDR_LIST: NO', ADDR1, ADDR2,
 'Access file from ConfigMap lab-acf',
 'Claim: tstioc-config',
 'Serves: tst:ArrayData, tst:ColorMode,',
 '    and the rest of the image database')
gateway_l = fields('Labels: app=gateway',
 'Image: gateway',
 'Program: p4p pvagw',
 'readOnly: false',
 'TLS only: EPICS_PVAS_SERVER_PORT NO,',
 '    EPICS_PVAS_TLS_PORT 5076',
 'Upstream address list: pvxs-lab-pvacms',
 '    pvxs-lab-testioc pvxs-lab-tstioc',
 'Claim: gateway-config',
 'conf and pvlist from ConfigMap gateway-config')
inet_client_l = fields('Labels: app=internet-client zone=internet',
 'Image: internet',
 'Logins: guest, operator',
 'EPICS_PVA_AUTO_ADDR_LIST: NO',
 'EPICS_PVA_NAME_SERVERS: pvas://facility:5076',
 'EPICS_PVA_TLS_OPTIONS: no_own_cert_status_check',
 'Claim: internet-client-config')

def svc_l(app):
    return fields('ClusterIP', '5075/TCP 5076/TCP 5076/UDP', f'selects app={app}')

svc_cms_l, svc_t1_l, svc_t2_l = svc_l('pvacms'), svc_l('testioc'), svc_l('tstioc')
svc_fac_l = fields('ClusterIP', '5076/TCP only', 'selects app=gateway')

# The cluster objects that carry no traffic, in a row of their own.
cm_l = fields('lab-scripts: the start scripts',
 'lab-acf: the access files',
 'gateway-config - gateway.conf and',
 '    gateway.pvlist for pvagw')
issuer_l = fields('issuer id, read back after the authority',
 'exists; pods roll to mount it')
pvc_l = fields('idm-config, idm-data, testioc-config,',
 'tstioc-config, gateway-config,',
 'lab-client-config, internet-client-config',
 'Keychains and the database outlive their',
 'pods, so a restart is the same holder')

FILE_CARDS = [('ConfigMaps', cm_l),
              ('ConfigMap lab-issuer', issuer_l),
              ('PersistentVolumeClaims', pvc_l)]

root_l = fields('Subject: CN=EPICS Root Certificate Authority',
 'SKID: ROOT_ISSUER_SKID', 'Issuer ID: ROOT_ISSUER',
 'Self-signed: it is its own issuer, and issues every',
 '    certificate in the laboratory directly',
 'File: cert_auth.p12 on claim idm-data',
 'Mounted into: pvxs-lab-pvacms')

# ---------------------------------------------------------------- legend content
CHIPS = [('client workstation pod', C['client'][1]),
         ('certificate authority - a file, mounted into a pod', C['ca'][1]),
         ('IOC pod', C['ioc'][1]),
         ('PVACMS pod - the certificate manager', C['pvacms'][1]),
         ('gateway pod - forwards PVAccess across the boundary', C['gateway'][1]),
         ('Service - a stable name and ports in front of a pod', C['lb'][1]),
         ('cluster objects - ConfigMaps, claims, policies, notes', C['file'][1])]
SAMPLES = [('Service selects pod - a short solid arrow', C['lb'][1], 2, None),
           ('PVA search and data on the lab segment', C['bus_lab'], 4, None),
           ('the outside path in - pvas:// over TLS alone', C['bus_inet'], 2.5, None),
           ('manually distributed trust_anchor.p12', C['filedrop'], 1.8, '6 5')]
NOTATION = ['5075/TCP  : PVAccess, plaintext',
            '5076/TCP  : PVAccess over TLS',
            '5076/UDP  : PVAccess search',
            'pvas://   : a PVAccess name server address, over TLS',
            'ClusterIP : a Service address that exists only',
            '            inside the cluster',
            'app=, zone= : pod labels. A Service picks its pod',
            '            by app; a NetworkPolicy admits by zone',
            '',
            'A Service name resolves inside the cluster, so the',
            'address lists name Services, not addresses.']
ABBREV = ['PVACMS : certificate manager',
          'IOC    : input output controller',
          'PVA    : PVAccess, the EPICS network protocol',
          'CNI    : container network interface, the',
          '         cluster network plugin',
          'pvagw  : the p4p gateway program',
          'conf, pvlist : the gateway configuration files']
NOTE = ['A line claims attachment. Arrowheads appear only',
        'where a direction is real.',
        '',
        'The outside workstation cannot ask the certificate',
        'manager about its own certificate, so it is told',
        'no_own_cert_status_check; the gateway checks what',
        'is presented to it instead.']

# ---------------------------------------------------------------- geometry
M = 40
TITLE_BLOCK = 108        # title, subtitle, and the cluster note
top_y = TITLE_BLOCK + 16

LEG_COL_GAP = 34
LEG_COL_L = int(max([len(t)*CH + 24 for t, _ in CHIPS] + [len(t)*CH + 50 for t, _, _, _ in SAMPLES])) + 10
LEG_COL_R = int(max(len(l)*CH for l in NOTATION + ABBREV + NOTE)) + 10
lg_w = 14 + LEG_COL_L + LEG_COL_GAP + LEG_COL_R + 14
lg_h = HDR + max(12 + len(CHIPS)*24 + 10 + len(SAMPLES)*24,
                 12 + LH + len(NOTATION)*LH + 10 + LH + len(ABBREV)*LH + 10 + len(NOTE)*LH) + 14

# The laboratory columns, exactly as the simple picture lays them.
COLS = [max(colw('lab-client', client_l), colw('svc pvxs-lab-testioc', svc_t1_l),
            colw('pvxs-lab-testioc', testioc_l)),
        max(colw('svc pvxs-lab-tstioc', svc_t2_l), colw('pvxs-lab-tstioc', tstioc_l)),
        max(colw('svc pvxs-lab-pvacms', svc_cms_l), colw('pvxs-lab-pvacms', pvacms_l))]
cxs = [0]
for w in COLS[:-1]:
    cxs.append(cxs[-1] + w + GAP)
W_lab = cxs[-1] + COLS[-1] + 2*ZP
lab_x = M

# The gateway hangs over the middle column, so its drop onto the lab bus is a straight
# line that clears the workstation card in the first column.
gw_cx = lab_x + ZP + cxs[1] + COLS[1]/2

# The ingress zone around the gateway. The facility Service stands at its right edge, so
# the drop from the workstation above enters clear of the zone's own title text.
PZ_TITLE = 'NetworkPolicy gateway-ingress'
gw_w = measure('pvxs-lab-gateway', gateway_l)[0]
fac_w = measure('svc facility', svc_fac_l)[0]
pz_w = int(max(fac_w + 2*ZP, gw_w + 2*ZP, 40 + len(PZ_TITLE)*9.0 + 30))
pz_x = gw_cx - pz_w/2
fac_cx = gw_cx

# The legend stands at the top left, the authority at the top right, and the picture starts
# below both.
legend_x, legend_y = M, top_y
root_w, root_h = measure('Root Certificate Authority', root_l)
ca_w = root_w + 2*ZP
ca_h = ZTITLE + 10 + root_h + 20
band_h = max(lg_h, ca_h)
ca_y = top_y + band_h - ca_h
band_y = top_y + band_h + 20
diagram_y = top_y + band_h + 44

# The internet zone above, centred over the facility Service so the workstation's path in
# is a straight drop.
IZ_TITLE = 'internet'
ic_w, ic_h = measure('internet-client', inet_client_l)
iz_w = int(max(ic_w + 2*ZP, 40 + len(IZ_TITLE)*9.0 + 16))
iz_h = ZTITLE + 12 + ic_h + 20
iz_x = max(M, fac_cx - iz_w/2)
iz_y = diagram_y

pz_y = iz_y + iz_h + 56
svc_row_y = pz_y + ZTITLE + 36
svc_row_h = measure('svc facility', svc_fac_l)[1]
gw_y = svc_row_y + svc_row_h + 44
gw_h = measure('pvxs-lab-gateway', gateway_l)[1]
pz_h = (gw_y - pz_y) + gw_h + ZP

zone_y = int(pz_y + pz_h + 64)

files_ws = [measure(t, l)[0] for t, l in FILE_CARDS]
files_total = sum(files_ws) + GAP*(len(files_ws) - 1)

# The by-hand line runs down the right margin, outside every zone.
nx = max(lab_x + W_lab, pz_x + pz_w, iz_x + iz_w) + 44

CANVAS_W = int(max(nx, M + files_total, M + lg_w + 40 + ca_w) + M)
ca_x = CANVAS_W - M - ca_w            # right edge, clear of the legend beside it
CANVAS_H = 0                          # set once the rows are measured

SEL = C['lb'][1]                      # the colour a Service arrow is drawn in

# ---------------------------------------------------------------- emit
def sel_arrow(cv, x, y0, y1):
    """A Service selecting its pod: a short solid drop with a hand-drawn head."""
    cv.hv([(x, y0), (x, y1 - 6)], SEL, 2)
    cv.emit(f'<path d="M {x-4.5} {y1-8} L {x+4.5} {y1-8} L {x} {y1-1} z" fill="{SEL}"/>')
    cv.pill(x + 46, (y0 + y1)/2, 'selects', SEL)


def build(cv):
    global CANVAS_H
    hdr = []

    row1_y = zone_y + ZTITLE + 34
    h_cl = measure('lab-client', client_l)[1]
    bus_y = row1_y + h_cl + 34
    svc_y = bus_y + 32
    svc_h = max(measure('svc pvxs-lab-pvacms', l)[1] for l in (svc_cms_l, svc_t1_l, svc_t2_l))
    pod_y = svc_y + svc_h + 44
    h_pods = max(measure('x', l)[1] for l in (testioc_l, tstioc_l, pvacms_l))
    zone_h = (pod_y - zone_y) + h_pods + ZP
    files_y = zone_y + zone_h + 40
    files_h = max(measure(t, l)[1] for t, l in FILE_CARDS)
    CANVAS_H = files_y + files_h + M

    LAB_TITLE = 'lab segment - NetworkPolicy lab-segment-ingress'
    assert gw_cx > lab_x + 40 + len(LAB_TITLE)*9.0 + 8, 'gateway drop crosses the lab title'

    cv.zone(lab_x, zone_y, W_lab, zone_h, LAB_TITLE, 'zone_lab')
    cv.emit(f'<text x="{lab_x+ZP}" y="{zone_y+ZTITLE+20}" font-family="Menlo,Consolas,monospace" '
            f'font-size="11" fill="{C["zone_lab"][1]}">ingress: zone=lab pods, and app=gateway</text>')
    cv.zone(iz_x, iz_y, iz_w, iz_h, IZ_TITLE, 'zone_it')
    cv.zone(pz_x, pz_y, pz_w, pz_h, PZ_TITLE, 'zone_perim')
    cv.emit(f'<text x="{pz_x+ZP}" y="{pz_y+ZTITLE+22}" font-family="Menlo,Consolas,monospace" '
            f'font-size="11" fill="{C["zone_perim"][1]}">ingress: zone=internet on 5076/TCP only</text>')

    # --- the lab segment's traffic, drawn as one bus
    bus0, bus1 = lab_x + ZP, lab_x + W_lab - ZP
    cv.hv([(bus0, bus_y), (bus1, bus_y)], C['bus_lab'], 4)
    bus_label = 'PVA search and data  5075/TCP 5076/TCP 5076/UDP'
    cv.pill(bus1 - 20 - (len(bus_label)*6.2 + 12)/2, bus_y - 16, bus_label, C['bus_lab'])

    def at(i, y, title, lines, kind, icon):
        """Centred in column i, which is what keeps the Service arrow vertical."""
        w = measure(title, lines)[0]
        return cv.card(lab_x + ZP + cxs[i] + (COLS[i] - w)/2, y, title, lines, kind, icon)

    cl = at(0, row1_y, 'lab-client', client_l, 'client', 'client')
    s1 = at(0, svc_y, 'svc pvxs-lab-testioc', svc_t1_l, 'lb', 'lb')
    s2 = at(1, svc_y, 'svc pvxs-lab-tstioc', svc_t2_l, 'lb', 'lb')
    s3 = at(2, svc_y, 'svc pvxs-lab-pvacms', svc_cms_l, 'lb', 'lb')
    t1 = at(0, pod_y, 'pvxs-lab-testioc', testioc_l, 'ioc', 'ioc')
    t2 = at(1, pod_y, 'pvxs-lab-tstioc', tstioc_l, 'ioc', 'ioc')
    pv = at(2, pod_y, 'pvxs-lab-pvacms', pvacms_l, 'pvacms', 'pvacms')

    ic = cv.card(iz_x + (iz_w - ic_w)/2, iz_y + ZTITLE + 12, 'internet-client',
                 inet_client_l, 'client', 'client')
    sf = cv.card(fac_cx - fac_w/2, svc_row_y, 'svc facility', svc_fac_l, 'lb', 'lb')
    gw = cv.card(gw_cx - gw_w/2, gw_y, 'pvxs-lab-gateway', gateway_l, 'gateway', 'gateway')

    # --- bus taps: the workstation from above, each Service from below
    cv.hv([(cl['cx'], cl['bot']), (cl['cx'], bus_y)], C['bus_lab'], 2)
    cv.dot(cl['cx'], bus_y, C['bus_lab'])
    for s in (s1, s2, s3):
        cv.hv([(s['cx'], bus_y), (s['cx'], s['top'])], C['bus_lab'], 2)
        cv.dot(s['cx'], bus_y, C['bus_lab'])

    # --- each Service selects its pod
    for s, p in ((s1, t1), (s2, t2), (s3, pv), (sf, gw)):
        sel_arrow(cv, s['cx'], s['bot'], p['top'])

    # --- the outside path in: workstation, facility Service, gateway - TLS and nothing else
    cv.hv([(ic['cx'], ic['bot']), (ic['cx'], sf['top'] - 6)], C['bus_inet'], 2.5)
    cv.emit(f'<path d="M {ic["cx"]-4.5} {sf["top"]-8} L {ic["cx"]+4.5} {sf["top"]-8} '
            f'L {ic["cx"]} {sf["top"]-1} z" fill="{C["bus_inet"]}"/>')
    cv.pill(ic['cx'], (ic['bot'] + pz_y)/2, 'pvas:// TLS only', C['bus_inet'])

    # --- the gateway is a client to the laboratory: its upstream side joins the lab bus
    cv.hv([(gw['cx'], gw['bot']), (gw['cx'], bus_y)], C['bus_lab'], 2)
    cv.dot(gw['cx'], bus_y, C['bus_lab'])
    cv.pill(gw['cx'], (pz_y + pz_h + zone_y)/2, 'client side', C['bus_lab'])

    # --- the trust anchor, carried by hand down the right margin: the one thing that
    # --- crosses the boundary without asking the gateway
    pvmid = pv['top'] + pv['h']/2
    icmid = ic['top'] + ic['h']/2
    cv.hv([(pv['x'] + pv['w'], pvmid), (nx, pvmid), (nx, icmid),
           (ic['x'] + ic['w'] + 8, icmid)], C['filedrop'], 1.8, dash='6 5')
    cv.emit(f'<path d="M {ic["x"]+ic["w"]+9} {icmid-4.5} L {ic["x"]+ic["w"]+9} {icmid+4.5} '
            f'L {ic["x"]+ic["w"]+2} {icmid} z" fill="{C["filedrop"]}"/>')
    cv.emit(f'<text x="{nx-8}" y="{pz_y-26}" text-anchor="end" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["filedrop"]}">manually distribute trust_anchor.p12</text>')
    cv.emit(f'<text x="{nx-8}" y="{pz_y-12}" text-anchor="end" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["filedrop"]}">to establish trust</text>')

    # --- the cluster objects that carry no traffic
    fx = M
    for title, lines in FILE_CARDS:
        c = cv.card(fx, files_y, title, lines, 'file', 'file')
        fx = c['x'] + c['w'] + GAP

    # --- the authority, and the line down to the pod that holds it
    cv.zone(ca_x, ca_y, ca_w, ca_h, 'Certificate Authority', 'zone_ca')
    rootc = cv.card(ca_x + ZP, ca_y + ZTITLE + 10, 'Root Certificate Authority',
                    root_l, 'ca', 'ca')
    pmid = pv['top'] + pv['h']/2
    cv.hv([(rootc['cx'], rootc['bot']), (rootc['cx'], band_y), (nx, band_y), (nx, pmid),
           (pv['x'] + pv['w'] + 3, pmid)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{nx-8}" y="{band_y+14}" text-anchor="end" '
            f'font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">'
            f'held by, and signs every certificate directly</text>')

    # --- legend. Two columns: the swatches and line kinds on the left, the notation and
    # --- the abbreviations on the right.
    lx0, ly = legend_x, legend_y
    cv.emit(f'<rect x="{lx0}" y="{ly}" width="{lg_w}" height="{lg_h}" rx="10" fill="white" stroke="#B0BEC5" stroke-width="1.4"/>')
    cv.emit(f'<path d="M {lx0} {ly+10} a10 10 0 0 1 10 -10 h{lg_w-20} a10 10 0 0 1 10 10 v{HDR-10} h-{lg_w} z" fill="#455A64"/>')
    cv.emit(f'<text x="{lx0+14}" y="{ly+20}" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" font-weight="bold" fill="white">Legend</text>')
    cv.emit(f'<line x1="{lx0+14+LEG_COL_L+LEG_COL_GAP/2}" y1="{ly+HDR+8}" x2="{lx0+14+LEG_COL_L+LEG_COL_GAP/2}" y2="{ly+lg_h-10}" stroke="#CFD8DC" stroke-width="1"/>')

    def _txt(x, y, t, bold=False, colour=None):
        b = ' font-weight="bold"' if bold else ''
        cv.emit(f'<text x="{x}" y="{y}" font-family="Menlo,Consolas,monospace" font-size="11"{b} fill="{colour or C["ink"]}" xml:space="preserve">{esc(t)}</text>')

    lcx = lx0 + 14
    yy = ly + HDR + 12 + 8
    for label, colr in CHIPS:
        cv.emit(f'<rect x="{lcx}" y="{yy-10}" width="14" height="14" rx="3" fill="{colr}"/>')
        _txt(lcx+24, yy+1, label)
        yy += 24
    yy += 10
    for label, colr, wdt, dash in SAMPLES:
        dd = f' stroke-dasharray="{dash}"' if dash else ''
        cv.emit(f'<line x1="{lcx}" y1="{yy-4}" x2="{lcx+40}" y2="{yy-4}" stroke="{colr}" stroke-width="{wdt}"{dd}/>')
        _txt(lcx+50, yy, label)
        yy += 24

    rx0 = lx0 + 14 + LEG_COL_L + LEG_COL_GAP
    yy = ly + HDR + 12 + 8
    _txt(rx0, yy, 'Notation', bold=True); yy += LH
    for l in NOTATION:
        _txt(rx0, yy, l); yy += LH
    yy += 10
    _txt(rx0, yy, 'Abbreviations', bold=True); yy += LH
    for l in ABBREV:
        _txt(rx0, yy, l); yy += LH
    yy += 10
    for l in NOTE:
        _txt(rx0, yy, l, colour='#607D8B'); yy += LH

    cv.note_card('LEGEND', lx0, ly, lg_w, lg_h)

    # --- page title, and the cluster the picture stands in
    hdr.append(f'<text x="{M}" y="40" font-family="Helvetica Neue,Arial,sans-serif" font-size="26" font-weight="bold" fill="{C["ink"]}">Secure PVAccess demonstration laboratory</text>')
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">simple with a gateway: the laboratory published at the facility Service, reached over TLS alone - example/kubernetes</text>')
    hdr.append(f'<text x="{M}" y="82" font-family="Menlo,Consolas,monospace" font-size="11" fill="#607D8B">Cluster: kind, name spva-lab, namespace spva-lab. Cilium is the network plugin.</text>')
    hdr.append(f'<text x="{M}" y="97" font-family="Menlo,Consolas,monospace" font-size="11" fill="#607D8B">The segments below are NetworkPolicy, enforced by Cilium; the default CNI of kind does not enforce policy at all.</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-simple-with-gateway.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory, simple topology with a gateway on Kubernetes - hand-drawn flat-design infographic.')
