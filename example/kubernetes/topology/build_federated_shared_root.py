#!/usr/bin/env python3
# The federated laboratory under one facility root, as Kubernetes renders it: two department
# segments each holding a certificate manager, IOCs and a workstation; an ingress zone holding the
# two gateways; the facility load balancer whose port chooses the department; a responder that
# answers for the root; and the pre-install Job that mints the whole hierarchy exactly once.
# Every coordinate is computed here. See topology_kit for the primitives.
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'podman', 'topology'))
from topology_kit import (C, CH, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
lab_addr = 'EPICS_PVA_ADDR_LIST: pvxs-lab-pvacms'
lab_addr2 = '    pvxs-lab-testioc pvxs-lab-tstioc'
ml_addr = 'EPICS_PVA_ADDR_LIST: pvxs-lab-ml-pvacms'
ml_addr2 = '    pvxs-lab-ml-ioc'

lab_client_l = fields('Labels: app=lab-client zone=lab',
 'Image: lab', 'Logins: guest, operator',
 'EPICS_PVA_NAME_SERVERS: facility:5175',
 lab_addr, lab_addr2,
 'Claim: lab-client-config')
lab_cms_l = fields('Labels: app=pvacms zone=lab',
 'Image: idm',
 'Signs with the lab intermediate,',
 '    from Secret lab-intermediate',
 'Access file pvacms-lab.acf',
 'Claims: idm-config, idm-data',
 'Serves CERT:CREATE, CERT:LIST,',
 '    CERT:STATUS:<lab issuer>:<serial>')
testioc_l = fields('Labels: app=testioc zone=lab',
 'Image: testioc',
 'EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    facility:5175',
 'Claim: testioc-config',
 'Serves: test:aiExample, test:spec,',
 '    test:open, and the rest')
tstioc_l = fields('Labels: app=tstioc zone=lab',
 'Image: tstioc',
 'EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    facility:5175',
 'Claim: tstioc-config',
 'Serves: tst:ArrayData and the rest')
ml_client_l = fields('Labels: app=ml-client zone=ml',
 'Image: lab', 'Logins: guest, operator',
 'EPICS_PVA_NAME_SERVERS: facility:5075',
 ml_addr, ml_addr2,
 'Claim: ml-client-config')
ml_cms_l = fields('Labels: app=ml zone=ml',
 'Image: ml',
 'Signs with the ML intermediate,',
 '    from Secret ml-intermediate',
 'Access file pvacms-ml.acf',
 'Claims: ml-config, ml-data',
 'Serves CERT:CREATE, CERT:LIST,',
 '    CERT:STATUS:<ml issuer>:<serial>')
ml_ioc_l = fields('Labels: app=ml-ioc zone=ml',
 'Image: ml-ioc',
 'EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    facility:5075',
 'Claim: ml-ioc-config',
 'Serves: ml:aiExample and the rest')
gw_lab_l = fields('Labels: app=gateway',
 'Image: gateway   Program: p4p pvagw',
 'Serves 5075/TCP and 5076/TCP TLS',
 'Upstream: the lab services',
 'gateway-lab.conf carries',
 '    EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    pvxs-lab-ml-gateway:5175 - read by',
 '    the inner client alone, so nothing',
 '    else is given the route',
 'Claim: gateway-config')
gw_ml_l = fields('Labels: app=ml-gateway',
 'Image: gateway   Program: p4p pvagw',
 'Serves 5175/TCP and 5176/TCP TLS',
 'Upstream: the ML services',
 'gateway-ml.conf carries',
 '    EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    pvxs-lab-gateway:5075',
 'Claim: ml-gateway-config')
fac_l = fields('Labels: app=facility zone=facility',
 'Image: haproxy, four frontends',
 'A port is never translated: a server',
 'names its own port in a search reply,',
 'and the client dials that port next')
inet_l = fields('Labels: app=internet-client zone=internet',
 'Image: internet', 'Logins: guest, operator',
 'EPICS_PVA_NAME_SERVERS:',
 '    facility:5075 facility:5175')
resp_l = fields('Labels: app=authority-status',
 'Image: idm - runs only openssl ocsp',
 'Secret ocsp-material: ca.pem,',
 '    signer.pem, signer.key',
 'Index seeded ONCE from ConfigMap',
 '    ocsp-index-seed onto claim',
 '    ocsp-state, so a revocation',
 '    survives the responder restarting',
 'Liveness: an exec openssl ocsp',
 '    question, not a TCP probe')
job_l = fields('pre-install hook, runs before anything',
 'probe: skips when lab-issuer-ids exists -',
 '    authorities are minted once per',
 '    laboratory, not once per helm operation',
 'mint: gen_lab_certs -R root -L lab -M ml',
 '    -S http://pvxs-lab-authority-status:8888',
 '    - the responder name is minted INTO',
 '    the root; changing it means minting again',
 'package: writes the Secrets and ConfigMaps;',
 '    the root key is never packaged')

def svc(app, ports):
    return fields('ClusterIP', ports, f'selects app={app}')

svc_lab_cms_l = svc('pvacms', '5075/TCP 5076/TCP 5076/UDP')
svc_t1_l = svc('testioc', '5075/TCP 5076/TCP 5076/UDP')
svc_t2_l = svc('tstioc', '5075/TCP 5076/TCP 5076/UDP')
svc_ml_cms_l = svc('ml', '5075/TCP 5076/TCP 5076/UDP')
svc_mlioc_l = svc('ml-ioc', '5075/TCP 5076/TCP 5076/UDP')
svc_gwl_l = svc('gateway', '5075/TCP 5076/TCP 5076/UDP')
svc_gwm_l = svc('ml-gateway', '5175/TCP 5176/TCP 5176/UDP')
svc_fac_l = fields('ClusterIP  5075 5076 5175 5176/TCP',
 'selects app=facility',
 'the port chooses the department')
svc_resp_l = svc('authority-status', '8888/TCP')

secrets_l = fields('Secrets: lab-intermediate, ml-intermediate,',
 '    ocsp-material',
 'ConfigMaps: lab-issuer-ids (LAB_ISSUER,',
 '    ML_ISSUER and both SKIDs),',
 '    ocsp-index-seed, lab-scripts, lab-acf,',
 '    gateway-config')
pvc_l = fields('idm-config idm-data ml-config ml-data',
 'testioc-config tstioc-config ml-ioc-config',
 'gateway-config ml-gateway-config',
 'lab-client-config ml-client-config',
 'internet-client-config ocsp-state',
 'Keychains and databases outlive their',
 'pods, so a restart is the same holder')
facpol_l = fields('zone=lab may reach 5175, 5176 only',
 'zone=ml may reach 5075, 5076 only',
 'zone=internet may reach all four')

FILE_CARDS = [('Secrets and ConfigMaps', secrets_l),
              ('PersistentVolumeClaims', pvc_l),
              ('NetworkPolicy facility-ingress', facpol_l)]

root_l = fields('Subject: CN=EPICS Root Certificate Authority',
 'OCSP: pvxs-lab-authority-status:8888',
 '    (named in the AIA extension)',
 'Minted by Job ca-keygen, kept in the',
 '    Secrets below')
labca_l = fields('Subject: CN=EPICS Controls Intermediate CA',
 'SKID: LAB_ISSUER_SKID', 'Issuer ID: LAB_ISSUER',
 'Secret lab-intermediate',
 'Mounted into: pvxs-lab-pvacms')
mlca_l = fields('Subject: CN=EPICS ML Intermediate CA',
 'SKID: ML_ISSUER_SKID', 'Issuer ID: ML_ISSUER',
 'Secret ml-intermediate',
 'Mounted into: pvxs-lab-ml-pvacms')
signer_l = fields('Subject: CN=EPICS Root Certificate Authority',
 '    OCSP Responder',
 'Secret ocsp-material')

# ---------------------------------------------------------------- legend content
CHIPS = [('client workstation pod', C['client'][1]),
         ('IOC pod', C['ioc'][1]),
         ('PVACMS pod - the certificate manager', C['pvacms'][1]),
         ('certificate authority - a file, mounted into a pod', C['ca'][1]),
         ('gateway pod', C['gateway'][1]),
         ('responder pod - answers for the root', C['ocsp'][1]),
         ('minting Job - runs once per laboratory', C['ca'][1]),
         ('Service - a stable name in front of a pod', C['lb'][1]),
         ('cluster objects and notes', C['file'][1])]
SAMPLES = [('Service selects pod', C['lb'][1], 2, None),
           ('PVA search and data, lab segment', C['bus_lab'], 4, None),
           ('PVA search and data, ML segment', C['bus_ml'], 4, None),
           ('a department reaching its peer', C['bus_inet'], 2.5, None),
           ('peer certificate status, gateway to gateway', C['peer'], 2.5, None),
           ('is the root still good? OCSP 8888', C['cert'], 2, None),
           ('written by the Job', C['filedrop'], 1.8, '6 5')]
NOTATION = ['5075, 5076 : the lab department, plain and TLS',
            '5175, 5176 : the ML department, plain and TLS',
            'facility   : the Service in front of haproxy;',
            '             the port chooses the department',
            'app=, zone= : pod labels. A Service picks by app,',
            '             a NetworkPolicy admits by zone',
            '',
            'Only the department that issued a certificate can',
            'report on its status, so every status route crosses',
            'to the peer: an IOC asks through the facility, a',
            'gateway asks the peer gateway directly.']
ABBREV = ['PVACMS : certificate manager',
          'IOC    : input output controller',
          'OCSP   : online certificate status protocol,',
          '         how the root is answered for',
          'SKID   : subject key identifier']
NOTE = ['The root has no status process variable of its own.',
        'The responder it names is the only way its',
        'revocation reaches anything issued beneath it.']

# ---------------------------------------------------------------- geometry
M = 40
TITLE_BLOCK = 108
top_y = TITLE_BLOCK + 16

LEG_COL_GAP = 34
LEG_COL_L = int(max([len(t)*CH + 24 for t, _ in CHIPS] + [len(t)*CH + 50 for t, _, _, _ in SAMPLES])) + 10
LEG_COL_R = int(max(len(l)*CH for l in NOTATION + ABBREV + NOTE)) + 10
lg_w = 14 + LEG_COL_L + LEG_COL_GAP + LEG_COL_R + 14
lg_h = HDR + max(12 + len(CHIPS)*24 + 10 + len(SAMPLES)*24,
                 12 + LH + len(NOTATION)*LH + 10 + LH + len(ABBREV)*LH + 10 + len(NOTE)*LH) + 14

# Department columns. Lab: client+testioc / tstioc / pvacms. ML: client+ml-ioc / pvacms.
LCOLS = [max(colw('lab-client', lab_client_l), colw('svc pvxs-lab-testioc', svc_t1_l),
             colw('pvxs-lab-testioc', testioc_l)),
         max(colw('svc pvxs-lab-tstioc', svc_t2_l), colw('pvxs-lab-tstioc', tstioc_l)),
         max(colw('svc pvxs-lab-pvacms', svc_lab_cms_l), colw('pvxs-lab-pvacms', lab_cms_l))]
MCOLS = [max(colw('ml-client', ml_client_l), colw('svc pvxs-lab-ml-ioc', svc_mlioc_l),
             colw('pvxs-lab-ml-ioc', ml_ioc_l)),
         max(colw('svc pvxs-lab-ml-pvacms', svc_ml_cms_l), colw('pvxs-lab-ml-pvacms', ml_cms_l))]
lxs = [0]
for w in LCOLS[:-1]:
    lxs.append(lxs[-1] + w + GAP)
W_lab = lxs[-1] + LCOLS[-1] + 2*ZP
mxs = [0]
for w in MCOLS[:-1]:
    mxs.append(mxs[-1] + w + GAP)
W_ml = mxs[-1] + MCOLS[-1] + 2*ZP

DEPT_GAP = 72
lab_x = M + 30                       # margin for the lab client's path up to the facility
ml_x = lab_x + W_lab + DEPT_GAP

# The ingress zone spans both departments; each gateway hangs over its own department.
gwl_w = measure('pvxs-lab-gateway', gw_lab_l)[0]
gwm_w = measure('pvxs-lab-ml-gateway', gw_ml_l)[0]
svc_gwl_w = measure('svc pvxs-lab-gateway', svc_gwl_l)[0]
svc_gwm_w = measure('svc pvxs-lab-ml-gateway', svc_gwm_l)[0]
gwl_cx = lab_x + ZP + lxs[1] + LCOLS[1]/2          # over the lab middle column
gwm_cx = ml_x + ZP + mxs[1] + MCOLS[1]/2           # over the ML manager column
pz_x = lab_x - 10
pz_w = (ml_x + W_ml + 10) - pz_x

# The facility above the gateways, the internet above the facility.
fac_w = measure('pvxs-facility-lb', fac_l)[0]
svc_fac_w = measure('svc facility', svc_fac_l)[0]
fac_cx = (gwl_cx + gwm_cx)/2
inet_w, inet_h = measure('internet-client', inet_l)
IZ_TITLE = 'internet'
iz_w = int(max(inet_w + 2*ZP, 40 + len(IZ_TITLE)*9.0 + 16))
iz_h = ZTITLE + 12 + inet_h + 20
iz_x = fac_cx - iz_w/2
legend_x, legend_y = M, top_y
ca_kids = [('Lab Intermediate CA', labca_l), ('ML Intermediate CA', mlca_l),
           ('OCSP Signing Cert', signer_l)]
ca_kid_ws = [measure(t, l)[0] for t, l in ca_kids]
root_w, root_h = measure('Root Certificate Authority', root_l)
kids_w = sum(ca_kid_ws) + GAP*(len(ca_kid_ws) - 1)
kids_h = max(measure(t, l)[1] for t, l in ca_kids)
ca_w = max(kids_w, root_w) + 2*ZP
ca_h = ZTITLE + 10 + root_h + 46 + kids_h + 20
ca_x = M
ca_y = legend_y + lg_h + 34
band_y = ca_y + ca_h + 18
iz_y = ca_y + ca_h + 44

FZ_TITLE = 'facility - NetworkPolicy facility-ingress'
fz_h = ZTITLE + 30 + max(measure('svc facility', svc_fac_l)[1], measure('pvxs-facility-lb', fac_l)[1]) + ZP
fz_w = int(max(svc_fac_w + GAP + fac_w + 2*ZP, 40 + len(FZ_TITLE)*9.0 + 16))
fz_x = fac_cx - fz_w/2
fz_y = iz_y + iz_h + 56

PZ_TITLE = 'NetworkPolicies gateway-ingress and ml-gateway-ingress'
pz_y = fz_y + fz_h + 64
svcgw_y = pz_y + ZTITLE + 36
svcgw_h = max(measure('svc pvxs-lab-gateway', svc_gwl_l)[1],
              measure('svc pvxs-lab-ml-gateway', svc_gwm_l)[1])
gw_y = svcgw_y + svcgw_h + 44
gw_h = max(measure('pvxs-lab-gateway', gw_lab_l)[1], measure('pvxs-lab-ml-gateway', gw_ml_l)[1])
pz_h = (gw_y - pz_y) + gw_h + ZP

zone_y = int(pz_y + pz_h + 64)

# The responder below the departments, the files row below it, the legend last.
resp_w = measure('pvxs-lab-authority-status', resp_l)[0]
svc_resp_w = measure('svc pvxs-lab-authority-status', svc_resp_l)[0]
job_w = measure('Job ca-keygen', job_l)[0]

files_ws = [measure(t, l)[0] for t, l in FILE_CARDS]
files_total = sum(files_ws) + GAP*(len(files_ws) - 1)

CANVAS_W = int(max(ml_x + W_ml + 70, M + files_total, M + lg_w, M + ca_w,
                   M + job_w + GAP + resp_w + GAP + svc_resp_w) + M)
CANVAS_H = 0

SEL = C['lb'][1]

# ---------------------------------------------------------------- emit
def sel_arrow(cv, x, y0, y1):
    cv.hv([(x, y0), (x, y1 - 6)], SEL, 2)
    cv.emit(f'<path d="M {x-4.5} {y1-8} L {x+4.5} {y1-8} L {x} {y1-1} z" fill="{SEL}"/>')
    cv.pill(x + 46, (y0 + y1)/2, 'selects', SEL)

def head_down(cv, x, y, colour):
    cv.emit(f'<path d="M {x-4.5} {y-8} L {x+4.5} {y-8} L {x} {y-1} z" fill="{colour}"/>')


def build(cv):
    global CANVAS_H
    hdr = []

    # Department internals, laid out like the simple picture, once per department.
    row1_y = zone_y + ZTITLE + 34
    h_row1 = max(measure('lab-client', lab_client_l)[1], measure('ml-client', ml_client_l)[1])
    bus_y = row1_y + h_row1 + 34
    svc_y = bus_y + 32
    svc_h = max(measure('svc x', l)[1] for l in
                (svc_lab_cms_l, svc_t1_l, svc_t2_l, svc_ml_cms_l, svc_mlioc_l))
    pod_y = svc_y + svc_h + 44
    h_pods = max(measure('x', l)[1] for l in (testioc_l, tstioc_l, lab_cms_l, ml_cms_l, ml_ioc_l))
    zone_h = (pod_y - zone_y) + h_pods + ZP

    RZ_TITLE = 'facility root status'
    rz_y = zone_y + zone_h + 70
    rsvc_h = measure('svc pvxs-lab-authority-status', svc_resp_l)[1]
    rz_h = ZTITLE + 28 + rsvc_h + 40 + measure('pvxs-lab-authority-status', resp_l)[1] + ZP
    rz_w = int(max(resp_w, svc_resp_w) + 2*ZP)
    rz_cx = (lab_x + W_lab + ml_x)/2   # in the gap's neighbourhood, clear of both buses
    rz_x = rz_cx - rz_w/2

    files_y = rz_y + rz_h + 44
    files_h = max(measure(t, l)[1] for t, l in FILE_CARDS)
    CANVAS_H = files_y + files_h + M

    # --- zones
    LZ_TITLE = 'lab segment - NetworkPolicy lab-segment-ingress'
    MZ_TITLE = 'ML segment - NetworkPolicy ml-segment-ingress'
    cv.zone(lab_x, zone_y, W_lab, zone_h, LZ_TITLE, 'zone_lab')
    cv.zone(ml_x, zone_y, W_ml, zone_h, MZ_TITLE, 'zone_ml')
    for zx, txt, kind in ((lab_x, 'ingress: zone=lab, app=gateway, app=facility', 'zone_lab'),
                          (ml_x, 'ingress: zone=ml, app=ml-gateway, app=facility', 'zone_ml')):
        cv.emit(f'<text x="{zx+ZP}" y="{zone_y+ZTITLE+20}" font-family="Menlo,Consolas,monospace" '
                f'font-size="11" fill="{C[kind][1]}">{esc(txt)}</text>')
    cv.zone(iz_x, iz_y, iz_w, iz_h, IZ_TITLE, 'zone_it')
    cv.zone(fz_x, fz_y, fz_w, fz_h, FZ_TITLE, 'zone_ca')
    cv.zone(pz_x, pz_y, pz_w, pz_h, PZ_TITLE, 'zone_perim')
    cv.emit(f'<text x="{pz_x+ZP}" y="{pz_y+ZTITLE+22}" font-family="Menlo,Consolas,monospace" '
            f'font-size="11" fill="{C["zone_perim"][1]}">ingress: app=facility, and the peer gateway</text>')
    cv.zone(rz_x, rz_y, rz_w, rz_h, RZ_TITLE, 'zone_it')
    cv.emit(f'<text x="{rz_x+ZP}" y="{rz_y+ZTITLE+20}" font-family="Menlo,Consolas,monospace" '
            f'font-size="11" fill="{C["zone_it"][1]}">ingress: zones lab and ml, port 8888</text>')

    # --- department buses
    lb0, lb1 = lab_x + ZP, lab_x + W_lab - ZP
    mb0, mb1 = ml_x + ZP, ml_x + W_ml - ZP
    cv.hv([(lb0, bus_y), (lb1, bus_y)], C['bus_lab'], 4)
    cv.hv([(mb0, bus_y), (mb1, bus_y)], C['bus_ml'], 4)

    def at(x0, cols, cxs_, i, y, title, lines, kind, icon):
        w = measure(title, lines)[0]
        return cv.card(x0 + ZP + cxs_[i] + (cols[i] - w)/2, y, title, lines, kind, icon)

    lcl = at(lab_x, LCOLS, lxs, 0, row1_y, 'lab-client', lab_client_l, 'client', 'client')
    ls1 = at(lab_x, LCOLS, lxs, 0, svc_y, 'svc pvxs-lab-testioc', svc_t1_l, 'lb', 'lb')
    ls2 = at(lab_x, LCOLS, lxs, 1, svc_y, 'svc pvxs-lab-tstioc', svc_t2_l, 'lb', 'lb')
    ls3 = at(lab_x, LCOLS, lxs, 2, svc_y, 'svc pvxs-lab-pvacms', svc_lab_cms_l, 'lb', 'lb')
    lt1 = at(lab_x, LCOLS, lxs, 0, pod_y, 'pvxs-lab-testioc', testioc_l, 'ioc', 'ioc')
    lt2 = at(lab_x, LCOLS, lxs, 1, pod_y, 'pvxs-lab-tstioc', tstioc_l, 'ioc', 'ioc')
    lpv = at(lab_x, LCOLS, lxs, 2, pod_y, 'pvxs-lab-pvacms', lab_cms_l, 'pvacms', 'pvacms')

    mcl = at(ml_x, MCOLS, mxs, 0, row1_y, 'ml-client', ml_client_l, 'client', 'client')
    ms1 = at(ml_x, MCOLS, mxs, 0, svc_y, 'svc pvxs-lab-ml-ioc', svc_mlioc_l, 'lb', 'lb')
    ms2 = at(ml_x, MCOLS, mxs, 1, svc_y, 'svc pvxs-lab-ml-pvacms', svc_ml_cms_l, 'lb', 'lb')
    mio = at(ml_x, MCOLS, mxs, 0, pod_y, 'pvxs-lab-ml-ioc', ml_ioc_l, 'ioc', 'ioc')
    mpv = at(ml_x, MCOLS, mxs, 1, pod_y, 'pvxs-lab-ml-pvacms', ml_cms_l, 'pvacms', 'pvacms')

    # --- bus taps
    for c, colr in ((lcl, C['bus_lab']), (mcl, C['bus_ml'])):
        cv.hv([(c['cx'], c['bot']), (c['cx'], bus_y)], colr, 2)
        cv.dot(c['cx'], bus_y, colr)
    for s, colr in ((ls1, C['bus_lab']), (ls2, C['bus_lab']), (ls3, C['bus_lab']),
                    (ms1, C['bus_ml']), (ms2, C['bus_ml'])):
        cv.hv([(s['cx'], bus_y), (s['cx'], s['top'])], colr, 2)
        cv.dot(s['cx'], bus_y, colr)
    for s, p in ((ls1, lt1), (ls2, lt2), (ls3, lpv), (ms1, mio), (ms2, mpv)):
        sel_arrow(cv, s['cx'], s['bot'], p['top'])

    # --- facility and internet
    sf = cv.card(fac_cx - (svc_fac_w + GAP + fac_w)/2, fz_y + ZTITLE + 30,
                 'svc facility', svc_fac_l, 'lb', 'lb')
    fb = cv.card(sf['x'] + svc_fac_w + GAP, fz_y + ZTITLE + 30,
                 'pvxs-facility-lb', fac_l, 'lb', 'router')
    # The Service and the pod stand side by side; the selection is said, not drawn, because
    # an arrow between neighbours reads as traffic.
    cv.pill((sf['x'] + sf['w'] + fb['x'])/2, sf['top'] - 14, 'selects app=facility', SEL)
    ic = cv.card(iz_x + (iz_w - inet_w)/2, iz_y + ZTITLE + 12, 'internet-client',
                 inet_l, 'client', 'client')
    cv.hv([(ic['cx'], ic['bot']), (ic['cx'], sf['top'] - 6)], C['bus_inet'], 2.5)
    head_down(cv, ic['cx'], sf['top'], C['bus_inet'])
    cv.pill(ic['cx'], (ic['bot'] + fz_y)/2, 'facility:5075 facility:5175', C['bus_inet'])

    # --- the gateways and their Services
    sgl = cv.card(gwl_cx - svc_gwl_w/2, svcgw_y, 'svc pvxs-lab-gateway', svc_gwl_l, 'lb', 'lb')
    sgm = cv.card(gwm_cx - svc_gwm_w/2, svcgw_y, 'svc pvxs-lab-ml-gateway', svc_gwm_l, 'lb', 'lb')
    gwl = cv.card(gwl_cx - gwl_w/2, gw_y, 'pvxs-lab-gateway', gw_lab_l, 'gateway', 'gateway')
    gwm = cv.card(gwm_cx - gwm_w/2, gw_y, 'pvxs-lab-ml-gateway', gw_ml_l, 'gateway', 'gateway')
    sel_arrow(cv, sgl['cx'], sgl['bot'], gwl['top'])
    sel_arrow(cv, sgm['cx'], sgm['bot'], gwm['top'])

    # --- the facility chooses a department by port
    fan_y = fz_y + fz_h + 22
    for tgt, label in ((sgl, 'ports 5075 5076'), (sgm, 'ports 5175 5176')):
        x = tgt['cx']
        cv.hv([(sf['cx'], sf['bot']), (sf['cx'], fan_y), (x, fan_y), (x, tgt['top'] - 6)],
              C['bus_inet'], 2.5)
        head_down(cv, x, tgt['top'], C['bus_inet'])
        cv.pill(x, fan_y + 26, label, C['bus_inet'])

    # --- each gateway is a client to its own department
    for g, colr in ((gwl, C['bus_lab']), (gwm, C['bus_ml'])):
        cv.hv([(g['cx'], g['bot']), (g['cx'], bus_y)], colr, 2)
        cv.dot(g['cx'], bus_y, colr)
        cv.pill(g['cx'], (pz_y + pz_h + zone_y)/2, 'client side', colr)

    # --- the one thing that crosses sideways: peer certificate status
    ymid = gw_y + gw_h/2
    cv.hv([(gwl['x'] + gwl['w'], ymid), (gwm['x'], ymid)], C['peer'], 2.5)
    cv.pill((gwl['x'] + gwl['w'] + gwm['x'])/2, ymid - 16, 'peer certificate status', C['peer'])

    # --- each department reaches its peer through the facility, up the outer margins
    lmx = lab_x - 22
    rmx = ml_x + W_ml + 22
    cv.hv([(lcl['x'], lcl['top'] + 24), (lmx, lcl['top'] + 24), (lmx, fz_y + fz_h/2),
           (fz_x, fz_y + fz_h/2)], C['bus_inet'], 2.5)
    cv.pill(lmx, zone_y - 26, 'facility:5175 - the ML department', C['bus_inet'])
    cv.hv([(mcl['x'] + mcl['w'], mcl['top'] + 24), (rmx, mcl['top'] + 24), (rmx, fz_y + fz_h/2),
           (fz_x + fz_w, fz_y + fz_h/2)], C['bus_inet'], 2.5)
    cv.pill(rmx, zone_y - 26, 'facility:5075 - the lab department', C['bus_inet'])

    # --- the responder, and who asks it
    rsv = cv.card(rz_cx - svc_resp_w/2, rz_y + ZTITLE + 28,
                  'svc pvxs-lab-authority-status', svc_resp_l, 'lb', 'lb')
    rsp = cv.card(rz_cx - resp_w/2, rsv['bot'] + 40, 'pvxs-lab-authority-status',
                  resp_l, 'ocsp', 'ocsp')
    sel_arrow(cv, rsv['cx'], rsv['bot'], rsp['top'])
    # Straight drops into the responder zone's top edge, then the zone speaks for itself.
    for pv_ in (lpv, mpv):
        cv.hv([(pv_['cx'], pv_['bot']), (pv_['cx'], zone_y + zone_h + 34),
               (rz_cx, zone_y + zone_h + 34)], C['cert'], 2)
    cv.hv([(rz_cx, zone_y + zone_h + 34), (rz_cx, rz_y)], C['cert'], 2)
    cv.pill(rz_cx, zone_y + zone_h + 18, 'is the root still good? OCSP 8888', C['cert'])

    # --- the minting Job, beside the responder with its outputs to the right
    jb = cv.card(M, rz_y, 'Job ca-keygen', job_l, 'ca', 'ca')

    # --- the cluster objects
    fx = M
    fcards = []
    for title, lines in FILE_CARDS:
        c = cv.card(fx, files_y, title, lines, 'file', 'file')
        fcards.append((title, c))
        fx = c['x'] + c['w'] + GAP
    sec = dict(fcards)['Secrets and ConfigMaps']
    cv.hv([(jb['cx'], jb['bot']), (jb['cx'], files_y - 18), (sec['cx'], files_y - 18),
           (sec['cx'], sec['top'] - 2)], C['filedrop'], 1.8, dash='6 5')
    head_down(cv, sec['cx'], sec['top'] + 4, C['filedrop'])

    # --- the authorities
    cv.zone(ca_x, ca_y, ca_w, ca_h, 'Certificate Authorities', 'zone_ca')
    rootc = cv.card(ca_x + (ca_w - root_w)/2, ca_y + ZTITLE + 10,
                    'Root Certificate Authority', root_l, 'ca', 'ca')
    cax = ca_x + (ca_w - kids_w)/2
    kids = []
    for (title, lines), w in zip(ca_kids, ca_kid_ws):
        kids.append(cv.card(cax, rootc['bot'] + 46, title, lines, 'ca', 'ca'))
        cax += w + GAP
    # the root signs each of them
    for kid in kids:
        cv.hv([(rootc['cx'], rootc['bot']), (rootc['cx'], rootc['bot'] + 16),
               (kid['cx'], rootc['bot'] + 16), (kid['cx'], kid['top'] - 3)],
              C['cert'], 2, dash='6 5', marker=True)
    # the responder holds the signing certificate
    sx = CANVAS_W - M - 16
    cv.hv([(kids[2]['cx'], kids[2]['bot']), (kids[2]['cx'], ca_y + ca_h + 18),
           (sx, ca_y + ca_h + 18), (sx, rsp['top'] + 24), (rsp['x'] + rsp['w'] + 3, rsp['top'] + 24)],
          C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{sx-8}" y="{ca_y+ca_h+14}" text-anchor="end" '
            f'font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">'
            f'signs the status answers</text>')

    # --- legend
    lx0, ly = M, legend_y
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

    # --- title
    hdr.append(f'<text x="{M}" y="40" font-family="Helvetica Neue,Arial,sans-serif" font-size="26" font-weight="bold" fill="{C["ink"]}">Secure PVAccess demonstration laboratory</text>')
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">federated-shared-root: two departments under one facility root - example/kubernetes</text>')
    hdr.append(f'<text x="{M}" y="82" font-family="Menlo,Consolas,monospace" font-size="11" fill="#607D8B">Cluster: kind, name spva-lab, namespace spva-lab. Cilium is the network plugin.</text>')
    hdr.append(f'<text x="{M}" y="97" font-family="Menlo,Consolas,monospace" font-size="11" fill="#607D8B">The segments below are NetworkPolicy, enforced by Cilium; the default CNI of kind does not enforce policy at all.</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-federated-shared-root.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory, federated topology with one facility root, on Kubernetes - hand-drawn flat-design infographic.')
