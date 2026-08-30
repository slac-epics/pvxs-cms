#!/usr/bin/env python3
# The federated laboratory under two independent roots, as Kubernetes renders it: the same
# two departments, but no facility root above them and nothing shared. Each keychain holds
# BOTH roots as trust anchors, so trust comes from the anchor list rather than from a chain.
# There is no load balancer and no responder: the gateways are addressed by name.
# Every coordinate is computed here. See topology_kit for the primitives.
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'podman', 'topology'))
from topology_kit import (C, CH, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
lab_client_l = fields('Labels: app=lab-client zone=lab',
 'Image: lab', 'Logins: guest, operator',
 'EPICS_PVA_NAME_SERVERS:',
 '    pvxs-lab-ml-gateway:5075',
 'EPICS_PVA_AUTH_ISSUER: both SKIDs',
 'Claim: lab-client-config')
lab_cms_l = fields('Labels: app=pvacms zone=lab',
 'Image: idm',
 'Signs with the Controls intermediate,',
 '    from Secret lab-intermediate;',
 '    the lab root above it',
 'Access file pvacms-lab.acf',
 'Claims: idm-config, idm-data')
testioc_l = fields('Labels: app=testioc zone=lab',
 'Image: testioc',
 'EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    pvxs-lab-ml-gateway:5075',
 'Access file testioc.acf, naming',
 '    BOTH roots',
 'Anchors: /certs/trust_anchors.p12',
 'Claim: testioc-config',
 'Serves: test:aiExample, test:spec,',
 '    test:open, and the rest')
tstioc_l = fields('Labels: app=tstioc zone=lab',
 'Image: tstioc',
 'EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    pvxs-lab-ml-gateway:5075',
 'Access file tstioc.acf',
 'Anchors: /certs/trust_anchors.p12',
 'Claim: tstioc-config')
ml_client_l = fields('Labels: app=ml-client zone=ml',
 'Image: lab', 'Logins: guest, operator',
 'EPICS_PVA_NAME_SERVERS:',
 '    pvxs-lab-gateway:5075',
 'EPICS_PVA_AUTH_ISSUER: both SKIDs',
 'Claim: ml-client-config')
ml_cms_l = fields('Labels: app=ml zone=ml',
 'Image: ml',
 'Signs with its OWN ROOT, from',
 '    Secret ml-root - this department',
 '    answers for itself all the way up',
 'Access file pvacms-ml.acf',
 'Claims: ml-config, ml-data')
ml_ioc_l = fields('Labels: app=ml-ioc zone=ml',
 'Image: ml-ioc',
 'EPICS_PVAS_STATUS_NAME_SERVERS:',
 '    pvxs-lab-gateway:5075',
 'Access file mlioc.acf',
 'Anchors: /certs/trust_anchors.p12',
 'Claim: ml-ioc-config')
gw_lab_l = fields('Labels: app=gateway',
 'Image: gateway   Program: p4p pvagw',
 'Serves 5075/TCP and 5076/TCP TLS',
 'Upstream: the lab services',
 'gateway.acf names BOTH roots:',
 '    LAB_CA and ML_CA',
 'pvlist: issuer-qualified CERT names',
 'Anchors: /certs/trust_anchors.p12',
 'Claim: gateway-config')
gw_ml_l = fields('Labels: app=ml-gateway',
 'Image: gateway   Program: p4p pvagw',
 'Serves 5075/TCP and 5076/TCP TLS',
 'Upstream: the ML services',
 'gateway.acf names BOTH roots',
 'pvlist: issuer-qualified CERT names',
 'Anchors: /certs/trust_anchors.p12',
 'Claim: ml-gateway-config')
inet_l = fields('Labels: app=internet-client zone=internet',
 'Image: internet', 'Logins: guest, operator',
 'EPICS_PVA_NAME_SERVERS:',
 '    pvxs-lab-gateway:5075',
 '    pvxs-lab-ml-gateway:5075')
job_l = fields('pre-install hook, runs before anything',
 'probe: skips when lab-issuer-ids exists -',
 '    authorities are minted once per',
 '    laboratory, not once per helm operation',
 'mint: gen_lab_certs makes the lab root and',
 '    the Controls intermediate; the lab',
 '    root key is then discarded',
 'mint: pvacms itself makes the ML root,',
 '    key included - that department signs',
 '    with its root directly',
 'package: both roots, without keys, become',
 '    Secret trust-anchors')
anchors_l = fields('Secret trust-anchors: trust_anchors.p12,',
 'both roots, mounted into every IOC,',
 'gateway and workstation.')

def svc(app, ports):
    return fields('ClusterIP', ports, f'selects app={app}')

svc_lab_cms_l = svc('pvacms', '5075/TCP 5076/TCP 5076/UDP')
svc_t1_l = svc('testioc', '5075/TCP 5076/TCP 5076/UDP')
svc_t2_l = svc('tstioc', '5075/TCP 5076/TCP 5076/UDP')
svc_ml_cms_l = svc('ml', '5075/TCP 5076/TCP 5076/UDP')
svc_mlioc_l = svc('ml-ioc', '5075/TCP 5076/TCP 5076/UDP')
svc_gwl_l = svc('gateway', '5075/TCP 5076/TCP 5076/UDP')
svc_gwm_l = svc('ml-gateway', '5075/TCP 5076/TCP 5076/UDP')

secrets_l = fields('Secrets: lab-intermediate, ml-root,',
 '    trust-anchors',
 'ConfigMaps: lab-issuer-ids (LAB_ISSUER,',
 '    ML_ISSUER and both SKIDs), lab-scripts,',
 '    lab-acf (per-place access files),',
 '    gateway-config')
pvc_l = fields('idm-config idm-data ml-config ml-data',
 'testioc-config tstioc-config ml-ioc-config',
 'gateway-config ml-gateway-config',
 'lab-client-config ml-client-config',
 'internet-client-config',
 'Keychains and databases outlive their',
 'pods, so a restart is the same holder')

FILE_CARDS = [('Secrets and ConfigMaps', secrets_l),
              ('PersistentVolumeClaims', pvc_l)]

lab_root_l = fields('Subject: CN=EPICS Lab Root Certificate Authority',
 'Signs the Lab intermediate, which signs',
 '    every Lab certificate',
 'Rotated independently of the ML root')
labca_l = fields('Subject: CN=EPICS Controls Intermediate CA',
 'SKID: LAB_ISSUER_SKID', 'Issuer ID: LAB_ISSUER',
 'Issued by: EPICS Lab Root Certificate Authority',
 'Secret lab-intermediate',
 'Mounted into: pvxs-lab-pvacms')
ml_root_l = fields('Subject: CN=EPICS ML Root Certificate Authority',
 'SKID: ML_ISSUER_SKID', 'Issuer ID: ML_ISSUER',
 'Signs every ML certificate itself',
 'Secret ml-root',
 'Mounted into: pvxs-lab-ml-pvacms',
 'Rotated independently of the Lab root')

# ---------------------------------------------------------------- legend content
CHIPS = [('client workstation pod', C['client'][1]),
         ('IOC pod', C['ioc'][1]),
         ('PVACMS pod - the certificate manager', C['pvacms'][1]),
         ('certificate authority - a file, mounted into a pod', C['ca'][1]),
         ('gateway pod', C['gateway'][1]),
         ('minting Job - runs once per laboratory', C['ca'][1]),
         ('Service - a stable name in front of a pod', C['lb'][1]),
         ('cluster objects and notes', C['file'][1])]
SAMPLES = [('Service selects pod', C['lb'][1], 2, None),
           ('PVA search and data, lab segment', C['bus_lab'], 4, None),
           ('PVA search and data, ML segment', C['bus_ml'], 4, None),
           ('a department reaching its peer, by name', C['bus_inet'], 2.5, None),
           ('peer certificate status, gateway to gateway', C['peer'], 2.5, None),
           ('written by the Job / seeded by hand', C['filedrop'], 1.8, '6 5')]
NOTATION = ['5075/TCP, 5076/TCP : plain and TLS. Both gateways',
            '             use the same numbers; each is',
            '             addressed by its own name',
            'app=, zone= : pod labels. A Service picks by app,',
            '             a NetworkPolicy admits by zone',
            '',
            'Only the department that issued a certificate can',
            'report on its status.']
ABBREV = ['PVACMS : certificate manager',
          'IOC    : input output controller',
          'SKID   : subject key identifier - the full 40',
          '         digits establish first-use trust']
NOTE = []

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
lab_x = M + 30
ml_x = lab_x + W_lab + DEPT_GAP

gwl_w = measure('pvxs-lab-gateway', gw_lab_l)[0]
gwm_w = measure('pvxs-lab-ml-gateway', gw_ml_l)[0]
svc_gwl_w = measure('svc pvxs-lab-gateway', svc_gwl_l)[0]
svc_gwm_w = measure('svc pvxs-lab-ml-gateway', svc_gwm_l)[0]
gwl_cx = lab_x + ZP + lxs[1] + LCOLS[1]/2
gwm_cx = ml_x + ZP + mxs[1] + MCOLS[1]/2
pz_x = lab_x - 10
pz_w = (ml_x + W_ml + 10) - pz_x

inet_w, inet_h = measure('internet-client', inet_l)
IZ_TITLE = 'internet'
iz_w = int(max(inet_w + 2*ZP, 40 + len(IZ_TITLE)*9.0 + 16))
iz_h = ZTITLE + 12 + inet_h + 20
iz_cx = (gwl_cx + gwm_cx)/2
iz_x = iz_cx - iz_w/2
legend_x, legend_y = M, top_y
lab_root_w, lab_root_h = measure('Lab Root Certificate Authority', lab_root_l)
labca_w, labca_h = measure('Lab Intermediate CA', labca_l)
ml_root_w, ml_root_h = measure('ML Root Certificate Authority', ml_root_l)
ca_h = ZTITLE + 10 + lab_root_h + 46 + labca_h + 20
lab_ca_w = max(lab_root_w, labca_w) + 2*ZP
ml_ca_w = ml_root_w + 2*ZP
lab_ca_x = M
ml_ca_x = M + lab_ca_w + GAP
ca_y = legend_y + lg_h + 34
iz_y = ca_y + ca_h + 44

PZ_TITLE = 'gateways - NetworkPolicies gateway-ingress and ml-gateway-ingress'
pz_y = iz_y + iz_h + 64
svcgw_y = pz_y + ZTITLE + 36
svcgw_h = max(measure('svc pvxs-lab-gateway', svc_gwl_l)[1],
              measure('svc pvxs-lab-ml-gateway', svc_gwm_l)[1])
gw_y = svcgw_y + svcgw_h + 44
gw_h = max(measure('pvxs-lab-gateway', gw_lab_l)[1], measure('pvxs-lab-ml-gateway', gw_ml_l)[1])
pz_h = (gw_y - pz_y) + gw_h + ZP

zone_y = int(pz_y + pz_h + 64)

job_w = measure('Job ca-keygen', job_l)[0]
anchors_w = measure('the trust anchors', anchors_l)[0]

files_ws = [measure(t, l)[0] for t, l in FILE_CARDS]
files_total = sum(files_ws) + GAP*(len(files_ws) - 1)

CANVAS_W = int(max(ml_x + W_ml + 70, M + files_total, M + lg_w,
                   ml_ca_x + ml_ca_w) + M)
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

    row1_y = zone_y + ZTITLE + 34
    h_row1 = max(measure('lab-client', lab_client_l)[1], measure('ml-client', ml_client_l)[1])
    bus_y = row1_y + h_row1 + 34
    svc_y = bus_y + 32
    svc_h = max(measure('svc x', l)[1] for l in
                (svc_lab_cms_l, svc_t1_l, svc_t2_l, svc_ml_cms_l, svc_mlioc_l))
    pod_y = svc_y + svc_h + 44
    h_pods = max(measure('x', l)[1] for l in (testioc_l, tstioc_l, lab_cms_l, ml_cms_l, ml_ioc_l))
    zone_h = (pod_y - zone_y) + h_pods + ZP

    jobs_y = zone_y + zone_h + 56
    jobs_h = max(measure('Job ca-keygen', job_l)[1], measure('the trust anchors', anchors_l)[1])
    files_y = jobs_y + jobs_h + 44
    files_h = max(measure(t, l)[1] for t, l in FILE_CARDS)
    CANVAS_H = files_y + files_h + M

    # --- zones
    LZ_TITLE = 'lab segment - NetworkPolicy lab-segment-ingress'
    MZ_TITLE = 'ML segment - NetworkPolicy ml-segment-ingress'
    cv.zone(lab_x, zone_y, W_lab, zone_h, LZ_TITLE, 'zone_lab')
    cv.zone(ml_x, zone_y, W_ml, zone_h, MZ_TITLE, 'zone_ml')
    for zx, txt, kind in ((lab_x, 'ingress: zone=lab, the own gateway, the peer gateway', 'zone_lab'),
                          (ml_x, 'ingress: zone=ml, the own gateway, the peer gateway', 'zone_ml')):
        cv.emit(f'<text x="{zx+ZP}" y="{zone_y+ZTITLE+20}" font-family="Menlo,Consolas,monospace" '
                f'font-size="11" fill="{C[kind][1]}">{esc(txt)}</text>')
    cv.zone(iz_x, iz_y, iz_w, iz_h, IZ_TITLE, 'zone_it')
    cv.zone(pz_x, pz_y, pz_w, pz_h, PZ_TITLE, 'zone_perim')
    cv.emit(f'<text x="{pz_x+ZP}" y="{pz_y+ZTITLE+22}" font-family="Menlo,Consolas,monospace" '
            f'font-size="11" fill="{C["zone_perim"][1]}">ingress: zone=internet, the peer zone, and the peer gateway</text>')

    # --- department buses
    cv.hv([(lab_x + ZP, bus_y), (lab_x + W_lab - ZP, bus_y)], C['bus_lab'], 4)
    cv.hv([(ml_x + ZP, bus_y), (ml_x + W_ml - ZP, bus_y)], C['bus_ml'], 4)

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

    for c, colr in ((lcl, C['bus_lab']), (mcl, C['bus_ml'])):
        cv.hv([(c['cx'], c['bot']), (c['cx'], bus_y)], colr, 2)
        cv.dot(c['cx'], bus_y, colr)
    for s, colr in ((ls1, C['bus_lab']), (ls2, C['bus_lab']), (ls3, C['bus_lab']),
                    (ms1, C['bus_ml']), (ms2, C['bus_ml'])):
        cv.hv([(s['cx'], bus_y), (s['cx'], s['top'])], colr, 2)
        cv.dot(s['cx'], bus_y, colr)
    for s, p in ((ls1, lt1), (ls2, lt2), (ls3, lpv), (ms1, mio), (ms2, mpv)):
        sel_arrow(cv, s['cx'], s['bot'], p['top'])

    # --- gateways
    sgl = cv.card(gwl_cx - svc_gwl_w/2, svcgw_y, 'svc pvxs-lab-gateway', svc_gwl_l, 'lb', 'lb')
    sgm = cv.card(gwm_cx - svc_gwm_w/2, svcgw_y, 'svc pvxs-lab-ml-gateway', svc_gwm_l, 'lb', 'lb')
    gwl = cv.card(gwl_cx - gwl_w/2, gw_y, 'pvxs-lab-gateway', gw_lab_l, 'gateway', 'gateway')
    gwm = cv.card(gwm_cx - gwm_w/2, gw_y, 'pvxs-lab-ml-gateway', gw_ml_l, 'gateway', 'gateway')
    sel_arrow(cv, sgl['cx'], sgl['bot'], gwl['top'])
    sel_arrow(cv, sgm['cx'], sgm['bot'], gwm['top'])

    # --- the outside reaches both gateways by name
    ic = cv.card(iz_x + (iz_w - inet_w)/2, iz_y + ZTITLE + 12, 'internet-client',
                 inet_l, 'client', 'client')
    for tgt in (sgl, sgm):
        x = tgt['cx']
        cv.hv([(ic['cx'], ic['bot']), (ic['cx'], pz_y - 22), (x, pz_y - 22),
               (x, tgt['top'] - 6)], C['bus_inet'], 2.5)
        head_down(cv, x, tgt['top'], C['bus_inet'])
    cv.pill(ic['cx'], pz_y - 40, 'both gateways, by name', C['bus_inet'])

    # --- each gateway is a client to its own department
    for g, colr in ((gwl, C['bus_lab']), (gwm, C['bus_ml'])):
        cv.hv([(g['cx'], g['bot']), (g['cx'], bus_y)], colr, 2)
        cv.dot(g['cx'], bus_y, colr)
        cv.pill(g['cx'], (pz_y + pz_h + zone_y)/2, 'client side', colr)

    # --- peer certificate status, gateway to gateway
    ymid = gw_y + gw_h/2
    cv.hv([(gwl['x'] + gwl['w'], ymid), (gwm['x'], ymid)], C['peer'], 2.5)
    cv.pill((gwl['x'] + gwl['w'] + gwm['x'])/2, ymid - 16, 'peer certificate status', C['peer'])

    # --- each department's workstation names the PEER gateway, up the outer margins
    lmx = lab_x - 22
    rmx = ml_x + W_ml + 22
    cv.hv([(lcl['x'], lcl['top'] + 24), (lmx, lcl['top'] + 24), (lmx, svcgw_y - 26),
           (sgm['x'] + 20, svcgw_y - 26), (sgm['x'] + 20, sgm['top'] - 6)], C['bus_inet'], 2.5)
    head_down(cv, sgm['x'] + 20, sgm['top'], C['bus_inet'])
    cv.pill(lmx, zone_y - 26, 'pvxs-lab-ml-gateway:5075', C['bus_inet'])
    cv.hv([(mcl['x'] + mcl['w'], mcl['top'] + 24), (rmx, mcl['top'] + 24), (rmx, svcgw_y - 40),
           (sgl['x'] + sgl['w'] - 20, svcgw_y - 40), (sgl['x'] + sgl['w'] - 20, sgl['top'] - 6)],
          C['bus_inet'], 2.5)
    head_down(cv, sgl['x'] + sgl['w'] - 20, sgl['top'], C['bus_inet'])
    cv.pill(rmx, zone_y - 26, 'pvxs-lab-gateway:5075', C['bus_inet'])

    # --- the Job and the anchors it writes
    jb = cv.card(M, jobs_y, 'Job ca-keygen', job_l, 'ca', 'ca')
    an = cv.card(M + job_w + GAP + 20, jobs_y, 'the trust anchors', anchors_l, 'file', 'file')
    amid = an['top'] + an['h']/2
    cv.hv([(jb['x'] + jb['w'], amid), (an['x'], amid)], C['filedrop'], 1.8, dash='6 5')

    # --- the cluster objects
    fx = M
    for title, lines in FILE_CARDS:
        c = cv.card(fx, files_y, title, lines, 'file', 'file')
        fx = c['x'] + c['w'] + GAP

    # --- the two independent authorities
    cv.zone(lab_ca_x, ca_y, lab_ca_w, ca_h, 'Lab Certificate Authority   -   independent', 'zone_ca')
    cv.zone(ml_ca_x, ca_y, ml_ca_w, ca_h, 'ML Certificate Authority   -   independent', 'zone_ca')
    lroot = cv.card(lab_ca_x + (lab_ca_w - lab_root_w)/2, ca_y + ZTITLE + 10,
                    'Lab Root Certificate Authority', lab_root_l, 'ca', 'ca')
    lint = cv.card(lab_ca_x + (lab_ca_w - labca_w)/2, lroot['bot'] + 46,
                   'Lab Intermediate CA', labca_l, 'ca', 'ca')
    cv.hv([(lroot['cx'], lroot['bot']), (lint['cx'], lint['top'] - 3)],
          C['cert'], 2, dash='6 5', marker=True)
    cv.card(ml_ca_x + (ml_ca_w - ml_root_w)/2, ca_y + ZTITLE + 10,
            'ML Root Certificate Authority', ml_root_l, 'ca', 'ca')

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
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">federated-non-shared-root: two departments under two independent roots - example/kubernetes</text>')
    hdr.append(f'<text x="{M}" y="82" font-family="Menlo,Consolas,monospace" font-size="11" fill="#607D8B">Cluster: kind, name spva-lab, namespace spva-lab. Cilium is the network plugin.</text>')
    hdr.append(f'<text x="{M}" y="97" font-family="Menlo,Consolas,monospace" font-size="11" fill="#607D8B">The segments below are NetworkPolicy, enforced by Cilium; the default CNI of kind does not enforce policy at all.</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-federated-non-shared-root.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory, federated topology with two independent roots, on Kubernetes - hand-drawn flat-design infographic.')
