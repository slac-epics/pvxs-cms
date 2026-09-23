#!/usr/bin/env python3
# The federated shared-root topology: two isolated zones, each with its own gateway and
# certificate manager, both chaining to one facility root certificate authority whose
# status is answered by a single shared OCSP responder.
# Every coordinate is computed here. See topology_kit for the primitives.
from topology_kit import (C, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
lab_client_l = fields('Role: client (dual-homed)','Image: lab',
 'eth0  net-lab        10.89.0.0/24',
 'eth1  net-perimeter  10.89.2.0/24',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: pvxs-lab-pvacms, pvxs-lab-testioc, pvxs-lab-tstioc',
 'EPICS_PVA_NAME_SERVERS: pvxs-lab-ml-gateway:5075')
lab_gw_l = fields('Role: gateway (dual-homed), net-lab <-> net-perimeter','Image: gateway',
 'eth0  net-lab        10.89.0.0/24',
 'eth1  net-perimeter  10.89.2.0/24',
 'Program: p4p pvagw','Config: config/gateway-lab.conf',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'Presents: CN=gateway',
 'Upstream: pvxs-lab-pvacms, pvxs-lab-testioc, pvxs-lab-tstioc','ACF: gateway.acf','PVList: config/gateway-lab.pvlist')
testioc_l = fields('Role: IOC','Image: testioc','eth0  net-lab        10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: testioc.db, testiocg.db, testioc-lab.db',
 'ACF: testioc.acf','Serves:','    test:aiExample, test:stringExample, test:longExample',
 '    test:enumExample, test:arrayExample, test:calcExample',
 '    test:spec (SPECIAL), test:labspec (LABSPEC), test:open (OPEN)')
tstioc_l = fields('Role: IOC','Image: tstioc','eth0  net-lab        10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: image.db, image.json','ACF: tstioc.acf',
 'Serves: tst:ArrayData, tst:ColorMode,','    and the rest of the image database')
pvacms_l = fields('Role: PVACMS','Image: idm','eth0  net-lab        10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'CA keychain: certs/lab_intermediate.p12',
 'ACF: /etc/pvacms/pvacms.acf','Serves:','    CERT:CREATE, CERT:LIST, CERT:ROOT, CERT:ISSUER',
 '    CERT:CREATE:LAB_ISSUER, CERT:ISSUER:LAB_ISSUER, CERT:ROOT:LAB_ISSUER',
 '    CERT:LIST:LAB_ISSUER:ALL, :EXPIRING, :PENDING_APPROVAL',
 '    CERT:STATUS:LAB_ISSUER:<serial>')
ml_gw_l = fields('Role: gateway (dual-homed), net-ml <-> net-perimeter','Image: gateway',
 'eth0  net-ml         10.89.1.0/24',
 'eth1  net-perimeter  10.89.2.0/24',
 'Program: p4p pvagw','Config: config/gateway-ml.conf',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'Presents: CN=ml-gateway',
 'Upstream: pvxs-lab-ml, pvxs-lab-ml-ioc','ACF: gateway.acf','PVList: config/gateway-ml.pvlist')
ml_client_l = fields('Role: client (dual-homed)','Image: lab',
 'eth0  net-ml         10.89.1.0/24',
 'eth1  net-perimeter  10.89.2.0/24',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: pvxs-lab-ml, pvxs-lab-ml-ioc','EPICS_PVA_NAME_SERVERS: pvxs-lab-gateway:5075')
mlioc_l = fields('Role: IOC','Image: ml-ioc','eth0  net-ml         10.89.1.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: mlioc.db','ACF: mlioc.acf',
 'Serves: ml:aiExample, ml:stringExample,','    ml:longExample, ml:open (OPEN)')
mlcms_l = fields('Role: PVACMS','Image: ml','eth0  net-ml         10.89.1.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'CA keychain: certs/ml_intermediate.p12',
 'ACF: /etc/pvacms/pvacms.acf','Serves:','    CERT:CREATE, CERT:LIST, CERT:ROOT, CERT:ISSUER',
 '    CERT:CREATE:ML_ISSUER, CERT:ISSUER:ML_ISSUER, CERT:ROOT:ML_ISSUER',
 '    CERT:LIST:ML_ISSUER:ALL, :EXPIRING, :PENDING_APPROVAL',
 '    CERT:STATUS:ML_ISSUER:<serial>')
pc_l = fields('Role: client','Image: internet',
 'eth0  net-perimeter  10.89.2.0/24',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: none',
 'EPICS_PVA_NAME_SERVERS: pvxs-lab-gateway:5075, pvxs-lab-ml-gateway:5075')
resp_l = fields('Role: OCSP responder for the Facility Root CA (dual-homed)','Image: idm',
 'eth0  net-lab        10.89.0.0/24',
 'eth1  net-ml         10.89.1.0/24',
 'Listens: tcp/8888 OCSP over HTTP',
 'Program: openssl ocsp, under supervisor with a watchdog',
 'Files: ocsp/ca.pem, ocsp/signer.pem, ocsp/signer.key, ocsp/index.txt')
root_l = fields('Subject: CN=EPICS Root Certificate Authority','OCSP: pvxs-lab-authority-status:8888',
 '    (named in the AIA extension)','File: certs/cert_auth.p12')
labca_l = fields('Subject: CN=EPICS Controls Intermediate CA','SKID: LAB_ISSUER_SKID','Issuer ID: LAB_ISSUER',
 'File: certs/lab_intermediate.p12','Mounted into: pvxs-lab-pvacms')
mlca_l = fields('Subject: CN=EPICS ML Intermediate CA','SKID: ML_ISSUER_SKID','Issuer ID: ML_ISSUER',
 'File: certs/ml_intermediate.p12','Mounted into: pvxs-lab-ml')
signer_l = fields('Subject: CN=EPICS Root Certificate Authority OCSP Responder','Files: ocsp/signer.pem, ocsp/signer.key')

testacf_l = ['§Authorities',
 '    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority") {',
 '        AUTHORITY(AUTH_LAB, "EPICS Controls Intermediate CA")',
 '        AUTHORITY(AUTH_ML,  "EPICS ML Intermediate CA")','    }','',
 '§UAGs','    UAG(OPERATORS) {gateway, operator}','    UAG(GUESTS)    {guest}',
 '    UAG(GATEWAYS)  {gateway, ml-gateway}','    UAG(BEAMLINE)  {OU=beamline}','    UAG(LAB_UNIT)  {OU=lab}','',
 '§ASGs','    ASG(SPECIAL)     test:spec','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)',
 '            AUTHORITY(AUTH_LAB, AUTH_ML) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(LABSPEC)     test:labspec','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(LAB_UNIT)',
 '            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(OPEN)        test:open','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { AUTHORITY(EPICS_CA)',
 '            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(GATEWAYS)',
 '            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(DEFAULT)     everything else','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)',
 '            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)',
 '            AUTHORITY(AUTH_ML) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(BEAMLINE)',
 '            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }']
tstacf_l = ['§Authorities',
 '    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority") {',
 '        AUTHORITY(AUTH_LAB, "EPICS Controls Intermediate CA")',
 '        AUTHORITY(AUTH_ML,  "EPICS ML Intermediate CA")','    }','',
 '§UAGs','    UAG(OPERATORS) {gateway, operator}','    UAG(GUESTS)    {guest}','',
 '§ASGs','    ASG(DEFAULT)','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)',
 '            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)',
 '            AUTHORITY(AUTH_ML) PROTOCOL(TLS) METHOD(X509) }']
gwacf_l = ['in the gateway image','',
 '§Authorities','    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority")','',
 '§UAGs','    UAG(USERS)         {guest, operator, remote}','    UAG(SPECIAL_USERS) {operator}','',
 '§ASGs','    ASG(SPECIAL)',
 '        RULE(1,READ) { UAG(USERS) AUTHORITY(EPICS_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(SPECIAL_USERS)','            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(OPEN_WRITE)',
 '        RULE(1,READ) { AUTHORITY(EPICS_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { AUTHORITY(EPICS_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(CERT_CREATE) { RULE(1,READ) RULE(1,WRITE) }',
 '    ASG(CERT_STATUS) { RULE(1,READ) }',
 '    ASG(DEFAULT)',
 '        RULE(1,READ) { UAG(USERS) AUTHORITY(EPICS_CA)','            PROTOCOL(TLS) METHOD(X509) }']
labpvl_l = ['test:.*                          ALLOW','tst:.*                           ALLOW',
 'test:spec                        ALLOW SPECIAL','test:open                        ALLOW OPEN_WRITE',
 'CERT:CREATE:LAB_ISSUER(?::.*)?   ALLOW CERT_CREATE','CERT:STATUS:LAB_ISSUER(?::.*)?   ALLOW CERT_STATUS',
 'CERT:LIST:LAB_ISSUER:ALL         ALLOW CERT_STATUS','CERT:LIST:LAB_ISSUER:EXPIRING    ALLOW CERT_STATUS']
labcmsacf_l = ['at /etc/pvacms/pvacms.acf','',
 '§Authorities','    AUTHORITY("EPICS Root Certificate Authority") {',
 '        AUTHORITY(CMS_AUTH, "EPICS Controls Intermediate CA")','    }','',
 '§UAGs','    UAG(CMS_ADMIN) {admin, certadmin}','',
 '§ASGs','    ASG(DEFAULT) {','        RULE(0,READ)',
 '        RULE(1,WRITE) { UAG(CMS_ADMIN) AUTHORITY(CMS_AUTH)','            PROTOCOL(TLS) METHOD("x509") }','    }']
mlacf_l = ['§Authorities',
 '    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority") {',
 '        AUTHORITY(AUTH_LAB, "EPICS Controls Intermediate CA")',
 '        AUTHORITY(AUTH_ML,  "EPICS ML Intermediate CA")','    }','',
 '§UAGs','    UAG(OPERATORS) {gateway, operator, mloperator}','    UAG(GUESTS)    {guest, mlsystem}',
 '    UAG(GATEWAYS)  {gateway, ml-gateway}','',
 '§ASGs','    ASG(OPEN)        ml:open','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { AUTHORITY(EPICS_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(GATEWAYS)','            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(DEFAULT)     everything else','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)','            AUTHORITY(AUTH_ML) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)','            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }']
gwref_l = ['in the gateway image','the same file as the lab gateway','',
 '§Authorities','    AUTHORITY(EPICS_CA, ...)','',
 '§UAGs','    UAG(USERS), UAG(SPECIAL_USERS)','',
 '§ASGs','    ASG(SPECIAL), ASG(OPEN_WRITE),','    ASG(CERT_CREATE), ASG(CERT_STATUS),','    ASG(DEFAULT)','',
 'rules shown on the lab gateway copy']
mlpvl_l = ['ml:.*                            ALLOW','ml:open                          ALLOW OPEN_WRITE',
 'CERT:CREATE:ML_ISSUER(?::.*)?    ALLOW CERT_CREATE','CERT:STATUS:ML_ISSUER(?::.*)?    ALLOW CERT_STATUS',
 'CERT:LIST:ML_ISSUER:ALL          ALLOW CERT_STATUS','CERT:LIST:ML_ISSUER:EXPIRING     ALLOW CERT_STATUS']
mlcmsacf_l = ['at /etc/pvacms/pvacms.acf','',
 '§Authorities','    AUTHORITY("EPICS Root Certificate Authority") {',
 '        AUTHORITY(CMS_AUTH, "EPICS ML Intermediate CA")','    }','',
 '§UAGs','    UAG(CMS_ADMIN) {admin, mlcertadmin}','',
 '§ASGs','    ASG(DEFAULT) {','        RULE(0,READ)',
 '        RULE(1,WRITE) { UAG(CMS_ADMIN) AUTHORITY(CMS_AUTH)','            PROTOCOL(TLS) METHOD("x509") }','    }']

# ---------------------------------------------------------------- geometry
M = 40
title_h = 64

# lab zone columns fixed by the file row
lw = [colw('testioc.acf', testacf_l), colw('tstioc.acf', tstacf_l), colw('gateway.acf', gwacf_l),
      colw('config/gateway-lab.pvlist', labpvl_l), colw('config/pvacms-lab.acf', labcmsacf_l)]
lx = [0]
for w in lw[:-1]: lx.append(lx[-1] + w + GAP)
lab_inner = lx[-1] + lw[-1]
W_lab = lab_inner + 2*ZP

mw = [colw('mlioc.acf', mlacf_l), colw('gateway.acf', gwref_l), colw('config/gateway-ml.pvlist', mlpvl_l),
      colw('config/pvacms-ml.acf', mlcmsacf_l)]
mx = [0]
for w in mw[:-1]: mx.append(mx[-1] + w + GAP)
ml_inner = mx[-1] + mw[-1]
W_ml = ml_inner + 2*ZP

ZONE_GAP = 90
zone_y = 0  # set later
lab_x = M
ml_x = M + W_lab + ZONE_GAP
CANVAS_W = ml_x + W_ml + M

# top band geometry
legend_x, legend_y = M, title_h + 26
# gateway centres (local): over its two file columns
gw1_span = (lx[2], lx[3] + lw[3])
gx1_local = (gw1_span[0] + gw1_span[1]) / 2
gw2_span = (mx[1], mx[2] + mw[2])
gx2_local = (gw2_span[0] + gw2_span[1]) / 2
gx1 = lab_x + ZP + gx1_local
gx2 = ml_x + ZP + gx2_local
rx = (gx1 + gx2) / 2

pz_w = measure('perimeter-client', pc_l)[0] + 2*ZP
pz_h = ZTITLE + 12 + measure('perimeter-client', pc_l)[1] + 20

ca_children_w = colw('Lab Intermediate CA', labca_l) + colw('ML Intermediate CA', mlca_l) + colw('OCSP Signing Cert', signer_l) + 2*GAP
ca_w = ca_children_w + 2*ZP
root_w, root_h = measure('Facility Root CA', root_l)
child_h = max(measure('Lab Intermediate CA', labca_l)[1], measure('OCSP Signing Cert', signer_l)[1])
ca_h = ZTITLE + 10 + root_h + 46 + child_h + 20
ca_x = rx - ca_w/2
ca_y = title_h + 26

# The perimeter stands beside the authorities rather than above them, right of the legend,
# which is where the simple-with-gateway picture puts it too.
pz_x, pz_y = ca_x - pz_w - 60, ca_y

resp_w, resp_h = measure('pvxs-lab-authority-status', resp_l)
resp_x = rx - resp_w/2
resp_y = ca_y + ca_h + 46

# The perimeter segment is drawn the way every other segment is: one horizontal line, tapped
# by each host that stands on it, labelled once. It runs between the top band and the zones.
# It has to clear the legend, whose left end it runs under to reach the lab workstation.
# The line-through-card assertion guards that, since the legend registers as a rectangle.
perim_bus_y = resp_y + resp_h + 90
zone_y = perim_bus_y + 60
CANVAS_H = 0  # set after zones

# ---------------------------------------------------------------- emit
def build(cv):
    global CANVAS_H
    hdr = []

    # zones first (containers under everything)
    row1_y = zone_y + ZTITLE + 14
    # measure row1/row2 heights
    h_gw = measure('pvxs-lab-gateway', lab_gw_l)[1]
    h_cl = measure('lab-client', lab_client_l)[1]
    row1_h = max(h_gw, h_cl)
    bus_lab_y = row1_y + row1_h + 34
    row2_y = bus_lab_y + 34
    h_r2 = max(measure('pvxs-lab-pvacms', pvacms_l)[1], measure('pvxs-lab-testioc', testioc_l)[1])
    files_y = row2_y + h_r2 + 46
    files_h = max(measure('x', l)[1] for l in (testacf_l, tstacf_l, gwacf_l, labpvl_l, labcmsacf_l, mlacf_l, gwref_l, mlpvl_l, mlcmsacf_l))
    zone_h = (files_y - zone_y) + files_h + ZP
    CANVAS_H = zone_y + zone_h + M

    cv.zone(lab_x, zone_y, W_lab, zone_h, 'net-lab   10.89.0.0/24   bridge, isolated   -   Lab zone (accelerator)', 'zone_lab')
    cv.zone(ml_x, zone_y, W_ml, zone_h, 'net-ml   10.89.1.0/24   bridge, isolated   -   ML zone', 'zone_ml')
    cv.zone(pz_x, pz_y, pz_w, pz_h, 'net-perimeter   10.89.2.0/24   bridge, isolated   -   outside both zones', 'zone_perim')
    cv.zone(ca_x, ca_y, ca_w, ca_h, 'Certificate Authorities', 'zone_ca')

    # --- buses (under cards)
    busL0, busL1 = lab_x + ZP, lab_x + W_lab - ZP
    busM0, busM1 = ml_x + ZP, ml_x + W_ml - ZP
    cv.hv([(busL0, bus_lab_y), (busL1, bus_lab_y)], C['bus_lab'], 4)
    cv.hv([(busM0, bus_lab_y), (busM1, bus_lab_y)], C['bus_ml'], 4)
    cv.pill(busL0 + 120, bus_lab_y - 16, 'net-lab  10.89.0.0/24  tcp/5075, tcp/5076, udp/5076, tcp/8888', C['bus_lab'])
    cv.pill(busM0 + 120, bus_lab_y - 16, 'net-ml  10.89.1.0/24  tcp/5075, tcp/5076, udp/5076, tcp/8888', C['bus_ml'])

    # --- lab cards
    cl = cv.card(lab_x + ZP + lx[0], row1_y, 'lab-client', lab_client_l, 'client', 'client')
    gw1 = cv.card(gx1 - measure('pvxs-lab-gateway', lab_gw_l)[0]/2, row1_y, 'pvxs-lab-gateway', lab_gw_l, 'gateway', 'gateway')
    t1 = cv.card(lab_x + ZP + lx[0], row2_y, 'pvxs-lab-testioc', testioc_l, 'ioc', 'ioc')
    t2 = cv.card(lab_x + ZP + lx[1], row2_y, 'pvxs-lab-tstioc', tstioc_l, 'ioc', 'ioc')
    pw = measure('pvxs-lab-pvacms', pvacms_l)[0]
    pv = cv.card(lab_x + ZP + lx[4] + lw[4] - pw, row2_y, 'pvxs-lab-pvacms', pvacms_l, 'pvacms', 'pvacms')
    fa1 = cv.card(lab_x + ZP + lx[0], files_y, 'testioc.acf', testacf_l, 'file', 'file')
    fa2 = cv.card(lab_x + ZP + lx[1], files_y, 'tstioc.acf', tstacf_l, 'file', 'file')
    fa3 = cv.card(lab_x + ZP + lx[2], files_y, 'gateway.acf', gwacf_l, 'file', 'file')
    fa4 = cv.card(lab_x + ZP + lx[3], files_y, 'config/gateway-lab.pvlist', labpvl_l, 'file', 'file')
    fa5 = cv.card(lab_x + ZP + lx[4], files_y, 'config/pvacms-lab.acf', labcmsacf_l, 'file', 'file')

    # --- ml cards
    gw2 = cv.card(gx2 - measure('pvxs-lab-ml-gateway', ml_gw_l)[0]/2, row1_y, 'pvxs-lab-ml-gateway', ml_gw_l, 'gateway', 'gateway')
    mcw = measure('ml-client', ml_client_l)[0]
    mcl = cv.card(ml_x + ZP + ml_inner - mcw, row1_y, 'ml-client', ml_client_l, 'client', 'client')
    mi = cv.card(ml_x + ZP + mx[0], row2_y, 'pvxs-lab-ml-ioc', mlioc_l, 'ioc', 'ioc')
    mpw = measure('pvxs-lab-ml', mlcms_l)[0]
    mp = cv.card(ml_x + ZP + mx[3] + mw[3] - mpw, row2_y, 'pvxs-lab-ml', mlcms_l, 'pvacms', 'pvacms')
    fb1 = cv.card(ml_x + ZP + mx[0], files_y, 'mlioc.acf', mlacf_l, 'file', 'file')
    fb2 = cv.card(ml_x + ZP + mx[1], files_y, 'gateway.acf', gwref_l, 'file', 'file')
    fb3 = cv.card(ml_x + ZP + mx[2], files_y, 'config/gateway-ml.pvlist', mlpvl_l, 'file', 'file')
    fb4 = cv.card(ml_x + ZP + mx[3], files_y, 'config/pvacms-ml.acf', mlcmsacf_l, 'file', 'file')

    # --- bus taps
    for t, colr in ((cl, 'bus_lab'), (gw1, 'bus_lab'), (mcl, 'bus_ml'), (gw2, 'bus_ml')):
        x = t['cx'] - 40 if t in (gw1, gw2) else t['cx']
        cv.hv([(x, t['bot']), (x, bus_lab_y)], C[colr], 2); cv.dot(x, bus_lab_y, C[colr])
    for t, colr in ((t1, 'bus_lab'), (t2, 'bus_lab'), (pv, 'bus_lab'), (mi, 'bus_ml'), (mp, 'bus_ml')):
        cv.hv([(t['cx'], bus_lab_y), (t['cx'], t['top'])], C[colr], 2); cv.dot(t['cx'], bus_lab_y, C[colr])

    # --- perimeter client + CA + responder cards
    pcc = cv.card(pz_x + (pz_w - measure('perimeter-client', pc_l)[0])/2, pz_y + ZTITLE + 12, 'perimeter-client', pc_l, 'client', 'client')
    rootc = cv.card(rx - root_w/2, ca_y + ZTITLE + 10, 'Facility Root CA', root_l, 'ca', 'ca')
    ch_y = rootc['bot'] + 46
    c1 = cv.card(ca_x + ZP, ch_y, 'Lab Intermediate CA', labca_l, 'ca', 'ca')
    c2 = cv.card(ca_x + ZP + colw('Lab Intermediate CA', labca_l) + GAP, ch_y, 'ML Intermediate CA', mlca_l, 'ca', 'ca')
    c3 = cv.card(ca_x + ZP + colw('Lab Intermediate CA', labca_l) + colw('ML Intermediate CA', mlca_l) + 2*GAP, ch_y, 'OCSP Signing Cert', signer_l, 'ca', 'ca')
    rc = cv.card(resp_x, resp_y, 'pvxs-lab-authority-status', resp_l, 'ocsp', 'ocsp')

    # --- certificate relationships (dashed purple, arrowheads)
    for cc in (c1, c2, c3):
        cv.hv([(rootc['cx'], rootc['bot']), (rootc['cx'], rootc['bot']+16), (cc['cx'], rootc['bot']+16), (cc['cx'], cc['top']-3)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{rootc["cx"]+8}" y="{rootc["bot"]+30}" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">signs</text>')
    # root names the responder (route around the right of the children row)
    nx = ca_x + ca_w - 12
    cv.hv([(rootc['x']+rootc['w'], rootc['top']+rootc['h']/2), (nx, rootc['top']+rootc['h']/2), (nx, rc['top']+24), (rc['x']+rc['w']+3, rc['top']+24)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{nx+6}" y="{(rootc["top"]+ca_y+ca_h)/2}" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">names</text>')
    # signer signs the responder's answers
    cv.hv([(c3['cx'], c3['bot']), (c3['cx'], ca_y+ca_h+26), (rc['x']+60, ca_y+ca_h+26), (rc['x']+60, rc['top']-3)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{c3["cx"]+8}" y="{ca_y+ca_h+22}" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">signs its answers</text>')

    # --- the perimeter segment: one line, tapped by every host that stands on it. The two
    # --- gateways and both dual-homed workstations reach it from below, the outside
    # --- workstation from above.
    perim_hosts = [cl, gw1, gw2, mcl]
    pbus0 = min(h['cx'] for h in perim_hosts) - 40
    pbus1 = max(h['cx'] for h in perim_hosts) + 40
    cv.hv([(pbus0, perim_bus_y), (pbus1, perim_bus_y)], C['perim'], 4)
    for h in perim_hosts:
        cv.hv([(h['cx'], perim_bus_y), (h['cx'], h['top'])], C['perim'], 2)
        cv.dot(h['cx'], perim_bus_y, C['perim'])
    cv.hv([(pcc['cx'], pcc['bot']), (pcc['cx'], perim_bus_y)], C['perim'], 2)
    cv.dot(pcc['cx'], perim_bus_y, C['perim'])
    # centred on the open span between the two zones, clear of the legend at the left end
    cv.pill(rx, perim_bus_y - 16, 'net-perimeter  10.89.2.0/24  tcp/5075, tcp/5076, udp/5076', C['perim'])

    # --- the responder stands on both departmental segments, so it taps each of them. The
    # --- port it answers on is named once, on each segment's own label.
    dxl = lab_x + ZP + (lx[1] + lw[1] + lx[2]) / 2                    # corridor between tstioc.acf and gateway.acf cols
    dxm = ml_x + ZP + (mx[0] + mw[0] + mx[1]) / 2
    cv.hv([(rc['x']+30, rc['bot']), (rc['x']+30, perim_bus_y+22), (dxl, perim_bus_y+22), (dxl, bus_lab_y)], C['bus_lab'], 2)
    cv.dot(dxl, bus_lab_y, C['bus_lab'])
    cv.hv([(rc['x']+rc['w']-30, rc['bot']), (rc['x']+rc['w']-30, perim_bus_y+34), (dxm, perim_bus_y+34), (dxm, bus_lab_y)], C['bus_ml'], 2)
    cv.dot(dxm, bus_lab_y, C['bus_ml'])

    # --- file drops (dotted grey)
    def drop(comp, filecard, xoff=0):
        x = comp['cx'] + xoff
        cv.hv([(x, comp['bot']), (x, filecard['top'])], C['filedrop'], 1.6, dash='2 4')
    drop(t1, fa1); drop(t2, fa2); drop(pv, fa5); drop(mi, fb1); drop(mp, fb4)
    # gateways: two files each, L shaped through the free corridor
    cv.hv([(gw1['cx']-12, gw1['bot']), (gw1['cx']-12, fa3['top']-16), (fa3['x']+fa3['w']/2, fa3['top']-16), (fa3['x']+fa3['w']/2, fa3['top'])], C['filedrop'], 1.6, dash='2 4')
    cv.hv([(gw1['cx']+12, gw1['bot']), (gw1['cx']+12, fa4['top']-28), (fa4['x']+fa4['w']/2, fa4['top']-28), (fa4['x']+fa4['w']/2, fa4['top'])], C['filedrop'], 1.6, dash='2 4')
    cv.hv([(gw2['cx']-12, gw2['bot']), (gw2['cx']-12, fb2['top']-16), (fb2['x']+fb2['w']/2, fb2['top']-16), (fb2['x']+fb2['w']/2, fb2['top'])], C['filedrop'], 1.6, dash='2 4')
    cv.hv([(gw2['cx']+12, gw2['bot']), (gw2['cx']+12, fb3['top']-28), (fb3['x']+fb3['w']/2, fb3['top']-28), (fb3['x']+fb3['w']/2, fb3['top'])], C['filedrop'], 1.6, dash='2 4')

    # --- legend
    ly = legend_y
    lx0 = legend_x
    chips = [('CA or certificate - a file, on no network', C['ca'][1]),
             ('OCSP responder', C['ocsp'][1]),
             ('PVACMS - certificate manager', C['pvacms'][1]),
             ('IOC - controller', C['ioc'][1]),
             ('gateway - the only route between a zone', C['gateway'][1]),
             ('    and the perimeter', None),
             ('client - workstation', C['client'][1]),
             ('ACF or PVList - a file a component loads', C['file'][1])]
    samples = [('net-lab bus - tapping it = attached to net-lab', C['bus_lab'], 4, None),
               ('net-ml bus - the same for net-ml', C['bus_ml'], 4, None),
               ('net-perimeter bus - tapping it = attached', C['perim'], 4, None),
               ('    to net-perimeter', None, 0, None),
               ('certificate relationship - signs / names', C['cert'], 2, '6 5'),
               ('a file the component loads', C['filedrop'], 1.6, '2 4')]
    notation = ['10.89.0.0/24 : the segment, in CIDR. Three podman bridges with',
                '               no routing between them, so a host reaches only',
                '               the segments it is attached to',
                'eth0, eth1   : the host\'s interface on each segment. A host on',
                '               two segments is marked dual-homed',
                'tcp/5075     : PVAccess, plaintext',
                'tcp/5076     : PVAccess over TLS',
                'udp/5076     : PVAccess search and beacons, sent to the',
                '               segment broadcast address',
                'tcp/8888     : OCSP over HTTP, to the responder',
                '',
                'The segment CIDRs are pinned in compose.yaml, so they are',
                'these on every laboratory. Host addresses within a segment are',
                'assigned by podman when a container starts and are not fixed:',
                'per-container addresses cannot be set, because podman refuses',
                'them on a container attached to more than one segment.']
    abbrev = ['CA     : certificate authority','SKID   : subject key identifier, 40 hex digits',
              'Issuer ID: the first 8 digits of a SKID','PVACMS : certificate manager',
              'IOC    : input output controller','ACF    : access security file',
              'PVList : gateway process variable list','OCSP   : online certificate status protocol',
              'AIA    : authority information access extension','ML     : machine learning']
    note = ['A line claims attachment, not direction.','Arrowheads only where a direction is real.','',
            'LAB_ISSUER, ML_ISSUER and the _SKID forms are','named, not printed: a fresh mint changes them.',
            'Values: issuer_ids.env']
    # Two columns: the swatches and line kinds on the left, the notation and the
    # abbreviations on the right. One column ran past the zones below and crossed the line
    # into lab-client.
    col_gap = 34
    colw_l, colw_r = 470, 470
    lg_w = 14 + colw_l + col_gap + colw_r + 14
    left_h  = 12 + len(chips)*24 + 10 + len(samples)*24
    right_h = 12 + LH + len(notation)*LH + 10 + LH + len(abbrev)*LH + 10 + len(note)*LH
    lg_h = HDR + max(left_h, right_h) + 14

    cv.emit(f'<rect x="{lx0}" y="{ly}" width="{lg_w}" height="{lg_h}" rx="10" fill="white" stroke="#B0BEC5" stroke-width="1.4"/>')
    cv.emit(f'<path d="M {lx0} {ly+10} a10 10 0 0 1 10 -10 h{lg_w-20} a10 10 0 0 1 10 10 v{HDR-10} h-{lg_w} z" fill="#455A64"/>')
    cv.emit(f'<text x="{lx0+14}" y="{ly+20}" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" font-weight="bold" fill="white">Legend</text>')
    cv.emit(f'<line x1="{lx0+14+colw_l+col_gap/2}" y1="{ly+HDR+8}" x2="{lx0+14+colw_l+col_gap/2}" y2="{ly+lg_h-10}" stroke="#CFD8DC" stroke-width="1"/>')

    def _txt(x, y, t, bold=False, colour=None):
        b = ' font-weight="bold"' if bold else ''
        cv.emit(f'<text x="{x}" y="{y}" font-family="Menlo,Consolas,monospace" font-size="11"{b} fill="{colour or C["ink"]}" xml:space="preserve">{esc(t)}</text>')

    # left column
    lcx = lx0 + 14
    yy = ly + HDR + 12 + 8
    for label, colr in chips:
        if colr: cv.emit(f'<rect x="{lcx}" y="{yy-10}" width="14" height="14" rx="3" fill="{colr}"/>')
        _txt(lcx+24, yy+1, label)
        yy += 24
    yy += 10
    for label, colr, wdt, dash in samples:
        if colr:
            dd = f' stroke-dasharray="{dash}"' if dash else ''
            cv.emit(f'<line x1="{lcx}" y1="{yy-4}" x2="{lcx+40}" y2="{yy-4}" stroke="{colr}" stroke-width="{wdt}"{dd}/>')
        _txt(lcx+50, yy, label)
        yy += 24

    # right column
    rx0 = lx0 + 14 + colw_l + col_gap
    yy = ly + HDR + 12 + 8
    _txt(rx0, yy, 'Notation', bold=True); yy += LH
    for l in notation:
        _txt(rx0, yy, l); yy += LH
    yy += 10
    _txt(rx0, yy, 'Abbreviations', bold=True); yy += LH
    for l in abbrev:
        _txt(rx0, yy, l); yy += LH
    yy += 10
    for l in note:
        _txt(rx0, yy, l, colour='#607D8B'); yy += LH

    cv.note_card('LEGEND', lx0, ly, lg_w, lg_h)

    # --- page title
    hdr.append(f'<text x="{M}" y="40" font-family="Helvetica Neue,Arial,sans-serif" font-size="26" font-weight="bold" fill="{C["ink"]}">Secure PVAccess demonstration laboratory</text>')
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">federated, shared root: one facility root signing both departmental intermediates, so every certificate traces to it - example/podman</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-federated-shared-root.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory - hand-drawn flat-design infographic.')
