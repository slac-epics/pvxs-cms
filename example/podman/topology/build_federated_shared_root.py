#!/usr/bin/env python3
# The federated shared-root topology, as compose.yaml builds it: five segments, two
# departments each with its own gateway and certificate manager, a facility load balancer
# owning one address for the whole facility, and an OCSP responder on the facility's own IT
# segment answering for the root both departments chain to.
#
# THIS PICTURE MATCHES THE RUNNING LABORATORY. Every segment carries isolate=true, so the
# separation drawn here is enforced by podman rather than merely configured.
# topology-federated-shared-root-routed.svg draws the same laboratory with the routing
# firewall a site would install, and says on the firewall itself what stands in for it here.
# Every coordinate is computed here. See topology_kit for the primitives.
from topology_kit import (C, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
lab_client_l = fields('Role: client','Image: lab',
 'eth0  net-lab        10.89.0.0/24',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: pvxs-lab-pvacms, pvxs-lab-testioc, pvxs-lab-tstioc',
 'EPICS_PVA_NAME_SERVERS: facility:5175   the ML department, by its port')
lab_gw_l = fields('Role: gateway (dual-homed), net-lab <-> net-perimeter','Image: gateway',
 'eth0  net-lab        10.89.0.0/24   upstream side, to its department',
 'eth1  net-perimeter  10.89.2.0/24   server side, where it is asked',
 'Program: p4p pvagw, layer 7','Config: config/gateway-lab.conf',
 'Serves on eth1 alone: "interface" pinned to its net-perimeter address',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'Reached from outside at facility:5075 and facility:5076',
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
pvacms_l = fields('Role: PVACMS','Image: idm',
 'eth0  net-lab        10.89.0.0/24   its only interface',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'CA keychain: certs/lab_intermediate.p12',
 'ACF: /etc/pvacms/pvacms.acf','Serves:','    CERT:CREATE, CERT:LIST, CERT:ROOT, CERT:ISSUER',
 '    CERT:CREATE:LAB_ISSUER, CERT:ISSUER:LAB_ISSUER, CERT:ROOT:LAB_ISSUER',
 '    CERT:LIST:LAB_ISSUER:ALL, :EXPIRING, :PENDING_APPROVAL',
 '    CERT:STATUS:LAB_ISSUER:<serial>')
ml_gw_l = fields('Role: gateway (dual-homed), net-ml <-> net-perimeter','Image: gateway',
 'eth0  net-ml         10.89.1.0/24   upstream side, to its department',
 'eth1  net-perimeter  10.89.2.0/24   server side, where it is asked',
 'Program: p4p pvagw, layer 7','Config: config/gateway-ml.conf',
 'Serves on eth1 alone, and on its own ports: serverport 5175,',
 '    EPICS_PVAS_TLS_PORT 5176',
 'Listens: tcp/5175 PVA   tcp/5176 PVA over TLS   udp/5176 PVA search',
 'Reached from outside at facility:5175 and facility:5176',
 'Presents: CN=ml-gateway',
 'Upstream: pvxs-lab-ml, pvxs-lab-ml-ioc','ACF: gateway.acf','PVList: config/gateway-ml.pvlist')
ml_client_l = fields('Role: client','Image: lab',
 'eth0  net-ml         10.89.1.0/24',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: pvxs-lab-ml, pvxs-lab-ml-ioc',
 'EPICS_PVA_NAME_SERVERS: facility:5075   the lab department, by its port')
mlioc_l = fields('Role: IOC','Image: ml-ioc','eth0  net-ml         10.89.1.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: mlioc.db','ACF: mlioc.acf',
 'Serves: ml:aiExample, ml:stringExample,','    ml:longExample, ml:open (OPEN)')
mlcms_l = fields('Role: PVACMS','Image: ml',
 'eth0  net-ml         10.89.1.0/24   its only interface',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'CA keychain: certs/ml_intermediate.p12',
 'ACF: /etc/pvacms/pvacms.acf','Serves:','    CERT:CREATE, CERT:LIST, CERT:ROOT, CERT:ISSUER',
 '    CERT:CREATE:ML_ISSUER, CERT:ISSUER:ML_ISSUER, CERT:ROOT:ML_ISSUER',
 '    CERT:LIST:ML_ISSUER:ALL, :EXPIRING, :PENDING_APPROVAL',
 '    CERT:STATUS:ML_ISSUER:<serial>')
# One appliance owns the facility address. Mapping a port to a different port would break
# PVAccess: a server names its own port in a search reply and the client dials that port on
# the address the reply arrived from, so a translated port sends it to the other department.
lb_l = fields('Role: facility load balancer, layer 4','Image: haproxy',
 'eth0  net-internet   10.89.4.0/24   the facility address',
 'eth1  net-perimeter  10.89.2.0/24   its foot in the DMZ',
 'eth2  net-lab        10.89.0.0/24   aliased "facility" on each',
 'eth3  net-ml         10.89.1.0/24       network that names it',
 'Maps inward, port for port:',
 '    facility:5075 -> pvxs-lab-gateway:5075',
 '    facility:5076 -> pvxs-lab-gateway:5076      over TLS',
 '    facility:5175 -> pvxs-lab-ml-gateway:5175',
 '    facility:5176 -> pvxs-lab-ml-gateway:5176   over TLS',
 'Backends: resolve-net 10.89.2.0/24, the DMZ address of each gateway')

pc_l = fields('Role: client','Image: internet',
 'eth0  net-internet   10.89.4.0/24',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: none',
 'EPICS_PVA_NAME_SERVERS: facility:5075, facility:5175',
 '    one address, one port per department')
resp_l = fields('Role: OCSP responder for the Facility Root CA','Image: idm',
 'eth0  net-it         10.89.3.0/24   its own segment',
 'eth1  net-lab        10.89.0.0/24   on each network that names it,',
 'eth2  net-ml         10.89.1.0/24       as the balancer is',
 'An IT service: it belongs to neither department, as the root does not',
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

# The legend's height decides where everything below the top band starts, so it is worked
# out here rather than while drawing.
chips = [('CA or certificate - a file, on no network', C['ca'][1]),
         ('OCSP responder', C['ocsp'][1]),
         ('PVACMS - certificate manager', C['pvacms'][1]),
         ('IOC - controller', C['ioc'][1]),
         ('gateway - proxies PVAccess between a zone', C['gateway'][1]),
         ('    and the perimeter', None),
         ('load balancer - owns the facility address', C['lb'][1]),
         ('    and maps a port to a department', None),
         ('client - workstation', C['client'][1]),
         ('ACF or PVList - a file a component loads', C['file'][1])]
samples = [('net-lab bus - tapping it = attached to net-lab', C['bus_lab'], 4, None),
           ('net-ml bus - the same for net-ml', C['bus_ml'], 4, None),
           ('net-it bus - the same for net-it', C['bus_it'], 4, None),
           ('net-perimeter bus - tapping it = attached', C['perim'], 4, None),
           ('    to net-perimeter', None, 0, None),
           ('certificate relationship - signs / names', C['cert'], 2, '6 5'),
           ('a file the component loads', C['filedrop'], 1.6, '2 4')]
notation = ['10.89.0.0/24 : the segment, in CIDR. Five podman bridges, each',
            '               with isolate=true: no network forwards to another,',
            '               a broadcast search does not leave one, and a name',
            '               is answered only within one. Crossing needs an',
            '               interface on both sides, which four containers',
            '               here have and every one is drawn.',
            'eth0, eth1   : the host\'s interface on each segment. A host on',
            '               more than one is marked dual-homed',
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

# Every segment is one horizontal line, tapped by each host standing on it, labelled once.
# The perimeter line runs under the left end of the legend to reach the lab side, and the
# line-through-card assertion guards that, since the legend registers as a rectangle.
lb_w, lb_h = measure('pvxs-facility-lb', lb_l)
resp_w, resp_h = measure('pvxs-lab-authority-status', resp_l)

# The facility's own segments and the services standing on them, in one box, the way each
# department is in one box. The two lines belong to it; the departments and the outside
# workstation reach across into them.
# It reaches from under the outside workstation to over the far gateway, which is the span
# the facility's own segments actually cover.
gw2_w = measure('pvxs-lab-ml-gateway', ml_gw_l)[0]
itz_x = pz_x
itz_w = (gx2 + gw2_w/2) - pz_x
# The IT zone stands entirely right of the legend, so only what is directly above it counts.
# net-internet belongs to nobody in the facility, so its line is drawn above the IT zone
# rather than inside it, and the balancer reaches up out of the box to stand on it.
inet_bus_y = max(ca_y + ca_h, pz_y + pz_h) + 44
itz_y = inet_bus_y + 44

# The services sit above both lines, so every connector coming up from a department stops at
# a line and never has to cross a card to get there.
svc_y = itz_y + ZTITLE + 14
svc_h = max(lb_h, resp_h)
perim_bus_y = svc_y + svc_h + 40
it_bus_y = perim_bus_y + 40
itz_h = (it_bus_y - itz_y) + 30
# The departments do span under the legend, so they are the ones that have to clear it.
zone_y = max(itz_y + itz_h + 46, legend_y + lg_h + 44)
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
    cv.zone(pz_x, pz_y, pz_w, pz_h, 'net-internet   10.89.4.0/24   -   outside the facility', 'zone_perim')
    cv.zone(ca_x, ca_y, ca_w, ca_h, 'Certificate Authorities', 'zone_ca')

    # --- buses (under cards)
    busL0, busL1 = lab_x + ZP, lab_x + W_lab - ZP
    busM0, busM1 = ml_x + ZP, ml_x + W_ml - ZP
    cv.hv([(busL0, bus_lab_y), (busL1, bus_lab_y)], C['bus_lab'], 4)
    cv.hv([(busM0, bus_lab_y), (busM1, bus_lab_y)], C['bus_ml'], 4)
    cv.pill(busL0 + 120, bus_lab_y - 16, 'net-lab  10.89.0.0/24  tcp/5075, tcp/5076, udp/5076', C['bus_lab'])
    cv.pill(busM0 + 120, bus_lab_y - 16, 'net-ml  10.89.1.0/24  tcp/5075, tcp/5076, udp/5076', C['bus_ml'])

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
    cv.zone(itz_x, itz_y, itz_w, itz_h,
            'IT zone   -   the facility\'s own segments: net-perimeter, and net-it behind it', 'zone_it')
    svc_span = lb_w + 70 + resp_w
    svc_x = itz_x + (itz_w - svc_span)/2
    lb = cv.card(svc_x, svc_y, 'pvxs-facility-lb', lb_l, 'lb', 'lb')
    # Bottom-aligned with the load balancer, which leaves the run down from the signing
    # certificate long enough to read as arriving from above.
    rc = cv.card(svc_x + lb_w + 70, svc_y + max(0, lb_h - resp_h),
                 'pvxs-lab-authority-status', resp_l, 'ocsp', 'ocsp')

    # --- certificate relationships (dashed purple, arrowheads)
    for cc in (c1, c2, c3):
        cv.hv([(rootc['cx'], rootc['bot']), (rootc['cx'], rootc['bot']+16), (cc['cx'], rootc['bot']+16), (cc['cx'], cc['top']-3)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{rootc["cx"]+8}" y="{rootc["bot"]+30}" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">signs</text>')
    # root names the responder (route around the right of the children row)
    nx = ca_x + ca_w + 40      # outside the authority group, which it must not cut through
    cv.hv([(rootc['x']+rootc['w'], rootc['top']+rootc['h']/2), (nx, rootc['top']+rootc['h']/2), (nx, rc['top']+24), (rc['x']+rc['w']+3, rc['top']+24)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{nx+6}" y="{(rootc["top"]+ca_y+ca_h)/2}" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">names</text>')
    # signer signs the responder's answers
    cv.hv([(c3['cx'], c3['bot']), (c3['cx'], ca_y+ca_h+26), (rc['x']+60, ca_y+ca_h+26), (rc['x']+60, rc['top']-3)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{c3["cx"]+8}" y="{ca_y+ca_h+22}" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">signs its answers</text>')

    # --- the perimeter segment: one line, tapped by every host that stands on it. The two
    # --- gateways reach it from below and the balancer from above; nothing else is on it,
    # --- which is what makes a gateway the only way in.
    perim_hosts = [gw1, gw2]
    pbus_x = [h['cx'] for h in perim_hosts] + [lb['cx']]
    pbus0 = min(pbus_x) - 40
    pbus1 = max(pbus_x) + 40
    cv.hv([(pbus0, perim_bus_y), (pbus1, perim_bus_y)], C['perim'], 4)
    for h in perim_hosts:
        cv.hv([(h['cx'], perim_bus_y), (h['cx'], h['top'])], C['perim'], 2)
        cv.dot(h['cx'], perim_bus_y, C['perim'])
    cv.hv([(lb['cx'], lb['bot']), (lb['cx'], perim_bus_y)], C['perim'], 2)
    cv.dot(lb['cx'], perim_bus_y, C['perim'])

    # the segment outside the facility: the workstation on it, and the balancer's other foot
    inet_x = [pcc['cx'], lb['cx'] + 40]
    cv.hv([(min(inet_x) - 70, inet_bus_y), (max(inet_x) + 70, inet_bus_y)], C['bus_inet'], 4)
    cv.hv([(pcc['cx'], pcc['bot']), (pcc['cx'], inet_bus_y)], C['bus_inet'], 2)
    cv.dot(pcc['cx'], inet_bus_y, C['bus_inet'])
    cv.hv([(lb['cx'] + 40, lb['top']), (lb['cx'] + 40, inet_bus_y)], C['bus_inet'], 2)
    cv.dot(lb['cx'] + 40, inet_bus_y, C['bus_inet'])
    cv.pill((min(inet_x) + max(inet_x))/2, inet_bus_y - 16,
            'net-internet  10.89.4.0/24  tcp/5075, tcp/5076, tcp/5175, tcp/5176', C['bus_inet'])
    # centred on the open span between the two zones, clear of the legend at the left end
    cv.pill(rx, perim_bus_y - 16, 'net-perimeter  10.89.2.0/24  tcp/5075, tcp/5076, tcp/5175, tcp/5176', C['perim'])

    # --- the IT segment: the responder's own, and nothing else stands on it. A certificate
    # --- manager has one interface, on its own department, so neither can address the other.
    it0, it1 = rc['cx'] - 110, rc['cx'] + 110
    cv.hv([(it0, it_bus_y), (it1, it_bus_y)], C['bus_it'], 4)
    cv.hv([(rc['cx'], it_bus_y), (rc['cx'], rc['bot'])], C['bus_it'], 2)
    cv.dot(rc['cx'], it_bus_y, C['bus_it'])
    cv.pill(rc['cx'], it_bus_y - 16, 'net-it  10.89.3.0/24  tcp/8888', C['bus_it'])

    # --- the legs each appliance has into the departments, so the name it is addressed by
    # --- can be answered where it is asked: the balancer for "facility", the responder for
    # --- the hostname the root's own extension gives.
    #
    # Each line has to climb past the first row of its zone, so the column is chosen rather
    # than guessed: the widest gap in that row, shared between the two appliances. Card
    # widths follow the text on them, so a column clear today closes the moment a line is
    # added to a card above it.
    def columns(row1_cards, lo, hi, n):
        blocked = sorted((c['x'] - 24, c['x'] + c['w'] + 24) for c in row1_cards)
        free, cur = [], lo
        for b0, b1 in blocked:
            if b0 > cur:
                free.append((cur, min(b0, hi)))
            cur = max(cur, b1)
            if cur >= hi:
                break
        if cur < hi:
            free.append((cur, hi))
        free = [(a, b) for a, b in free if b - a > 8]
        assert free, f'no clear column between {lo} and {hi}'
        a, b = max(free, key=lambda p: p[1] - p[0])
        return [a + (b - a) * (i + 1) / (n + 1) for i in range(n)]

    lab_cols = columns([cl, gw1], busL0, busL1, 2)
    ml_cols = columns([gw2, mcl], busM0, busM1, 2)
    for appliance, off, y, cols in ((lb, -20, it_bus_y + 26, (lab_cols[0], ml_cols[0])),
                                    (rc, -20, it_bus_y + 58, (lab_cols[1], ml_cols[1]))):
        for colr, sign, down in (('bus_lab', off, cols[0]), ('bus_ml', -off, cols[1])):
            cv.hv([(appliance['cx'] + sign, appliance['bot']), (appliance['cx'] + sign, y),
                   (down, y), (down, bus_lab_y)], C[colr], 2)
            cv.dot(down, bus_lab_y, C[colr])

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
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">federated, shared root: one facility root signing both departmental intermediates, so every certificate traces to it - the laboratory topologies/federated-shared-root/compose.yaml builds</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-federated-shared-root.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory - hand-drawn flat-design infographic.')
