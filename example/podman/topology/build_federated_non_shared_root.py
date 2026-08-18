#!/usr/bin/env python3
# The federated non-shared-root topology: two isolated zones, each with its own gateway,
# PVACMS and root certificate authority. The two roots are independent: neither signs the
# other, nothing sits above them, and each is rotated on its own. Trust comes from each
# keychain storing both roots as trust anchors, which is also what lets a certificate status
# reply signed under either root be verified.
# Every coordinate is computed here. See topology_kit for the primitives.
from topology_kit import (C, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
lab_client_l = fields('Role: client','Image: lab',
 'eth0  net-lab        10.89.0.0/24',
 'Route: 10.89.4.0/24 via pvxs-lab-router',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: pvxs-lab-pvacms, pvxs-lab-testioc, pvxs-lab-tstioc',
 'EPICS_PVA_NAME_SERVERS: pvxs-lab-ml-gateway:5075',
 '    the ML gateway, reached across net-internet')
lab_gw_l = fields('Role: gateway (dual-homed), net-lab <-> net-internet','Image: gateway',
 'eth0  net-lab        10.89.0.0/24   upstream side, to its department',
 'eth1  net-internet   10.89.4.0/24   server side, where it is asked',
 'Program: p4p pvagw, layer 7','Config: config/gateway-lab.conf',
 'Serves on eth1 alone: "interface" pinned to its net-internet address',
 'Reached directly at its own net-internet address, on 5075 and 5076',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'Presents: CN=gateway',
 'Upstream: pvxs-lab-pvacms, pvxs-lab-testioc, pvxs-lab-tstioc','ACF: gateway.acf','pvlist: config/gateway-lab.pvlist')
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
ml_gw_l = fields('Role: gateway (dual-homed), net-ml <-> net-internet','Image: gateway',
 'eth0  net-ml         10.89.1.0/24   upstream side, to its department',
 'eth1  net-internet   10.89.4.0/24   server side, where it is asked',
 'Program: p4p pvagw, layer 7','Config: config/gateway-ml.conf',
 'Serves on eth1 alone: "interface" pinned to its net-internet address',
 'Reached directly at its own net-internet address, on 5075 and 5076',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'Presents: CN=ml-gateway',
 'Upstream: pvxs-lab-ml, pvxs-lab-ml-ioc','ACF: gateway.acf','pvlist: config/gateway-ml.pvlist')
ml_client_l = fields('Role: client','Image: lab',
 'eth0  net-ml         10.89.1.0/24',
 'Route: 10.89.4.0/24 via pvxs-ml-router',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: pvxs-lab-ml, pvxs-lab-ml-ioc',
 'EPICS_PVA_NAME_SERVERS: pvxs-lab-gateway:5075',
 '    the Lab gateway, reached across net-internet')
mlioc_l = fields('Role: IOC','Image: ml-ioc','eth0  net-ml         10.89.1.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: mlioc.db','ACF: mlioc.acf',
 'Serves: ml:aiExample, ml:stringExample,','    ml:longExample, ml:open (OPEN)')
mlcms_l = fields('Role: PVACMS','Image: ml','eth0  net-ml         10.89.1.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'CA keychain: certs/ml_root.p12 - the root itself',
 'ACF: /etc/pvacms/pvacms.acf','Serves:','    CERT:CREATE, CERT:LIST, CERT:ROOT, CERT:ISSUER',
 '    CERT:CREATE:ML_ISSUER, CERT:ISSUER:ML_ISSUER, CERT:ROOT:ML_ISSUER',
 '    CERT:LIST:ML_ISSUER:ALL, :EXPIRING, :PENDING_APPROVAL',
 '    CERT:STATUS:ML_ISSUER:<serial>')
pc_l = fields('Role: client','Image: internet',
 'eth0  net-internet   10.89.4.0/24',
 'Listens: none (client only)','Logins: guest, operator',
 'EPICS_PVA_ADDR_LIST: none',
 'EPICS_PVA_NAME_SERVERS: pvxs-lab-gateway:5075, pvxs-lab-ml-gateway:5075')
lab_root_l = fields('Subject: CN=EPICS Lab Root Certificate Authority',
 'File: certs/lab_root.p12',
 'Signs the Lab intermediate, which signs the Lab certificates',
 'Rotated independently of the ML root')
ml_root_l = fields('Subject: CN=EPICS ML Root Certificate Authority',
 'SKID: ML_ISSUER_SKID','Issuer ID: ML_ISSUER',
 'File: certs/ml_root.p12','Mounted into: pvxs-lab-ml',
 'Signs every ML certificate itself',
 'Rotated independently of the Lab root')
labca_l = fields('Subject: CN=EPICS Controls Intermediate CA','SKID: LAB_ISSUER_SKID','Issuer ID: LAB_ISSUER',
 'Issued by: EPICS Lab Root Certificate Authority',
 'File: certs/lab_intermediate.p12','Mounted into: pvxs-lab-pvacms')

# With no authority above the two roots, trust comes from the holder storing both roots as
# anchors: one identity, many anchors. The anchor list is also what lets a status reply
# signed under either root be verified.
keychain_l = fields('File: one PKCS#12 keychain',
 '',
 'IDENTITY - exactly one, never more',
 '    Entity certificate: CN=guest',
 '    Private key',
 '',
 'TRUST ANCHORS - one or more',
 '    EPICS Lab Root Certificate Authority',
 '    EPICS ML Root Certificate Authority')

testacf_l = ['§Authorities',
 '    AUTHORITY(LAB_CA, "EPICS Lab Root Certificate Authority") {',
 '        AUTHORITY(AUTH_LAB, "EPICS Controls Intermediate CA")','    }',
 '    AUTHORITY(ML_CA, "EPICS ML Root Certificate Authority")','',
 '§UAGs','    UAG(OPERATORS) {gateway, operator}','    UAG(GUESTS)    {guest}',
 '    UAG(GATEWAYS)  {gateway, ml-gateway}','    UAG(BEAMLINE)  {OU=beamline}','    UAG(LAB_UNIT)  {OU=lab}','',
 '§ASGs','    ASG(SPECIAL)     test:spec','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)',
 '            AUTHORITY(AUTH_LAB, ML_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(LABSPEC)     test:labspec','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(LAB_UNIT)',
 '            AUTHORITY(LAB_CA, ML_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(OPEN)        test:open','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { AUTHORITY(LAB_CA, ML_CA)',
 '            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(GATEWAYS)',
 '            AUTHORITY(LAB_CA, ML_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(DEFAULT)     everything else','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)',
 '            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)',
 '            AUTHORITY(ML_CA) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(BEAMLINE)',
 '            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }']
tstacf_l = ['§Authorities',
 '    AUTHORITY(LAB_CA, "EPICS Lab Root Certificate Authority") {',
 '        AUTHORITY(AUTH_LAB, "EPICS Controls Intermediate CA")','    }',
 '    AUTHORITY(ML_CA, "EPICS ML Root Certificate Authority")','',
 '§UAGs','    UAG(OPERATORS) {gateway, operator}','    UAG(GUESTS)    {guest}','',
 '§ASGs','    ASG(DEFAULT)','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)',
 '            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)',
 '            AUTHORITY(ML_CA) PROTOCOL(TLS) METHOD(X509) }']
gwacf_l = ['in the gateway image','',
 '§Authorities','    AUTHORITY(LAB_CA, "EPICS Lab Root Certificate Authority")',
 '    AUTHORITY(ML_CA,  "EPICS ML Root Certificate Authority")','',
 '§UAGs','    UAG(USERS)         {guest, operator, remote}','    UAG(SPECIAL_USERS) {operator}','',
 '§ASGs','    ASG(SPECIAL)',
 '        RULE(1,READ) { UAG(USERS) AUTHORITY(LAB_CA, ML_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(SPECIAL_USERS)','            AUTHORITY(LAB_CA, ML_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(OPEN_WRITE)',
 '        RULE(1,READ) { AUTHORITY(LAB_CA, ML_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { AUTHORITY(LAB_CA, ML_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(CERT_CREATE) { RULE(1,READ) RULE(1,WRITE) }',
 '    ASG(CERT_STATUS) { RULE(1,READ) }',
 '    ASG(DEFAULT)',
 '        RULE(1,READ) { UAG(USERS) AUTHORITY(LAB_CA, ML_CA)','            PROTOCOL(TLS) METHOD(X509) }']
labpvl_l = ['test:.*                          ALLOW','tst:.*                           ALLOW',
 'test:spec                        ALLOW SPECIAL','test:open                        ALLOW OPEN_WRITE',
 'CERT:CREATE:LAB_ISSUER(?::.*)?   ALLOW CERT_CREATE','CERT:STATUS:LAB_ISSUER(?::.*)?   ALLOW CERT_STATUS',
 'CERT:LIST:LAB_ISSUER:ALL         ALLOW CERT_STATUS','CERT:LIST:LAB_ISSUER:EXPIRING    ALLOW CERT_STATUS']
labcmsacf_l = ['at /etc/pvacms/pvacms.acf','',
 '§Authorities','    AUTHORITY("EPICS Lab Root Certificate Authority") {',
 '        AUTHORITY(CMS_AUTH, "EPICS Controls Intermediate CA")','    }','',
 '§UAGs','    UAG(CMS_ADMIN) {admin, certadmin}','',
 '§ASGs','    ASG(DEFAULT) {','        RULE(0,READ)',
 '        RULE(1,WRITE) { UAG(CMS_ADMIN) AUTHORITY(CMS_AUTH)','            PROTOCOL(TLS) METHOD("x509") }','    }']
mlacf_l = ['§Authorities',
 '    AUTHORITY(LAB_CA, "EPICS Lab Root Certificate Authority") {',
 '        AUTHORITY(AUTH_LAB, "EPICS Controls Intermediate CA")','    }',
 '    AUTHORITY(ML_CA, "EPICS ML Root Certificate Authority")','',
 '§UAGs','    UAG(OPERATORS) {gateway, operator, mloperator}','    UAG(GUESTS)    {guest, mlsystem}',
 '    UAG(GATEWAYS)  {gateway, ml-gateway}','',
 '§ASGs','    ASG(OPEN)        ml:open','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { AUTHORITY(LAB_CA, ML_CA)','            PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(GATEWAYS)','            AUTHORITY(LAB_CA, ML_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(DEFAULT)     everything else','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)','            AUTHORITY(ML_CA) PROTOCOL(TLS) METHOD(X509) }',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)','            AUTHORITY(AUTH_LAB) PROTOCOL(TLS) METHOD(X509) }']
gwref_l = ['in the gateway image','the same file as the lab gateway','',
 '§Authorities','    AUTHORITY(LAB_CA, ...), AUTHORITY(ML_CA, ...)','',
 '§UAGs','    UAG(USERS), UAG(SPECIAL_USERS)','',
 '§ASGs','    ASG(SPECIAL), ASG(OPEN_WRITE),','    ASG(CERT_CREATE), ASG(CERT_STATUS),','    ASG(DEFAULT)','',
 'rules shown on the lab gateway copy']
mlpvl_l = ['ml:.*                            ALLOW','ml:open                          ALLOW OPEN_WRITE',
 'CERT:CREATE:ML_ISSUER(?::.*)?    ALLOW CERT_CREATE','CERT:STATUS:ML_ISSUER(?::.*)?    ALLOW CERT_STATUS',
 'CERT:LIST:ML_ISSUER:ALL          ALLOW CERT_STATUS','CERT:LIST:ML_ISSUER:EXPIRING     ALLOW CERT_STATUS']
mlcmsacf_l = ['at /etc/pvacms/pvacms.acf','',
 '§Authorities','    AUTHORITY(CMS_AUTH, "EPICS ML Root Certificate Authority")','',
 '§UAGs','    UAG(CMS_ADMIN) {admin, mlcertadmin}','',
 '§ASGs','    ASG(DEFAULT) {','        RULE(0,READ)',
 '        RULE(1,WRITE) { UAG(CMS_ADMIN) AUTHORITY(CMS_AUTH)','            PROTOCOL(TLS) METHOD("x509") }','    }']

def _router(dept, seg, cidr, far_gw, far_ports):
    return fields('Role: routing firewall, layers 3 and 4','Image: router',
     f'eth0  {seg:<14} {cidr}',
     'eth1  net-internet   10.89.4.0/24',
     f'Carries every packet leaving the {dept} department, and carries',
     '    it only to net-internet, where the other department presents',
     '    the outward face of its gateway',
     'Routes on the destination subnet alone, layer 3. The port decides',
     '    only whether a packet is permitted at all, layer 4:',
     f'    {far_ports[0]}, {far_ports[1]} to {far_gw} on net-internet',
     'Broadcast stays on the segment it was sent to, so a PVAccess',
     '    search stays inside the department. Anything past it is',
     '    reached by naming a server, which is unicast and routes.')
lab_router_l = _router('lab', 'net-lab', '10.89.0.0/24',
                       'pvxs-lab-ml-gateway', ('tcp/5075', 'tcp/5076'))
ml_router_l = _router('ML', 'net-ml', '10.89.1.0/24',
                      'pvxs-lab-gateway', ('tcp/5075', 'tcp/5076'))

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

# The legend's height decides where the rows below the top band start, so it is worked out
# here rather than while drawing.
chips = [('CA or certificate - a file, on no network', C['ca'][1]),
         ('PVACMS', C['pvacms'][1]),
         ('IOC', C['ioc'][1]),
         ('gateway - proxies PVAccess between a zone', C['gateway'][1]),
         ('    and the network outside the facility', None),
         ('router - forwards between segments, and', C['router'][1]),
         ('    states which may reach which', None),
         ('client - workstation', C['client'][1]),
         ('ACF or pvlist - a file a component loads', C['file'][1])]
samples = [('net-lab bus - tapping it = attached to net-lab', C['bus_lab'], 4, None),
           ('net-ml bus - the same for net-ml', C['bus_ml'], 4, None),
           ('net-internet bus - tapping it = attached', C['bus_inet'], 4, None),
           ('    to net-internet, outside the facility', None, 0, None),
           ('certificate relationship - signs', C['cert'], 2, '6 5'),
           ('a file the component loads', C['filedrop'], 1.6, '2 4')]
notation = ['10.89.0.0/24 : the segment, in CIDR. Three of them: the two',
            '               departments, and the network outside the facility,',
            '               where both gateways are asked. A host reaches',
            '               another segment through an appliance standing on both',
            'eth0, eth1   : the host\'s interface on each segment. A host on',
            '               two segments is marked dual-homed',
            'tcp/5075     : PVAccess, plaintext, either gateway',
            'tcp/5076     : PVAccess over TLS, either gateway',
            'udp/5076     : PVAccess search and beacons, sent to the',
            '               segment broadcast address, and staying there',
            '',
            'The segment CIDRs are pinned in compose.yaml, so they are',
            'these on every laboratory. Host addresses within a segment are',
            'assigned by podman when a container starts and are not fixed:',
            'per-container addresses cannot be set, because podman refuses',
            'them on a container attached to more than one segment.']
abbrev = ['CA     : certificate authority','SKID   : subject key identifier, 40 hex digits',
          'Issuer ID: the first 8 digits of a SKID','PVACMS : certificate manager',
          'IOC    : input output controller','ACF    : access security file',
          'pvlist : what a gateway forwards','ML     : machine learning']
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

pc_w, pc_h = measure('internet-client', pc_l)

# Two authority groups, not one. The gap between them is drawn wide enough that they cannot
# read as branches of a single tree, and nothing spans it.
CA_GAP = 150

lab_root_w, lab_root_h = measure('Lab Root CA', lab_root_l)
ml_root_w, ml_root_h = measure('ML Root CA', ml_root_l)
root_h = max(lab_root_h, ml_root_h)

lab_ca_children_w = colw('Lab Intermediate CA', labca_l)
ml_ca_children_w = 0                      # the ML root stands alone in its group
lab_ca_w = max(lab_ca_children_w, lab_root_w) + 2*ZP
ml_ca_w = max(ml_ca_children_w, ml_root_w) + 2*ZP

child_h = measure('Lab Intermediate CA', labca_l)[1]
ca_h = ZTITLE + 10 + root_h + 46 + child_h + 20
ca_y = title_h + 26
ca_span = lab_ca_w + CA_GAP + ml_ca_w

# The top band reads left to right: legend, then the two authority groups, which start
# immediately to its right. The legend's width is fixed by the two 470px columns build()
# lays it out in.
LEG_W = 14 + 470 + 34 + 470 + 14
lab_ca_x = M + LEG_W + 40
ml_ca_x = lab_ca_x + lab_ca_w + CA_GAP

ca_x, ca_w = lab_ca_x, ca_span

# The keychain sits below both groups and reaches up to each root. Anything drawn between or
# above them would read as the shared parent this topology does not have.
kc_w, kc_h = measure('Keychain: one identity, many trust anchors', keychain_l)
kc_x = (lab_ca_x + ml_ca_x + ml_ca_w)/2 - kc_w/2      # centred under the two groups it reaches
kc_y = ca_y + ca_h + 52

# net-internet is drawn the way every other segment is: one horizontal line, tapped by each
# host that stands on it, labelled once. It belongs to nobody in the facility, so the line is
# drawn below the box that holds the outside workstation rather than inside it: the
# workstation taps it from above, and the two gateways and the two routers reach up to it out
# of their departments.
router_w, router_h = measure('pvxs-lab-router', lab_router_l)

# The box outside the facility holds the one host that stands there and nothing else. It is
# wide enough for its own title strip as well as the card: the title is set in 15px bold from
# 40px in, so a box sized by the card alone would let the title run past the corner. It is
# centred between the two gateways, which is where the facility's outward face is, and hangs
# below the authority groups and the keychain, so nothing in the top band is crossed.
OUTSIDE_TITLE = 'net-internet   10.89.4.0/24   -   outside the facility'
outside_w = max(pc_w + 2*ZP, 40 + len(OUTSIDE_TITLE)*8.3 + 16)
outside_x = (gx1 + gx2)/2 - outside_w/2
outside_y = max(ca_y + ca_h, kc_y + kc_h) + 44
outside_h = ZTITLE + 12 + pc_h + 20
svc_y = outside_y + ZTITLE + 12
inet_bus_y = outside_y + outside_h + 44

# The departments span under the legend, so they are the ones that have to clear it.
zone_y = max(inet_bus_y + 76, legend_y + lg_h + 44)
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
    # the router shares this row, so the bus below it has to clear the tallest of the three
    row1_h = max(h_gw, h_cl, router_h)
    bus_lab_y = row1_y + row1_h + 34
    row2_y = bus_lab_y + 34
    h_r2 = max(measure('pvxs-lab-pvacms', pvacms_l)[1], measure('pvxs-lab-testioc', testioc_l)[1])
    files_y = row2_y + h_r2 + 46
    files_h = max(measure('x', l)[1] for l in (testacf_l, tstacf_l, gwacf_l, labpvl_l, labcmsacf_l, mlacf_l, gwref_l, mlpvl_l, mlcmsacf_l))
    zone_h = (files_y - zone_y) + files_h + ZP
    CANVAS_H = zone_y + zone_h + M

    cv.zone(lab_x, zone_y, W_lab, zone_h, 'net-lab   10.89.0.0/24   bridge, isolated   -   Lab zone (accelerator)', 'zone_lab')
    cv.zone(ml_x, zone_y, W_ml, zone_h, 'net-ml   10.89.1.0/24   bridge, isolated   -   ML zone', 'zone_ml')
    cv.zone(lab_ca_x, ca_y, lab_ca_w, ca_h, 'Lab Certificate Authority   -   independent', 'zone_ca')
    cv.zone(ml_ca_x, ca_y, ml_ca_w, ca_h, 'ML Certificate Authority   -   independent', 'zone_ca')

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

    # --- the two authority groups
    # Each group is drawn the same way and entirely within its own zone: a root on top, its own
    # intermediate beneath it. No line leaves a group, which is what makes the two independent.
    ca_cards = {}
    # The Lab root delegates to an intermediate; the ML root signs for itself.
    for tag, zx, zw, root_t, root_b, int_t, int_b in (
            ('lab', lab_ca_x, lab_ca_w, 'Lab Root CA', lab_root_l, 'Lab Intermediate CA', labca_l),
            ('ml', ml_ca_x, ml_ca_w, 'ML Root CA', ml_root_l, None, None)):
        rootc = cv.card(zx + zw/2 - measure(root_t, root_b)[0]/2, ca_y + ZTITLE + 10, root_t, root_b, 'ca', 'ca')
        ci = None
        if int_t:
            ci = cv.card(zx + zw/2 - colw(int_t, int_b)/2, rootc['bot'] + 46, int_t, int_b, 'ca', 'ca')
        ca_cards[tag] = (rootc, ci)

    # --- certificate relationships (dashed purple, arrowheads), one self-contained set per root
    for tag in ('lab', 'ml'):
        rootc, ci = ca_cards[tag]
        if ci is None:
            continue
        cv.hv([(rootc['cx'], rootc['bot']), (rootc['cx'], ci['top']-3)], C['cert'], 2, dash='6 5', marker=True)
        cv.emit(f'<text x="{rootc["cx"]+8}" y="{rootc["bot"]+26}" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">signs</text>')

    # --- the keychain, and the fact that makes this topology work: it holds BOTH roots
    kc = cv.card(kc_x, kc_y, 'Keychain: one identity, many trust anchors', keychain_l, 'file', 'file')
    for tag in ('lab', 'ml'):
        rootc = ca_cards[tag][0]
        side = kc['x'] - 3 if tag == 'lab' else kc['x'] + kc['w'] + 3
        # Hugging the root card keeps the lane inside the authority group, clear of the
        # legend that stands immediately left of the Lab group.
        lane = (rootc['x'] - 20) if tag == 'lab' else (rootc['x'] + rootc['w'] + 20)
        cv.hv([(side, kc['top']+26), (lane, kc['top']+26), (lane, rootc['top']+rootc['h']/2),
               (rootc['x'] - 3 if tag == 'lab' else rootc['x'] + rootc['w'] + 3, rootc['top']+rootc['h']/2)],
              C['cert'], 2, dash='2 4', marker=True)
    cv.emit(f'<text x="{kc["cx"]}" y="{kc["top"]-10}" text-anchor="middle" font-family="Menlo,Consolas,monospace" font-size="11" fill="{C["cert"]}">stores both roots as trust anchors, so certificates and status replies from either department verify</text>')

    # --- net-internet: one line, tapped by every host that stands on it. The two gateways
    # --- and the two routers reach up to it out of their departments; the workstation
    # --- stands outside the facility, in its own box above the line, and taps it downwards.
    cv.zone(outside_x, outside_y, outside_w, outside_h, OUTSIDE_TITLE, 'zone_perim')
    pcc = cv.card(outside_x + (outside_w - pc_w)/2, svc_y, 'internet-client', pc_l, 'client', 'client')
    labr = cv.card((gw1['x'] + gw1['w'] + lab_x + W_lab - ZP - router_w)/2, row1_y,
                   'pvxs-lab-router', lab_router_l, 'router', 'router')
    mlr = cv.card((ml_x + ZP + gw2['x'] - router_w)/2, row1_y,
                  'pvxs-ml-router', ml_router_l, 'router', 'router')

    inet_hosts = [labr, mlr, gw1, gw2]
    inet_x = [h['cx'] for h in inet_hosts] + [pcc['cx']]
    cv.hv([(min(inet_x) - 40, inet_bus_y), (max(inet_x) + 40, inet_bus_y)], C['bus_inet'], 4)
    for h in inet_hosts:
        cv.hv([(h['cx'], inet_bus_y), (h['cx'], h['top'])], C['bus_inet'], 2)
        cv.dot(h['cx'], inet_bus_y, C['bus_inet'])
    cv.hv([(pcc['cx'], pcc['bot']), (pcc['cx'], inet_bus_y)], C['bus_inet'], 2)
    cv.dot(pcc['cx'], inet_bus_y, C['bus_inet'])
    # On the widest open stretch of the line, between the lab gateway's tap and the lab
    # router's, so the label sits clear of every tap and of the workstation above it.
    cv.pill((gw1['cx'] + labr['cx'])/2, inet_bus_y - 16,
            'net-internet  10.89.4.0/24  tcp/5075, tcp/5076', C['bus_inet'])

    # each router stands on its own department's segment as well
    for r, colr in ((labr, 'bus_lab'), (mlr, 'bus_ml')):
        cv.hv([(r['cx'], r['bot']), (r['cx'], bus_lab_y)], C[colr], 2)
        cv.dot(r['cx'], bus_lab_y, C[colr])

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
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">federated, non-shared root: each department has its own root, and every keychain trusts both - example/podman</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-federated-non-shared-root.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory, federated with two independent root\n     certificate authorities - hand-drawn flat-design infographic.')
