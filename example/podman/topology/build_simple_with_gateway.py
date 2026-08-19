#!/usr/bin/env python3
# The simple topology plus a gateway: one laboratory segment, one self-signed root
# certificate authority held by the one certificate manager, two controllers and a client
# workstation - and a dual-homed gateway that also stands on a perimeter segment, so a
# workstation out there reaches the laboratory through it.
# Every coordinate is computed here. See topology_kit for the primitives.
from topology_kit import (C, CH, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
client_l = fields('Role: client','Image: lab',
 'eth0  net-lab  10.89.0.0/24',
 'Logins: guest, operator',
 'EPICS_PVA_AUTH_ISSUER: ROOT_ISSUER_SKID')
testioc_l = fields('Role: controller (IOC)','Image: testioc','eth0  net-lab  10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: testioc.db, testiocg.db','ACF: testioc.acf',
 'EPICS_PVA_AUTH_ISSUER: ROOT_ISSUER_SKID','Serves:',
 '    test:aiExample, test:stringExample, test:longExample',
 '    test:enumExample, test:arrayExample, test:calcExample',
 '    test:spec (SPECIAL), test:open (OPEN)')
tstioc_l = fields('Role: controller (IOC)','Image: tstioc','eth0  net-lab  10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: image.db, image.json','ACF: tstioc.acf',
 'EPICS_PVA_AUTH_ISSUER: ROOT_ISSUER_SKID',
 'Serves: tst:ArrayData, tst:ColorMode,','    and the rest of the image database')
pvacms_l = fields('Role: certificate manager (PVACMS)','Image: idm','eth0  net-lab  10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'CA keychain: certs/cert_auth.p12 - the CA root',
 'ACF: /etc/pvacms/pvacms.acf','Serves:',
 '    CERT:CREATE, CERT:LIST, CERT:ROOT, CERT:ISSUER',
 '    CERT:CREATE:ROOT_ISSUER, CERT:ISSUER:ROOT_ISSUER, CERT:ROOT:ROOT_ISSUER',
 '    CERT:LIST:ROOT_ISSUER:ALL, :EXPIRING, :PENDING_APPROVAL',
 '    CERT:STATUS:ROOT_ISSUER:<serial>')
# The one host with two interfaces: it stands on both segments at once, which is what lets
# the perimeter reach the laboratory.
gateway_l = fields('Role: gateway (dual-homed), net-lab <-> net-perimeter','Image: gateway',
 'eth0  net-lab        10.89.0.0/24   upstream side, to the laboratory',
 'eth1  net-perimeter  10.89.2.0/24   server side, where it is asked',
 'Program: p4p pvagw, layer 7','Config: config/gateway-lab.conf',
 'Serves on eth1 alone: "interface" pinned to its net-perimeter address',
 'Reached from outside at facility:5075 and facility:5076',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'Presents: CN=gateway',
 'Upstream: pvxs-lab-pvacms, pvxs-lab-testioc, pvxs-lab-tstioc',
 'ACF: gateway.acf','PVList: config/gateway-lab.pvlist')
perim_client_l = fields('Role: client','Image: internet',
 'eth0  net-internet   10.89.4.0/24',
 'Logins: guest, operator',
 'EPICS_PVA_NAME_SERVERS: facility:5075',
 'EPICS_PVA_AUTH_ISSUER: ROOT_ISSUER_SKID',
 'It names the facility, and the balancer carries its',
 '    calls on into the laboratory')
root_l = fields('Subject: CN=EPICS Root Certificate Authority',
 'SKID: ROOT_ISSUER_SKID','Issuer ID: ROOT_ISSUER',
 'Self-signed: it is its own issuer, and issues every',
 '    certificate in the laboratory directly',
 'File: certs/cert_auth.p12','Mounted into: pvxs-lab-pvacms')

# One authority, so one AUTHORITY entry: every certificate here traces to the same root, and
# a rule distinguishes holders by their user access group alone.
testacf_l = ['§Authorities',
 '    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority")','',
 '§UAGs','    UAG(OPERATORS) {operator}','    UAG(GUESTS)    {guest}','',
 '§ASGs','    ASG(SPECIAL)     test:spec','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS)',
 '            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(OPEN)        test:open','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { AUTHORITY(EPICS_CA)',
 '            PROTOCOL(TLS) METHOD(X509) }',
 '    ASG(DEFAULT)     everything else','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)',
 '            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }']
tstacf_l = ['§Authorities',
 '    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority")','',
 '§UAGs','    UAG(OPERATORS) {operator}','    UAG(GUESTS)    {guest}','',
 '§ASGs','    ASG(DEFAULT)','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)',
 '            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }']
cmsacf_l = ['at /etc/pvacms/pvacms.acf','',
 '§Authorities','    AUTHORITY(CMS_AUTH, "EPICS Root Certificate Authority")','',
 '§UAGs','    UAG(CMS_ADMIN) {admin, certadmin}','',
 '§ASGs','    ASG(DEFAULT) {','        RULE(0,READ)',
 '        RULE(1,WRITE) { UAG(CMS_ADMIN) AUTHORITY(CMS_AUTH)','            PROTOCOL(TLS) METHOD("x509") }','    }']
gwacf_l = ['at gateway.acf','',
 '§Authorities',
 '    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority")','',
 '§UAGs','    UAG(OPERATORS) {operator}','    UAG(GUESTS)    {guest}','',
 '§ASGs','    ASG(DEFAULT)','        RULE(1,READ)',
 '        RULE(1,WRITE,TRAPWRITE) { UAG(OPERATORS,GUESTS)',
 '            AUTHORITY(EPICS_CA) PROTOCOL(TLS) METHOD(X509) }']
# What the gateway carries across: laboratory values, and the certificate calls that let a
# perimeter workstation obtain its own certificate from the manager inside.
gwpvlist_l = ['at config/gateway-lab.pvlist','',
 '§Evaluation order','    EVALUATION ORDER ALLOW, DENY','',
 '§Laboratory process variables, forwarded',
 '    test:.*                    ALLOW',
 '    tst:.*                     ALLOW','',
 '§Certificate process variables, forwarded',
 '    CERT:CREATE:ROOT_ISSUER    ALLOW',
 '    CERT:STATUS:ROOT_ISSUER.*  ALLOW','',
 'So a perimeter workstation reads laboratory values and',
 'asks for a certificate, both through this gateway']

# ---------------------------------------------------------------- legend content
CHIPS = [('certificate authority - a file, mounted into a component', C['ca'][1]),
         ('PVACMS - certificate manager', C['pvacms'][1]),
         ('IOC - controller', C['ioc'][1]),
         ('client - workstation', C['client'][1]),
         ('gateway - proxies PVAccess between the', C['gateway'][1]),
         ('    laboratory and the DMZ', None),
         ('load balancer - owns the facility address', C['lb'][1]),
         ('    and maps a port to the gateway', None),
         ('a file a component loads: access security, or the list', C['file'][1]),
         ('    of process variables a gateway forwards', C['file'][1])]
SAMPLES = [('net-lab bus - tapping it = attached to net-lab', C['bus_lab'], 4, None),
           ('net-perimeter bus - the DMZ segment', C['perim'], 4, None),
           ('net-internet bus - outside the facility', C['bus_inet'], 4, None),
           ('certificate relationship - signs', C['cert'], 2, '6 5'),
           ('a file the component loads', C['filedrop'], 1.6, '2 4')]
NOTATION = ['10.89.0.0/24 : the laboratory segment, in CIDR. One podman',
            '               bridge, carrying this laboratory alone',
            '10.89.2.0/24 : the DMZ segment, its own podman bridge, where',
            '               the gateway is asked and the balancer answers',
            '10.89.4.0/24 : the segment outside the facility, where the',
            '               facility address is published',
            'eth0         : the host\'s interface on its own segment',
            'eth1         : the gateway\'s second interface, its foot on',
            '               the perimeter segment',
            'tcp/5075     : PVAccess, plaintext',
            'tcp/5076     : PVAccess over TLS',
            'udp/5076     : PVAccess search and beacons, sent to the',
            '               segment broadcast address',
            '',
            'Both segment CIDRs are pinned in compose.yaml, so they are',
            'this on every laboratory. Host addresses within a segment are',
            'assigned by podman when a container starts, and change',
            'between runs.']
ABBREV = ['CA     : certificate authority','SKID   : subject key identifier, 40 hex digits',
          'Issuer ID: the first 8 digits of a SKID','PVACMS : certificate manager',
          'IOC    : input output controller','ACF    : access security file',
          'PVList : the process variables a gateway forwards',
          'pvagw  : the p4p gateway program']
NOTE = ['A line claims attachment. Arrowheads appear only where','a direction is real.','',
        'A workstation outside names the facility address, so its',
        'search goes straight to the balancer, which hands it to',
        'the gateway, which searches the laboratory on its behalf.','',
        'ROOT_ISSUER and ROOT_ISSUER_SKID are named rather than','printed here: a fresh mint changes them.',
        'Values: issuer_ids.env']

# One appliance owns the facility address. Mapping a port to a different port would break
# PVAccess: a server names its own port in a search reply and the client dials that port on
# the address the reply arrived from, so a translated port would send it nowhere useful.
lb_l = fields('Role: facility load balancer, layer 4 (dual-homed)','Image: lb',
 'eth0  net-internet   10.89.4.0/24   (the facility address)',
 'eth1  net-perimeter  10.89.2.0/24   (its foot in the DMZ)',
 'The gateway stands only in the DMZ, so this is the one way in',
 'Maps inward, port for port:',
 '    facility:5075 -> pvxs-lab-gateway:5075',
 '    facility:5076 -> pvxs-lab-gateway:5076      over TLS',
 'This is the one device here where a port picks a destination. It',
 '    rewrites the destination and the packet is routed afterwards.',
 'It answers as itself to the gateway, so replies come back through',
 '    it. The gateway loses nothing by that: it authorises on the',
 '    certificate presented, not on the address it came from.')

# ---------------------------------------------------------------- geometry
M = 40
title_h = 64

# The file row fixes the columns, as it does on the federated pictures: one column per file,
# each as wide as the widest card standing in it, every card centred so a file drop falls
# straight. The gateway loads two files, so it owns two adjacent columns and spans them.
C_TESTIOC, C_TSTIOC, C_GWACF, C_GWPVL, C_CMS = range(5)
COLS = [max(colw('lab-client', client_l), colw('pvxs-lab-testioc', testioc_l), colw('testioc.acf', testacf_l)),
        max(colw('pvxs-lab-tstioc', tstioc_l), colw('tstioc.acf', tstacf_l)),
        colw('gateway.acf', gwacf_l),
        colw('config/gateway-lab.pvlist', gwpvlist_l),
        max(colw('pvxs-lab-pvacms', pvacms_l), colw('config/pvacms-lab.acf', cmsacf_l))]
cxs = [0]
for w in COLS[:-1]: cxs.append(cxs[-1] + w + GAP)
inner = cxs[-1] + COLS[-1]
W_lab = inner + 2*ZP
lab_x = M
# The right margin is wider than the left: the authority reaches the certificate manager
# down it, outside the network, and that line needs room to be read as outside.
RIGHT = 96
CANVAS_W = lab_x + W_lab + RIGHT

# legend, drawn by hand from the lists above. Both columns are measured from their own
# text rather than guessed, so a reworded line cannot run out past the border.
legend_x = M
top_y = title_h + 26          # where the boxes in the top band hang from
LEG_COL_GAP = 34
LEG_COL_L = int(max([len(t)*CH + 24 for t, _ in CHIPS] + [len(t)*CH + 50 for t, _, _, _ in SAMPLES])) + 10
LEG_COL_R = int(max(len(l)*CH for l in NOTATION + ABBREV + NOTE)) + 10
lg_w = 14 + LEG_COL_L + LEG_COL_GAP + LEG_COL_R + 14
lg_h = HDR + max(12 + len(CHIPS)*24 + 10 + len(SAMPLES)*24,
                 12 + LH + len(NOTATION)*LH + 10 + LH + len(ABBREV)*LH + 10 + len(NOTE)*LH) + 14

# the authority sits in the top band, right of the legend and above the certificate
# manager it is mounted into, so the eye follows it straight down into that card
root_w, root_h = measure('Root Certificate Authority', root_l)
ca_w = root_w + 2*ZP
ca_h = ZTITLE + 10 + root_h + 20
ca_x = lab_x + W_lab - ca_w
ca_y = top_y

# The perimeter stands in the top band between the legend and the authority, over the gateway
# that reaches it, so the link between them is a straight drop. The federated pictures put the
# perimeter in the same band, which is what makes the four comparable at a glance.
gwx = lab_x + ZP + (cxs[C_GWACF] + cxs[C_GWPVL] + COLS[C_GWPVL])/2
# Wide enough for the card AND for its own title strip: the title is set in 15px bold from
# 40px in, so a zone sized only by its card would let the title run out past the corner.
PERIM_TITLE = 'net-internet   10.89.4.0/24   -   outside the facility'
pz_w = max(measure('internet-client', perim_client_l)[0] + 2*ZP, 40 + len(PERIM_TITLE)*8.3 + 16)
pz_h = ZTITLE + 12 + measure('internet-client', perim_client_l)[1] + 20
pz_x = min(max(gwx - pz_w/2, legend_x + lg_w + 40), ca_x - pz_w - 40)
pz_y = top_y                         # level with the authority across the band

# The perimeter segment is drawn the way net-lab is: one horizontal line, tapped by each host
# that stands on it, labelled once. The outside workstation taps it from above, the gateway
# from below, which is the only other host on that segment.
lb_w, lb_h = measure('pvxs-facility-lb', lb_l)
gw_w = measure('pvxs-lab-gateway', gateway_l)[0]

# net-internet belongs to nobody in the facility, so its line is drawn above the DMZ box
# rather than inside it, and the balancer reaches up out of the box to stand on it.
band_y = max(ca_y + ca_h, pz_y + pz_h) + 20    # free track under the top band
inet_bus_y = max(ca_y + ca_h, pz_y + pz_h) + 44

# The DMZ reaches from under the outside workstation to over the gateway, which is the span
# the facility's own segment actually covers.
dmz_x = min(pz_x, gwx - gw_w/2 - ZP)
dmz_w = max(pz_x + pz_w, gwx + gw_w/2 + ZP) - dmz_x
dmz_y = inet_bus_y + 44
svc_y = dmz_y + ZTITLE + 14
perim_bus_y = svc_y + lb_h + 40
dmz_h = (perim_bus_y - dmz_y) + 30

# The laboratory spans under the legend, so it is what has to clear it.
zone_y = max(dmz_y + dmz_h + 46, top_y + lg_h + 44)

# The legend stands beside the DMZ rather than above it, so it drops to sit just clear of the
# laboratory instead of leaving a hole beneath itself.
legend_y = zone_y - lg_h - 44
CANVAS_H = 0                          # set once the rows are measured

# ---------------------------------------------------------------- emit
def build(cv):
    global CANVAS_H
    hdr = []

    row1_y = zone_y + ZTITLE + 14
    h_cl = max(measure('lab-client', client_l)[1], measure('pvxs-lab-gateway', gateway_l)[1])
    bus_y = row1_y + h_cl + 34
    row2_y = bus_y + 34
    h_r2 = max(measure('pvxs-lab-testioc', testioc_l)[1],
               measure('pvxs-lab-tstioc', tstioc_l)[1], measure('pvxs-lab-pvacms', pvacms_l)[1])
    files_y = row2_y + h_r2 + 46
    files_h = max(measure('x', l)[1] for l in (testacf_l, tstacf_l, gwacf_l, gwpvlist_l, cmsacf_l))
    zone_h = (files_y - zone_y) + files_h + ZP

    CANVAS_H = zone_y + zone_h + M

    cv.zone(lab_x, zone_y, W_lab, zone_h, 'net-lab   10.89.0.0/24   bridge, isolated   -   the whole laboratory', 'zone_lab')
    cv.zone(pz_x, pz_y, pz_w, pz_h, PERIM_TITLE, 'zone_perim')
    cv.zone(ca_x, ca_y, ca_w, ca_h, 'Certificate Authority', 'zone_ca')

    # --- the buses (under the cards)
    bus0, bus1 = lab_x + ZP, lab_x + W_lab - ZP
    cv.hv([(bus0, bus_y), (bus1, bus_y)], C['bus_lab'], 4)
    # At the right end, where the bus runs clear and the label has room above it.
    bus_label = 'net-lab  10.89.0.0/24  tcp/5075, tcp/5076, udp/5076'
    cv.pill(bus1 - 20 - (len(bus_label)*6.2 + 12)/2, bus_y - 16, bus_label, C['bus_lab'])

    def at(i, y, title, lines, kind, icon):
        """Centred in column i, which is what keeps a file drop vertical."""
        w = measure(title, lines)[0]
        return cv.card(lab_x + ZP + cxs[i] + (COLS[i] - w)/2, y, title, lines, kind, icon)

    cl = at(C_TESTIOC, row1_y, 'lab-client', client_l, 'client', 'client')
    gww = measure('pvxs-lab-gateway', gateway_l)[0]
    gw = cv.card(gwx - gww/2, row1_y, 'pvxs-lab-gateway', gateway_l, 'gateway', 'gateway')
    t1 = at(C_TESTIOC, row2_y, 'pvxs-lab-testioc', testioc_l, 'ioc', 'ioc')
    t2 = at(C_TSTIOC, row2_y, 'pvxs-lab-tstioc', tstioc_l, 'ioc', 'ioc')
    pv = at(C_CMS, row2_y, 'pvxs-lab-pvacms', pvacms_l, 'pvacms', 'pvacms')
    f1 = at(C_TESTIOC, files_y, 'testioc.acf', testacf_l, 'file', 'file')
    f2 = at(C_TSTIOC, files_y, 'tstioc.acf', tstacf_l, 'file', 'file')
    fg = at(C_GWACF, files_y, 'gateway.acf', gwacf_l, 'file', 'file')
    fp = at(C_GWPVL, files_y, 'config/gateway-lab.pvlist', gwpvlist_l, 'file', 'file')
    f3 = at(C_CMS, files_y, 'config/pvacms-lab.acf', cmsacf_l, 'file', 'file')
    rootc = cv.card(ca_x + ZP, ca_y + ZTITLE + 10, 'Root Certificate Authority', root_l, 'ca', 'ca')
    pcw = measure('internet-client', perim_client_l)[0]
    pc = cv.card(pz_x + (pz_w - pcw)/2, pz_y + ZTITLE + 12, 'internet-client', perim_client_l, 'client', 'client')

    # --- bus taps: the gateway and the client from above, the servers from below
    for t in (gw, cl):
        cv.hv([(t['cx'], t['bot']), (t['cx'], bus_y)], C['bus_lab'], 2); cv.dot(t['cx'], bus_y, C['bus_lab'])
    for t in (t1, t2, pv):
        cv.hv([(t['cx'], bus_y), (t['cx'], t['top'])], C['bus_lab'], 2); cv.dot(t['cx'], bus_y, C['bus_lab'])

    # --- the perimeter segment: the outside workstation taps it from above, the gateway's
    # --- second interface from below
    cv.zone(dmz_x, dmz_y, dmz_w, dmz_h, 'DMZ   -   net-perimeter, where the gateway stands', 'zone_it')
    lb = cv.card(dmz_x + (dmz_w - lb_w)/2, svc_y, 'pvxs-facility-lb', lb_l, 'lb', 'lb')

    pb0 = min(lb['cx'], gw['cx']) - 60
    pb1 = max(lb['cx'], gw['cx']) + 60
    cv.hv([(pb0, perim_bus_y), (pb1, perim_bus_y)], C['perim'], 4)
    cv.hv([(lb['cx'], lb['bot']), (lb['cx'], perim_bus_y)], C['perim'], 2)
    cv.dot(lb['cx'], perim_bus_y, C['perim'])
    cv.hv([(gw['cx'], perim_bus_y), (gw['cx'], gw['top'])], C['perim'], 2)
    cv.dot(gw['cx'], perim_bus_y, C['perim'])
    cv.pill((pb0 + pb1)/2, perim_bus_y - 16,
            'net-perimeter  10.89.2.0/24  tcp/5075, tcp/5076', C['perim'])

    # the segment outside the facility: the workstation on it, and the balancer's other foot
    inet_x = [pc['cx'], lb['cx'] + 40]
    cv.hv([(min(inet_x) - 70, inet_bus_y), (max(inet_x) + 70, inet_bus_y)], C['bus_inet'], 4)
    cv.hv([(pc['cx'], pc['bot']), (pc['cx'], inet_bus_y)], C['bus_inet'], 2)
    cv.dot(pc['cx'], inet_bus_y, C['bus_inet'])
    cv.hv([(lb['cx'] + 40, lb['top']), (lb['cx'] + 40, inet_bus_y)], C['bus_inet'], 2)
    cv.dot(lb['cx'] + 40, inet_bus_y, C['bus_inet'])
    cv.pill((min(inet_x) + max(inet_x))/2, inet_bus_y - 16,
            'net-internet  10.89.4.0/24  tcp/5075, tcp/5076', C['bus_inet'])

    # --- the root reaches the certificate manager down the right margin, outside the
    # --- network: an authority is a file, held by the component it is mounted into
    nx = lab_x + W_lab + 40
    pmid = pv['top'] + pv['h']/2
    cv.hv([(rootc['cx'], rootc['bot']), (rootc['cx'], band_y), (nx, band_y), (nx, pmid),
           (pv['x']+pv['w']+3, pmid)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{nx-8}" y="{band_y+14}" text-anchor="end" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">held by, and signs every certificate directly</text>')

    # --- file drops (dotted grey). The gateway's second file hangs below the first, reached
    # --- down the column gap so the drop stays clear of the card above it.
    for comp, filecard in ((t1, f1), (t2, f2), (pv, f3)):
        cv.hv([(comp['cx'], comp['bot']), (comp['cx'], filecard['top'])], C['filedrop'], 1.6, dash='2 4')
    for dx, filecard, clear in ((-12, fg, 16), (12, fp, 28)):
        cv.hv([(gw['cx']+dx, gw['bot']), (gw['cx']+dx, filecard['top']-clear),
               (filecard['cx'], filecard['top']-clear), (filecard['cx'], filecard['top'])],
              C['filedrop'], 1.6, dash='2 4')

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
        # a continuation line carries the text alone, so the swatch stays one per kind
        if not label.startswith('    '):
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

    # --- page title
    hdr.append(f'<text x="{M}" y="40" font-family="Helvetica Neue,Arial,sans-serif" font-size="26" font-weight="bold" fill="{C["ink"]}">Secure PVAccess demonstration laboratory</text>')
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">simple with a gateway: one laboratory network, published at the facility address and reached through a gateway in the DMZ - example/podman</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-simple-with-gateway.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory, simple topology with a gateway to a perimeter network - hand-drawn flat-design infographic.')
