#!/usr/bin/env python3
# The simple topology: one network, one self-signed root certificate authority held by the
# one PVACMS, two IOCs and a client workstation, all on one segment. The root issues every
# certificate directly, and every host reaches every other over the same bus.
# Every coordinate is computed here. See topology_kit for the primitives.
from topology_kit import (C, CH, GAP, HDR, LH, ZP, ZTITLE, Canvas, colw, esc, fields,
                          measure, output_path)

# ---------------------------------------------------------------- content
client_l = fields('Role: client','Image: lab',
 'eth0  net-lab  10.89.0.0/24',
 'Logins: guest, operator',
 'EPICS_PVA_AUTH_ISSUER: ROOT_ISSUER_SKID')
testioc_l = fields('Role: IOC','Image: testioc','eth0  net-lab  10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: testioc.db, testiocg.db','ACF: testioc.acf',
 'EPICS_PVA_AUTH_ISSUER: ROOT_ISSUER_SKID','Serves:',
 '    test:aiExample, test:stringExample, test:longExample',
 '    test:enumExample, test:arrayExample, test:calcExample',
 '    test:spec (SPECIAL), test:open (OPEN)')
tstioc_l = fields('Role: IOC','Image: tstioc','eth0  net-lab  10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'DB: image.db, image.json','ACF: tstioc.acf',
 'EPICS_PVA_AUTH_ISSUER: ROOT_ISSUER_SKID',
 'Serves: tst:ArrayData, tst:ColorMode,','    and the rest of the image database')
pvacms_l = fields('Role: PVACMS','Image: idm','eth0  net-lab  10.89.0.0/24',
 'Listens: tcp/5075 PVA   tcp/5076 PVA over TLS   udp/5076 PVA search',
 'CA keychain: certs/cert_auth.p12 - the CA root',
 'ACF: /etc/pvacms/pvacms.acf','Serves:',
 '    CERT:CREATE, CERT:LIST, CERT:ROOT, CERT:ISSUER',
 '    CERT:CREATE:ROOT_ISSUER, CERT:ISSUER:ROOT_ISSUER, CERT:ROOT:ROOT_ISSUER',
 '    CERT:LIST:ROOT_ISSUER:ALL, :EXPIRING, :PENDING_APPROVAL',
 '    CERT:STATUS:ROOT_ISSUER:<serial>')
root_l = fields('Subject: CN=EPICS Root Certificate Authority',
 'SKID: ROOT_ISSUER_SKID','Issuer ID: ROOT_ISSUER',
 'Self-signed: it is its own issuer, and issues every',
 '    certificate in the laboratory directly',
 'File: certs/cert_auth.p12','Mounted into: pvxs-lab-pvacms')

# One authority, so one AUTHORITY entry. A rule distinguishes holders by their user access
# group alone.
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

# ---------------------------------------------------------------- legend content
CHIPS = [('certificate authority - a file, mounted into a component', C['ca'][1]),
         ('PVACMS', C['pvacms'][1]),
         ('IOC', C['ioc'][1]),
         ('client - workstation', C['client'][1]),
         ('ACF - an access security file a component loads', C['file'][1])]
SAMPLES = [('net-lab bus - tapping it = attached to net-lab', C['bus_lab'], 4, None),
           ('certificate relationship - signs', C['cert'], 2, '6 5'),
           ('an access security file the component loads', C['filedrop'], 1.6, '2 4')]
NOTATION = ['10.89.0.0/24 : the segment, in CIDR. One podman bridge, carrying',
            '               this laboratory alone',
            'eth0         : the host\'s interface on that segment. Every host',
            '               here sits on that one segment',
            'tcp/5075     : PVAccess, plaintext',
            'tcp/5076     : PVAccess over TLS',
            'udp/5076     : PVAccess search and beacons, sent to the',
            '               segment broadcast address',
            '',
            'The segment CIDR is pinned in compose.yaml, so it is this on',
            'every laboratory. Host addresses within the segment are assigned',
            'by podman when a container starts, and change between runs.']
ABBREV = ['CA     : certificate authority','SKID   : subject key identifier, 40 hex digits',
          'Issuer ID: the first 8 digits of a SKID','PVACMS : certificate manager',
          'IOC    : input output controller','ACF    : access security file']
NOTE = ['A line claims attachment. Arrowheads mark a real direction.','',

        'ROOT_ISSUER and ROOT_ISSUER_SKID are named here:','a fresh mint changes them.',
        'Values: issuer_ids.env']

# ---------------------------------------------------------------- geometry
M = 40
title_h = 64

# One column per service, as wide as the widest card in it, with every card centred so a
# file drop is a straight line down.
COLS = [max(colw('lab-client', client_l), colw('pvxs-lab-testioc', testioc_l), colw('testioc.acf', testacf_l)),
        max(colw('pvxs-lab-tstioc', tstioc_l), colw('tstioc.acf', tstacf_l)),
        max(colw('pvxs-lab-pvacms', pvacms_l), colw('config/pvacms-lab.acf', cmsacf_l))]
cxs = [0]
for w in COLS[:-1]: cxs.append(cxs[-1] + w + GAP)
inner = cxs[-1] + COLS[-1]
W_lab = inner + 2*ZP
lab_x = M
# The right margin is wider than the left: the authority reaches PVACMS down it, outside
# the network, and that line needs room to be read as outside.
RIGHT = 96
CANVAS_W = lab_x + W_lab + RIGHT

# legend, drawn by hand from the lists above. Both columns are measured from their own text.
legend_x, legend_y = M, title_h + 26
LEG_COL_GAP = 34
LEG_COL_L = int(max([len(t)*CH + 24 for t, _ in CHIPS] + [len(t)*CH + 50 for t, _, _, _ in SAMPLES])) + 10
LEG_COL_R = int(max(len(l)*CH for l in NOTATION + ABBREV + NOTE)) + 10
lg_w = 14 + LEG_COL_L + LEG_COL_GAP + LEG_COL_R + 14
lg_h = HDR + max(12 + len(CHIPS)*24 + 10 + len(SAMPLES)*24,
                 12 + LH + len(NOTATION)*LH + 10 + LH + len(ABBREV)*LH + 10 + len(NOTE)*LH) + 14

# the authority sits in the top band, right of the legend and above the PVACMS it is
# mounted into, so the eye follows it straight down into that card
root_w, root_h = measure('Root Certificate Authority', root_l)
ca_w = root_w + 2*ZP
ca_h = ZTITLE + 10 + root_h + 20
ca_x = lab_x + W_lab - ca_w
ca_y = legend_y + lg_h - ca_h

band_y = legend_y + lg_h + 24        # free track under the top band
zone_y = legend_y + lg_h + 60
CANVAS_H = 0                          # set once the rows are measured

# ---------------------------------------------------------------- emit
def build(cv):
    global CANVAS_H
    hdr = []

    row1_y = zone_y + ZTITLE + 14
    h_cl = measure('lab-client', client_l)[1]
    bus_y = row1_y + h_cl + 34
    row2_y = bus_y + 34
    h_r2 = max(measure('pvxs-lab-testioc', testioc_l)[1], measure('pvxs-lab-tstioc', tstioc_l)[1],
               measure('pvxs-lab-pvacms', pvacms_l)[1])
    files_y = row2_y + h_r2 + 46
    files_h = max(measure('x', l)[1] for l in (testacf_l, tstacf_l, cmsacf_l))
    zone_h = (files_y - zone_y) + files_h + ZP
    CANVAS_H = zone_y + zone_h + M

    cv.zone(lab_x, zone_y, W_lab, zone_h, 'net-lab   10.89.0.0/24   bridge, isolated   -   the whole laboratory', 'zone_lab')
    cv.zone(ca_x, ca_y, ca_w, ca_h, 'Certificate Authority', 'zone_ca')

    # --- the bus (under the cards)
    bus0, bus1 = lab_x + ZP, lab_x + W_lab - ZP
    cv.hv([(bus0, bus_y), (bus1, bus_y)], C['bus_lab'], 4)
    # At the right end, where the bus runs clear and the label has room above it.
    bus_label = 'net-lab  10.89.0.0/24  tcp/5075, tcp/5076, udp/5076'
    cv.pill(bus1 - 20 - (len(bus_label)*6.2 + 12)/2, bus_y - 16, bus_label, C['bus_lab'])

    def at(i, y, title, lines, kind, icon):
        """Centred in column i, which is what keeps a file drop vertical."""
        w = measure(title, lines)[0]
        return cv.card(lab_x + ZP + cxs[i] + (COLS[i] - w)/2, y, title, lines, kind, icon)

    cl = at(0, row1_y, 'lab-client', client_l, 'client', 'client')
    t1 = at(0, row2_y, 'pvxs-lab-testioc', testioc_l, 'ioc', 'ioc')
    t2 = at(1, row2_y, 'pvxs-lab-tstioc', tstioc_l, 'ioc', 'ioc')
    pv = at(2, row2_y, 'pvxs-lab-pvacms', pvacms_l, 'pvacms', 'pvacms')
    f1 = at(0, files_y, 'testioc.acf', testacf_l, 'file', 'file')
    f2 = at(1, files_y, 'tstioc.acf', tstacf_l, 'file', 'file')
    f3 = at(2, files_y, 'config/pvacms-lab.acf', cmsacf_l, 'file', 'file')
    rootc = cv.card(ca_x + ZP, ca_y + ZTITLE + 10, 'Root Certificate Authority', root_l, 'ca', 'ca')

    # --- bus taps: the client from above, the servers from below
    cv.hv([(cl['cx'], cl['bot']), (cl['cx'], bus_y)], C['bus_lab'], 2); cv.dot(cl['cx'], bus_y, C['bus_lab'])
    for t in (t1, t2, pv):
        cv.hv([(t['cx'], bus_y), (t['cx'], t['top'])], C['bus_lab'], 2); cv.dot(t['cx'], bus_y, C['bus_lab'])

    # --- the root reaches PVACMS down the right margin, outside the network: an authority
    # --- is a file, held by the component it is mounted into
    nx = lab_x + W_lab + 40
    pmid = pv['top'] + pv['h']/2
    cv.hv([(rootc['cx'], rootc['bot']), (rootc['cx'], band_y), (nx, band_y), (nx, pmid),
           (pv['x']+pv['w']+3, pmid)], C['cert'], 2, dash='6 5', marker=True)
    cv.emit(f'<text x="{nx-8}" y="{band_y+14}" text-anchor="end" font-family="Menlo,Consolas,monospace" font-size="10" fill="{C["cert"]}">held by, and signs every certificate directly</text>')

    # --- file drops (dotted grey)
    for comp, filecard in ((t1, f1), (t2, f2), (pv, f3)):
        cv.hv([(comp['cx'], comp['bot']), (comp['cx'], filecard['top'])], C['filedrop'], 1.6, dash='2 4')

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

    # --- page title
    hdr.append(f'<text x="{M}" y="40" font-family="Helvetica Neue,Arial,sans-serif" font-size="26" font-weight="bold" fill="{C["ink"]}">Secure PVAccess demonstration laboratory</text>')
    hdr.append(f'<text x="{M}" y="60" font-family="Helvetica Neue,Arial,sans-serif" font-size="14" fill="#607D8B">simple: one network, one certificate authority, every host reaching every other directly - example/podman</text>')
    return hdr


cv = Canvas()
hdr = build(cv)
cv.write(output_path(__file__, 'topology-simple.svg'), CANVAS_W, CANVAS_H, hdr,
         'Secure PVAccess demonstration laboratory, simple topology - hand-drawn flat-design infographic.')
