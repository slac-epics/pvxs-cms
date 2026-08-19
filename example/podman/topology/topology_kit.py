#!/usr/bin/env python3
# Shared drawing kit for the topology infographics. Flat design, Material palette,
# simple icons. There is deliberately no layout engine: a builder computes every
# position itself, so each picture matches its sketch exactly. This module holds only
# what is true of every picture - metrics, palette, primitives, assertions, assembly.
import html
import os

CH = 6.65          # Menlo 11px advance
LH = 15            # line height
HDR = 30           # card header band height
PAD = 12           # card side padding
GAP = 28           # column gap inside a zone
ZP = 26            # zone inner padding
ZTITLE = 44        # zone title strip height

C = {
    'bg':      '#FAFAFA',
    'ink':     '#263238',
    'zone_lab':      ('#E8EAF6', '#3949AB'),   # indigo
    'zone_ml':       ('#E0F2F1', '#00897B'),   # teal
    'zone_perim':    ('#FFF8E1', '#FFB300'),   # amber
    'zone_ca':       ('#F3E5F5', '#8E24AA'),   # purple
    'zone_it':       ('#EDE7F6', '#6A1B9A'),   # deep purple, the facility's own segments
    'client':  ('#ECEFF1', '#546E7A'),
    'gateway': ('#FFF3E0', '#FB8C00'),
    'ioc':     ('#E8F5E9', '#43A047'),
    'pvacms':  ('#E3F2FD', '#1E88E5'),
    'ca':      ('#EDE7F6', '#5E35B1'),
    'ocsp':    ('#FFEBEE', '#E53935'),
    'file':    ('#FFFDE7', '#9E9D24'),
    'bus_lab': '#3949AB',
    'bus_ml':  '#00897B',
    'bus_it':  '#6A1B9A',
    'bus_inet':'#455A64',                # outside the facility, and owned by nobody in it
    'perim':   '#FB8C00',
    'cert':    '#8E24AA',
    'filedrop':'#9E9E9E',
    'peer':   '#D81B60',
    'router': ('#FCE4EC', '#AD1457'),   # layer 3: forwards packets, knows nothing of PVAccess
    'lb':     ('#EFEBE9', '#5D4037'),   # owns the facility address and maps ports inward
}

def esc(s): return html.escape(s, quote=False)

def fields(*ls): return list(ls)

def measure(title, lines):
    w = max([len(title)*7.4+52] + [len(l.lstrip('§'))*CH for l in lines]) + 2*PAD
    h = HDR + 14 + len(lines)*LH
    return int(w), int(h)

def colw(title, lines): return measure(title, lines)[0]

ICONS = {}
def icon_client(x,y):   return f'<rect x="{x}" y="{y+2}" width="16" height="10" rx="1.5" fill="none" stroke="white" stroke-width="1.8"/><line x1="{x+8}" y1="{y+12}" x2="{x+8}" y2="{y+15}" stroke="white" stroke-width="1.8"/><line x1="{x+4}" y1="{y+15.5}" x2="{x+12}" y2="{y+15.5}" stroke="white" stroke-width="1.8"/>'
def icon_gateway(x,y):  return f'<path d="M {x} {y+6} h9 m-3 -3 l3 3 l-3 3" stroke="white" stroke-width="1.8" fill="none"/><path d="M {x+16} {y+12} h-9 m3 -3 l-3 3 l3 3" stroke="white" stroke-width="1.8" fill="none"/>'
def icon_ioc(x,y):      return f'<rect x="{x+2}" y="{y+2}" width="12" height="12" rx="1.5" fill="none" stroke="white" stroke-width="1.8"/>' + ''.join(f'<line x1="{x+5+i*3}" y1="{y}" x2="{x+5+i*3}" y2="{y+2}" stroke="white" stroke-width="1.4"/><line x1="{x+5+i*3}" y1="{y+14}" x2="{x+5+i*3}" y2="{y+16}" stroke="white" stroke-width="1.4"/>' for i in range(3))
def icon_pvacms(x,y):   return f'<circle cx="{x+6}" cy="{y+6}" r="4.2" fill="none" stroke="white" stroke-width="1.8"/><path d="M {x+9} {y+9} l6 6 m-2.5 -1 l2 -2 m-4.5 0 l1.6 -1.6" stroke="white" stroke-width="1.8" fill="none"/>'
def icon_ca(x,y):       return f'<path d="M {x+8} {y} l7 3 v5 c0 4 -3.5 7 -7 8 c-3.5 -1 -7 -4 -7 -8 v-5 z" fill="none" stroke="white" stroke-width="1.8"/><path d="M {x+5} {y+7.5} l2.2 2.2 l4 -4" stroke="white" stroke-width="1.8" fill="none"/>'
def icon_ocsp(x,y):     return f'<circle cx="{x+8}" cy="{y+8}" r="7" fill="none" stroke="white" stroke-width="1.8"/><path d="M {x+2.5} {y+8} h3 l1.6 -3.6 l2.4 7 l1.6 -3.4 h2.4" stroke="white" stroke-width="1.6" fill="none"/>'
def icon_file(x,y):     return f'<path d="M {x+2} {y} h8 l4 4 v12 h-12 z" fill="none" stroke="white" stroke-width="1.8"/><path d="M {x+10} {y} v4 h4" fill="none" stroke="white" stroke-width="1.4"/>'
def icon_router(x,y):   return ''.join(f'<line x1="{x+1}" y1="{y+3+r*5}" x2="{x+15}" y2="{y+3+r*5}" stroke="white" stroke-width="1.5"/>' for r in range(3)) + ''.join(f'<line x1="{x+4+ (r%2)*6 + c*8}" y1="{y+3+r*5}" x2="{x+4+(r%2)*6+c*8}" y2="{y+8+r*5}" stroke="white" stroke-width="1.5"/>' for r in range(2) for c in range(2))
def icon_lb(x,y):       return f'<line x1="{x+2}" y1="{y+8}" x2="{x+7}" y2="{y+8}" stroke="white" stroke-width="1.8"/>' + ''.join(f'<path d="M {x+7} {y+8} L {x+14} {y+2+r*6}" stroke="white" stroke-width="1.5" fill="none"/>' for r in range(3)) + f'<circle cx="{x+7}" cy="{y+8}" r="2" fill="white"/>'
def icon_net(x,y):      return f'<circle cx="{x+3}" cy="{y+13}" r="2.6" fill="white"/><circle cx="{x+13}" cy="{y+13}" r="2.6" fill="white"/><circle cx="{x+8}" cy="{y+3}" r="2.6" fill="white"/><path d="M {x+8} {y+3} L {x+3} {y+13} M {x+8} {y+3} L {x+13} {y+13} M {x+3} {y+13} H {x+13}" stroke="white" stroke-width="1.4"/>'
ICONS.update(client=icon_client, gateway=icon_gateway, ioc=icon_ioc, pvacms=icon_pvacms,
             ca=icon_ca, ocsp=icon_ocsp, file=icon_file, net=icon_net, router=icon_router, lb=icon_lb)

def overlap(a, b):
    _, ax, ay, aw, ah = a; _, bx, by, bw, bh = b
    return not (ax+aw <= bx or bx+bw <= ax or ay+ah <= by or by+bh <= ay)

def touches(px, py, r, m=8):
    _, x, y, w, h = r
    return x-m <= px <= x+w+m and y-m <= py <= y+h+m


class Canvas:
    """One picture in progress. State is per instance so two builders in one process
    cannot contaminate each other's element list or assertion inputs."""

    def __init__(self):
        self.out = []
        self.cards = []   # (name, x, y, w, h) for overlap assertions
        self.segs = []    # every hv() segment, for the line-through-card assertion

    def emit(self, markup):
        """Raw markup, for the one-off elements a picture needs beyond the primitives."""
        self.out.append(markup)

    def note_card(self, name, x, y, w, h):
        """Register a rectangle the assertions must respect but that is drawn by hand."""
        self.cards.append((name, x, y, w, h))

    def card(self, x, y, title, lines, kind, icon):
        body, accent = C[kind]
        w, h = measure(title, lines)
        self.out.append(f'<g><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{body}" stroke="{accent}" stroke-width="1.4"/>')
        self.out.append(f'<path d="M {x} {y+8} a8 8 0 0 1 8 -8 h{w-16} a8 8 0 0 1 8 8 v{HDR-8} h-{w} z" fill="{accent}"/>')
        self.out.append(ICONS[icon](x+9, y+7))
        self.out.append(f'<text x="{x+32}" y="{y+20}" font-family="Menlo,Consolas,monospace" font-size="12" font-weight="bold" fill="white" xml:space="preserve">{esc(title)}</text>')
        ty = y + HDR + 8 + 11
        for l in lines:
            bold = ' font-weight="bold"' if l.startswith('§') else ''
            self.out.append(f'<text x="{x+PAD}" y="{ty}" font-family="Menlo,Consolas,monospace" font-size="11"{bold} fill="{C["ink"]}" xml:space="preserve">{esc(l.lstrip("§"))}</text>')
            ty += LH
        self.out.append('</g>')
        self.cards.append((title, x, y, w, h))
        return {'x': x, 'y': y, 'w': w, 'h': h, 'cx': x+w/2, 'bot': y+h, 'top': y}

    def zone(self, x, y, w, h, title, kind):
        body, accent = C[kind]
        self.out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{body}" stroke="{accent}" stroke-width="1.6"/>')
        self.out.append(f'<path d="M {x} {y+10} a10 10 0 0 1 10 -10 h{w-20} a10 10 0 0 1 10 10 v{ZTITLE-10} h-{w} z" fill="{accent}" fill-opacity="0.92"/>')
        self.out.append(ICONS['net'](x+14, y+14))
        self.out.append(f'<text x="{x+40}" y="{y+28}" font-family="Helvetica Neue,Arial,sans-serif" font-size="15" font-weight="bold" fill="white">{esc(title)}</text>')

    def pill(self, x, y, text, color):
        w = len(text)*6.2 + 12
        self.out.append(f'<g><rect x="{x-w/2}" y="{y-9}" width="{w}" height="18" rx="9" fill="white" stroke="{color}" stroke-width="1.2"/>'
                        f'<text x="{x}" y="{y+3.5}" text-anchor="middle" font-family="Menlo,Consolas,monospace" font-size="10" fill="{color}">{esc(text)}</text></g>')

    def hv(self, points, color, width, dash=None, marker=False):
        for i in range(len(points)-1):
            self.segs.append((points[i][0], points[i][1], points[i+1][0], points[i+1][1]))
        d = 'M ' + ' L '.join(f'{p[0]} {p[1]}' for p in points)
        dd = f' stroke-dasharray="{dash}"' if dash else ''
        mm = ' marker-end="url(#arr)"' if marker else ''
        self.out.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"{dd}{mm} stroke-linejoin="round" stroke-linecap="round"/>')

    def dot(self, x, y, color):
        self.out.append(f'<circle cx="{x}" cy="{y}" r="4" fill="{color}"/>')

    def check(self):
        """Cards must not overlap, and no connector segment may cross a card it does not
        start or end at. A picture that trips these is wrong even if it renders."""
        bad = [(a[0], b[0]) for i, a in enumerate(self.cards) for b in self.cards[i+1:] if overlap(a, b)]
        assert not bad, f'card overlaps: {bad}'
        through = []
        for (x1, y1, x2, y2) in self.segs:
            for r in self.cards:
                if touches(x1, y1, r) or touches(x2, y2, r):
                    continue
                _, cx0, cy0, cw, ch = r
                lox, hix = sorted((x1, x2)); loy, hiy = sorted((y1, y2))
                if x1 == x2 and cx0+2 < x1 < cx0+cw-2 and min(hiy, cy0+ch-2) - max(loy, cy0+2) > 4:
                    through.append((r[0], 'v', x1))
                if y1 == y2 and cy0+2 < y1 < cy0+ch-2 and min(hix, cx0+cw-2) - max(lox, cx0+2) > 4:
                    through.append((r[0], 'h', y1))
        assert not through, f'line through card: {through}'
        print('assertions passed: no card overlaps, no line through a card')

    def write(self, path, width, height, header, comment):
        """Assert, wrap the accumulated elements in the SVG document, write it out.
        The assertions run here so no builder can skip them."""
        self.check()
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {int(width)} {int(height)}" '
               f'width="{int(width)}" height="{int(height)}" font-synthesis="none">',
               f'<!-- {comment} -->',
               f'<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
               f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{C["cert"]}"/></marker></defs>',
               f'<rect x="0" y="0" width="{int(width)}" height="{int(height)}" fill="{C["bg"]}"/>'] + list(header) + self.out + ['</svg>']
        open(path, 'w').write('\n'.join(svg))
        print('wrote', path, 'canvas %d x %d' % (width, height), 'cards:', len(self.cards))


def output_path(script_file, name):
    """Beside the builder that made it, so a picture is found next to its source."""
    return os.path.join(os.path.dirname(os.path.abspath(script_file)), name)
