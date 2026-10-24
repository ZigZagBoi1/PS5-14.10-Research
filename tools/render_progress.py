"""Render an explicitly reviewed evidence rubric. Never infers exploit success."""
import argparse
import hashlib
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = '<!-- RESEARCH_PROGRESS:START -->'
END = '<!-- RESEARCH_PROGRESS:END -->'

COLORS = {
    'full':    '#22c55e',
    'partial': '#3b82f6',
    'zero':    '#374151',
    'track':   '#1f2937',
    'card':    '#0f172a',
    'card2':   '#1e293b',
    'border':  '#334155',
    'text':    '#f1f5f9',
    'dim':     '#94a3b8',
    'accent':  '#60a5fa',
}


def bar_color(earned, weight):
    if earned == weight:
        return COLORS['full']
    if earned > 0:
        return COLORS['partial']
    return COLORS['zero']


def render():
    data = json.loads((ROOT / 'docs/progress.json').read_text(encoding='utf-8'))
    rows = data['milestones']
    assert sum(r['weight'] for r in rows) == 100
    for row in rows:
        assert 0 <= row['earned'] <= row['weight']
        assert sum(c['weight'] for c in row['checks']) == row['weight']
        assert sum(c['earned'] for c in row['checks']) == row['earned']
        for check in row['checks']:
            assert 0 <= check['earned'] <= check['weight']
    for path, expected in data['evidence_hashes'].items():
        assert hashlib.sha256((ROOT / path).read_text(encoding="utf-8").encode("utf-8")).hexdigest() == expected, f'Re-audit changed evidence: {path}'
    inventory = {'lua_probe_files': len(list((ROOT / 'probes').rglob('*.lua'))),
                 'text_result_files': len(list((ROOT / 'results').rglob('*.txt')))}
    assert inventory == data['inventory'], 'Inventory changed: re-audit docs/progress.json'
    score = sum(r['earned'] for r in rows)

    W = 800
    row_h = 36
    pad_top = 100
    pad_bot = 60
    H = pad_top + len(rows) * row_h + pad_bot
    bar_x = 380
    bar_w = 360
    label_x = 32
    score_x = bar_x + bar_w

    milestone_rows = []
    for i, r in enumerate(rows):
        y = pad_top + i * row_h
        cy = y + row_h // 2
        fill_w = (r['earned'] / r['weight'] * bar_w) if r['weight'] > 0 else 0
        col = bar_color(r['earned'], r['weight'])
        tag = f"{r['earned']}/{r['weight']}"
        title_esc = html.escape(r['title'])
        milestone_rows.append(
            f'<rect x="{bar_x}" y="{cy - 8}" width="{bar_w}" height="16" rx="4" fill="{COLORS["track"]}"/>'
            f'<rect x="{bar_x}" y="{cy - 8}" width="{fill_w:g}" height="16" rx="4" fill="{col}"/>'
            f'<text x="{label_x}" y="{cy + 5}" font-family="\'Segoe UI\',system-ui,sans-serif" font-size="13" fill="{COLORS["text"]}">{title_esc}</text>'
            f'<text x="{score_x + 8}" y="{cy + 5}" font-family="\'Segoe UI\',system-ui,sans-serif" font-size="12" font-weight="600" fill="{COLORS["dim"]}">{tag}</text>'
        )

    pct = score
    ring_cx, ring_cy, ring_r = 120, 52, 32
    ring_circ = 2 * 3.14159 * ring_r
    ring_fill = ring_circ * pct / 100
    ring_gap = ring_circ - ring_fill

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-labelledby="title desc">
<title id="title">14.10 milestone estimate: {score} of 100</title>
<desc id="desc">Subjective evidence rubric. Not time remaining or odds of success. Kernel read/write is not demonstrated.</desc>
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
<stop offset="0%" stop-color="{COLORS['card']}"/>
<stop offset="100%" stop-color="{COLORS['card2']}"/>
</linearGradient>
</defs>
<rect width="{W}" height="{H}" rx="12" fill="url(#bg)" stroke="{COLORS['border']}" stroke-width="1"/>

<!-- Score ring -->
<circle cx="{ring_cx}" cy="{ring_cy}" r="{ring_r}" fill="none" stroke="{COLORS['track']}" stroke-width="6"/>
<circle cx="{ring_cx}" cy="{ring_cy}" r="{ring_r}" fill="none" stroke="{COLORS['accent']}" stroke-width="6" stroke-dasharray="{ring_fill:g} {ring_gap:g}" stroke-dashoffset="{ring_circ * 0.25:g}" stroke-linecap="round"/>
<text x="{ring_cx}" y="{ring_cy + 7}" text-anchor="middle" font-family="'Segoe UI',system-ui,sans-serif" font-size="22" font-weight="700" fill="{COLORS['text']}">{score}</text>

<!-- Header -->
<text x="170" y="40" font-family="'Segoe UI',system-ui,sans-serif" font-size="18" font-weight="600" fill="{COLORS['text']}">PS5 14.10 Research Progress</text>
<text x="170" y="62" font-family="'Segoe UI',system-ui,sans-serif" font-size="12" fill="{COLORS['dim']}">Evidence-weighted milestones · Kernel R/W not demonstrated · Audited {html.escape(data['audit_date'])}</text>

<!-- Divider -->
<line x1="24" y1="{pad_top - 12}" x2="{W - 24}" y2="{pad_top - 12}" stroke="{COLORS['border']}" stroke-width="1"/>

<!-- Milestone rows -->
{''.join(milestone_rows)}

<!-- Footer -->
<text x="{W // 2}" y="{H - 20}" text-anchor="middle" font-family="'Segoe UI',system-ui,sans-serif" font-size="11" fill="{COLORS['dim']}">Judgment-based estimate · {inventory['lua_probe_files']} probes · {inventory['text_result_files']} results · Hypervisor bypass excluded</text>
</svg>
'''

    table = '\n'.join(f"| {r['title']} | {r['earned']}/{r['weight']} |" for r in rows)
    block = f'''{START}
## Research progress

[![14.10 evidence-weighted milestone estimate: {score}/100](docs/images/research_progress.svg)](docs/PROGRESS_AUDIT.md)

**{score}/100 (~{score}%) on a subjective, evidence-weighted milestone rubric.** This is not a measured percentage of unknown exploit work, time remaining, or probability of success. **Kernel read/write on 14.10 is not demonstrated.** Hypervisor bypass is excluded from this score.

| Milestone | Points earned / weight |
|---|---:|
{table}

Audited {data['audit_date']}. [Evidence and counting rules](docs/PROGRESS_AUDIT.md) · [Machine-readable rubric](docs/progress.json) · [Website](https://marwanmohamed.ca/researchps5#research-progress)

**Correction:** Probe 45c retracts earlier `fn_addr`/ROP execution and W^X-bypass claims. Those are not credited by this meter; historical diagrams and older findings are not current proof. 13.60 artifacts do not establish 14.10 exploitability.
{END}'''
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    if START in readme:
        before, tail = readme.split(START, 1)
        _, after = tail.split(END, 1)
        readme = before + block + after
    else:
        marker = '## Exploit Chain Overview'
        assert marker in readme
        readme = readme.replace(marker, block + '\n\n' + marker, 1)
    return {ROOT / 'docs/images/research_progress.svg': svg, ROOT / 'README.md': readme}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Fail when generated output is stale')
    args = parser.parse_args()
    stale = []
    for path, content in render().items():
        if args.check:
            if not path.exists() or path.read_text(encoding='utf-8') != content:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(content, encoding='utf-8')
    if stale:
        parser.error('Stale generated output: ' + ', '.join(stale))
    print('Progress artifacts verified' if args.check else 'Progress artifacts generated')


if __name__ == '__main__':
    main()
