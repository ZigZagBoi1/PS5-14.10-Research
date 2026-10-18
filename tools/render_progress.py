"""Render an explicitly reviewed evidence rubric. Never infers exploit success."""
import argparse
import hashlib
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = '<!-- RESEARCH_PROGRESS:START -->'
END = '<!-- RESEARCH_PROGRESS:END -->'


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
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="720" height="112" viewBox="0 0 720 112" role="img" aria-labelledby="title desc">
<title id="title">14.10 milestone estimate: {score} of 100</title>
<desc id="desc">Subjective evidence rubric. Not time remaining or odds of success. Kernel read/write is not demonstrated.</desc>
<rect width="720" height="112" rx="8" fill="#f5f5f7"/>
<text x="22" y="30" font-family="sans-serif" font-size="16" fill="#242b36">14.10 evidence-weighted milestones</text>
<text x="698" y="30" text-anchor="end" font-family="sans-serif" font-size="16" font-weight="bold" fill="#194e9a">{score}/100</text>
<rect x="22" y="46" width="676" height="12" rx="3" fill="#dde3ec"/>
<rect x="22" y="46" width="{676 * score / 100:g}" height="12" rx="3" fill="#254d86"/>
<text x="22" y="84" font-family="sans-serif" font-size="12" fill="#545e6d">Judgment-based estimate · Kernel R/W not demonstrated · Audited {html.escape(data['audit_date'])}</text>
</svg>\n'''
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
