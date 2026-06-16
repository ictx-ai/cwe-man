#!/usr/bin/env python3
"""Render the CWE reference as a single syntax-highlighted HTML page.

Reuses cwe_data.ENTRIES, so text never diverges from the man pages. Each
weakness shows ecosystem tabs; selecting one reveals its vulnerable and fixed
code side by side, syntax-highlighted with Pygments.

    python3 generate_html.py        # writes cwe-top25.html
"""
import html as _html
import os
from pygments import highlight
from pygments.lexers import (PythonLexer, JavascriptLexer, CLexer, CppLexer,
                             JavaLexer, PhpLexer, GoLexer, CSharpLexer, TextLexer)
from pygments.formatters import HtmlFormatter

from cwe_data import ENTRIES, DATE
from kev import load_kev, kev_date

KEV = load_kev()
KEV_DATE = kev_date()

OUT = os.path.join(os.path.dirname(__file__), "cwe-top25.html")

LEXERS = {
    "Node.js": JavascriptLexer, "Python": PythonLexer, "Java": JavaLexer,
    "Go": GoLexer, "PHP": lambda: PhpLexer(startinline=True), "C": CLexer,
    "C++": CppLexer, "C#/.NET": CSharpLexer,
}
def lexer_for(eco):
    return LEXERS.get(eco, TextLexer)()

fmt = HtmlFormatter(style="dracula", cssclass="hl")
PYG_CSS = fmt.get_style_defs(".hl")

def hl(eco, code):
    return highlight(code, lexer_for(eco), fmt)

def tabs(cid, examples):
    btns, panels = [], []
    for i, x in enumerate(examples):
        active = " active" if i == 0 else ""
        btns.append(f'<button class="tab{active}" data-card="{cid}" data-i="{i}">'
                    f'{_html.escape(x["eco"])}</button>')
        panels.append(f"""
<div class="ecopanel{active}" id="{cid}-e{i}">
  <section class="panel bad"><h4><span class="dot"></span>Vulnerable</h4>{hl(x['eco'], x['bad'])}</section>
  <section class="panel good"><h4><span class="dot"></span>Fixed</h4>{hl(x['eco'], x['good'])}</section>
</div>""")
    return f'<div class="tabs">{"".join(btns)}</div>{"".join(panels)}'

def card(e):
    cid = e["id"].lower()
    num = e["id"].split("-")[1]
    desc = "".join("<p>%s</p>" % _html.escape(p) for p in e["desc"])
    see = ", ".join(_html.escape(s) for s in e["see"])
    appendix = e["rank"] is None
    rank_badge = "&middot;" if appendix else f"{e['rank']:02d}"
    prev_chip = ("Not in Top 25" if appendix
                 else f"2024: {'NEW' if str(e['prev']).upper()=='NEW' else '#'+str(e['prev'])}")
    cls = "card appendix" if appendix else "card"
    cves = KEV.get(int(num), [])
    kev_chip = (f'<span class="chip kev">{len(cves)} KEV</span>' if cves else "")
    if cves:
        links = "".join(
            f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" '
            f'rel="noopener">{c}</a>' for c in cves)
        kev_block = (f'<details class="kev"><summary>{len(cves)} known '
                     f'exploited CVE{"s" if len(cves) != 1 else ""} '
                     f'(CISA KEV)</summary><div class="cvelist">{links}</div>'
                     f'</details>')
    else:
        kev_block = ('<div class="kev-none">No CISA KEV entries reference '
                     'this weakness.</div>')
    return f"""
<article class="{cls}" id="{cid}">
  <header class="card-head">
    <span class="rank">{rank_badge}</span>
    <div class="titles">
      <h2><a href="https://cwe.mitre.org/data/definitions/{num}.html" target="_blank" rel="noopener">{e['id']}</a>
          <span class="name">{_html.escape(e['name'])}</span></h2>
      <div class="chips">
        <span class="chip cat">{_html.escape(e['category'])}</span>
        <span class="chip prevrank">{prev_chip}</span>
        {kev_chip}
      </div>
    </div>
  </header>
  <div class="desc">{desc}</div>
  {tabs(cid, e['examples'])}
  <div class="fix"><strong>Mitigation.</strong> {_html.escape(e['fix_text'])}</div>
  {kev_block}
  <footer class="see">See also: {see}</footer>
</article>"""

def toc():
    items = []
    for e in ENTRIES:
        appendix = e["rank"] is None
        r = "&middot;" if appendix else f"{e['rank']:02d}"
        items.append(
            f'<a href="#{e["id"].lower()}" class="toc-item">'
            f'<span class="toc-rank">{r}</span>'
            f'<span class="toc-id">{e["id"]}</span>'
            f'<span class="toc-name">{_html.escape(e["name"].split("(")[0].strip())}</span>'
            f'</a>')
    return f'<nav class="toc">{"".join(items)}</nav>'

HTMLDOC = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CWE Top 25 (2025) — Code Reference</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;700;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{{
  --bg:#0d0f14; --bg2:#141821; --ink:#e7e9ee; --mut:#8a93a6; --line:#232a38;
  --accent:#ffb454; --bad:#ff5c6c; --good:#43d17a;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:"Archivo",system-ui,sans-serif;
}}
*{{box-sizing:border-box}}
html{{scroll-behavior:smooth}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.55;-webkit-font-smoothing:antialiased}}
a{{color:inherit}}
.wrap{{max-width:1180px;margin:0 auto;padding:0 22px 80px}}
.mast{{border-bottom:1px solid var(--line);padding:54px 0 30px;margin-bottom:8px;background:radial-gradient(900px 280px at 12% -40%,rgba(255,180,84,.10),transparent)}}
.kicker{{font-family:var(--mono);font-size:12px;letter-spacing:.32em;text-transform:uppercase;color:var(--accent)}}
.mast h1{{font-size:clamp(34px,6vw,68px);font-weight:900;line-height:.98;margin:.18em 0 .25em;letter-spacing:-.02em}}
.mast h1 em{{font-style:normal;color:var(--accent)}}
.mast .sub{{color:var(--mut);max-width:72ch;font-size:15px}}
.mast .meta{{font-family:var(--mono);font-size:12px;color:var(--mut);margin-top:16px;display:flex;gap:18px;flex-wrap:wrap}}
.toc{{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:8px;margin:30px 0 50px}}
.toc-item{{display:flex;align-items:baseline;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:9px;text-decoration:none;background:var(--bg2);transition:.15s}}
.toc-item:hover{{border-color:var(--accent);transform:translateY(-1px)}}
.toc-rank{{font-family:var(--mono);color:var(--accent);font-weight:700;font-size:13px;min-width:18px}}
.toc-id{{font-family:var(--mono);font-size:13px;font-weight:500}}
.toc-name{{color:var(--mut);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.card{{border:1px solid var(--line);border-radius:16px;background:var(--bg2);padding:26px 26px 22px;margin:22px 0;scroll-margin-top:18px}}
.card.appendix{{border-style:dashed;border-color:#3a4252}}
.card-head{{display:flex;gap:18px;align-items:flex-start}}
.rank{{font-family:var(--mono);font-weight:700;font-size:26px;color:var(--bg);background:var(--accent);border-radius:11px;padding:6px 12px;line-height:1;margin-top:3px;flex:none;min-width:46px;text-align:center}}
.appendix .rank{{background:#3a4252;color:var(--ink)}}
.titles h2{{margin:0;font-size:18px;font-weight:700;letter-spacing:-.01em}}
.titles h2 a{{font-family:var(--mono);color:var(--accent);text-decoration:none}}
.titles h2 .name{{color:var(--ink);font-weight:500}}
.chips{{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}}
.chip{{font-family:var(--mono);font-size:11px;color:var(--mut);border:1px solid var(--line);border-radius:999px;padding:3px 10px}}
.desc{{color:#c4cad6;margin:16px 0 6px;max-width:92ch;font-size:14.5px}}
.desc p{{margin:.5em 0}}
.tabs{{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 12px;border-bottom:1px solid var(--line);padding-bottom:10px}}
.tab{{font-family:var(--mono);font-size:12px;color:var(--mut);background:transparent;border:1px solid var(--line);border-radius:8px;padding:5px 12px;cursor:pointer;transition:.12s}}
.tab:hover{{color:var(--ink);border-color:var(--accent)}}
.tab.active{{color:var(--bg);background:var(--accent);border-color:var(--accent);font-weight:700}}
.ecopanel{{display:none;grid-template-columns:1fr 1fr;gap:14px}}
.ecopanel.active{{display:grid}}
.panel{{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:#11141b}}
.panel h4{{margin:0;font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--line)}}
.panel.bad h4{{color:var(--bad);background:rgba(255,92,108,.07)}}
.panel.good h4{{color:var(--good);background:rgba(67,209,122,.07)}}
.panel.bad{{border-color:rgba(255,92,108,.32)}}
.panel.good{{border-color:rgba(67,209,122,.32)}}
.dot{{width:8px;height:8px;border-radius:50%}}
.panel.bad .dot{{background:var(--bad)}}
.panel.good .dot{{background:var(--good)}}
.hl{{margin:0}}
.hl pre{{margin:0;padding:13px 15px;overflow:auto;font-family:var(--mono);font-size:12.5px;line-height:1.55;background:transparent!important}}
.fix{{margin:14px 0 0;padding:13px 16px;border-left:3px solid var(--accent);background:rgba(255,180,84,.06);border-radius:0 10px 10px 0;font-size:14px;color:#d7dbe4}}
.fix strong{{color:var(--accent)}}
.chip.kev{{color:var(--bad);border-color:rgba(255,92,108,.4);background:rgba(255,92,108,.08);font-weight:700}}
details.kev{{margin-top:12px;border:1px solid var(--line);border-radius:10px;background:#11141b}}
details.kev summary{{cursor:pointer;padding:9px 14px;font-family:var(--mono);font-size:12px;color:var(--bad);list-style:none}}
details.kev summary::-webkit-details-marker{{display:none}}
details.kev summary::before{{content:"▸ ";color:var(--mut)}}
details.kev[open] summary::before{{content:"▾ "}}
.cvelist{{display:flex;flex-wrap:wrap;gap:6px;padding:4px 14px 14px}}
.cvelist a{{font-family:var(--mono);font-size:11.5px;color:var(--mut);text-decoration:none;border:1px solid var(--line);border-radius:6px;padding:2px 7px}}
.cvelist a:hover{{color:var(--accent);border-color:var(--accent)}}
.kev-none{{margin-top:12px;font-family:var(--mono);font-size:11.5px;color:var(--mut)}}
.see{{margin-top:14px;font-family:var(--mono);font-size:12px;color:var(--mut)}}
.foot{{margin-top:50px;padding-top:22px;border-top:1px solid var(--line);font-family:var(--mono);font-size:12px;color:var(--mut)}}
.foot a{{color:var(--accent)}}
.totop{{position:fixed;right:18px;bottom:18px;font-family:var(--mono);font-size:12px;background:var(--accent);color:var(--bg);text-decoration:none;padding:9px 13px;border-radius:10px;font-weight:700;box-shadow:0 6px 20px rgba(0,0,0,.4)}}
@media (max-width:760px){{.ecopanel.active{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff;color:#111}}.toc,.totop,.mast .meta{{display:none}}.card,.panel{{break-inside:avoid;border-color:#ccc}}.ecopanel{{display:grid!important}}.tabs{{display:none}}.hl pre{{font-size:9px}}}}
{PYG_CSS}
</style>
</head>
<body>
<div class="wrap">
  <header class="mast">
    <div class="kicker">Secure-coding reference</div>
    <h1>CWE Top 25 <em>2025</em></h1>
    <p class="sub">The 25 most dangerous software weaknesses, each with a vulnerable and fixed
      example in every major ecosystem. Pick an ecosystem tab on any card. Generated from the
      same data as the <code>man</code> pages, so the wording stays in sync.</p>
    <div class="meta">
      <span>Published 2025-12-11 · MITRE / CISA</span>
      <span>Node.js · Python · Java · Go · PHP · C/C++</span>
      <span>Red = avoid · Green = recommended</span>
      <span>CISA KEV{(' · ' + KEV_DATE) if KEV_DATE else ''}</span>
    </div>
  </header>
  {toc()}
  {''.join(card(e) for e in ENTRIES)}
  <footer class="foot">
    Source: <a href="https://cwe.mitre.org/top25/" target="_blank" rel="noopener">cwe.mitre.org/top25</a>.
    Dashed card = appendix / related weakness, not part of the official 25.
    Defensive material — vulnerable snippets are patterns to recognise and avoid.
  </footer>
</div>
<a class="totop" href="#">↑ top</a>
<script>
document.querySelectorAll('.tab').forEach(function(b){{
  b.addEventListener('click', function(){{
    var card = b.dataset.card, i = b.dataset.i;
    document.querySelectorAll('.tab[data-card="'+card+'"]').forEach(function(t){{
      t.classList.toggle('active', t.dataset.i === i);
    }});
    document.querySelectorAll('[id^="'+card+'-e"]').forEach(function(p){{
      p.classList.toggle('active', p.id === card+'-e'+i);
    }});
  }});
}});
</script>
</body>
</html>"""

if __name__ == "__main__":
    with open(OUT, "w") as f:
        f.write(HTMLDOC)
    n = sum(len(e["examples"]) for e in ENTRIES)
    print("Wrote %s (%d weaknesses, %d code pairs)" % (OUT, len(ENTRIES), n))
