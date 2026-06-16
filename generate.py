#!/usr/bin/env python3
"""Generate troff (man section 7) pages for KEV-referenced CWEs.

Two tiers of page, one generator:

  * Curated pages come from cwe_data.py: full description, mitigation and a
    vulnerable -> fixed code example per ecosystem (Node.js, Python, Java,
    Go, PHP; C/C++ for the memory-safety classes).
  * Stub pages are generated for every other CWE that appears in the CISA
    KEV catalog, using the name and description from MITRE's comprehensive
    CWE list (data/cwe_catalog.csv, fetched by `make fetch-cwe`).

Every page -- curated or stub -- carries a KNOWN EXPLOITED VULNERABILITIES
section listing the CVEs that CISA maps to that weakness, so you can see at
a glance which KEVs belong to a CWE. Data lives in cwe_data.py and the two
upstream CSVs, so the man pages, HTML and PDF never diverge.
"""
import os
from cwe_data import ENTRIES as CURATED, DATE, SOURCE, MANUAL
from cwe_examples import EXAMPLES_SINGLE
from kev import load_kev, load_catalog, kev_date

OUTDIR = os.path.join(os.path.dirname(__file__), "man7")


def esc(text):
    """Escape a plain-text string for roff (outside code blocks)."""
    return text.replace("\\", "\\e").replace("-", "\\-")


def code_block(code):
    """Render a code string inside an .EX/.EE example block, guarded."""
    out = [".EX"]
    for line in code.split("\n"):
        line = line.replace("\\", "\\\\")          # literal backslash
        if line[:1] in (".", "'"):                 # protect roff control lines
            line = "\\&" + line
        out.append(line)
    out.append(".EE")
    return "\n".join(out)


def cwe_num(e):
    return int(e["id"].split("-")[1])


def rank_str(e):
    if e.get("stub"):
        return ("KEV\\-referenced weakness. Not part of the 2025 CWE Top 25; "
                "documented here because it appears in the CISA KEV catalog.")
    if e["rank"] is None:
        return "Appendix \\- not part of the 2025 CWE Top 25."
    return "2025 CWE Top 25 rank: \\fB#%d\\fR (2024 rank: %s)." % (
        e["rank"], esc(str(e["prev"])))


def kev_section(e, kev):
    """The KNOWN EXPLOITED VULNERABILITIES section for one CWE."""
    cves = kev.get(cwe_num(e), [])
    L = [".SH KNOWN EXPLOITED VULNERABILITIES"]
    asof = kev_date()
    stamp = (" (as of %s)" % asof) if asof else ""
    if not cves:
        L.append("No entries in the current CISA KEV catalog%s reference "
                 "this weakness." % stamp)
        return L
    L.append("CISA KEV catalog%s: \\fB%d\\fR exploited "
             "%s mapped to this weakness."
             % (stamp, len(cves), "CVE" if len(cves) == 1 else "CVEs"))
    L.append(".PP")
    # One filled paragraph; groff wraps the comma-separated list.
    L.append(", ".join(esc(c) for c in cves) + ".")
    return L


def page(e, kev):
    title = e["id"].replace("-", "\\-")
    L = []
    L.append('.\\" Educational secure-coding reference. Generated, not hand-edited.')
    L.append('.TH %s 7 "%s" "%s" "%s"' % (e["id"], DATE, SOURCE, MANUAL))
    L.append(".SH NAME")
    L.append("%s \\- %s" % (title, esc(e["name"])))
    L.append(".SH RANK")
    L.append(rank_str(e))
    L.append(".SH CLASSIFICATION")
    L.append("Class: %s." % esc(e["category"]))
    L.append(".SH DESCRIPTION")
    for para in e["desc"]:
        L.append(esc(para))
        L.append(".PP")
    if L[-1] == ".PP":
        L.pop()
    if e.get("fix_text"):
        L.append(".SH MITIGATION")
        L.append(esc(e["fix_text"]))
    # KEV section sits high so `man cwe-78` shows real-world CVEs early.
    L += kev_section(e, kev)
    if e["examples"]:
        L.append(".SH EXAMPLES")
        ecos = ", ".join(x["eco"] for x in e["examples"])
        L.append("One vulnerable\\->fixed pair per ecosystem (%s)." % esc(ecos))
        for x in e["examples"]:
            L.append('.SS %s' % esc(x["eco"]))
            L.append("\\fIVulnerable:\\fR")
            L.append(".RS")
            L.append(code_block(x["bad"]))
            L.append(".RE")
            L.append("\\fIFixed:\\fR")
            L.append(".RS")
            L.append(code_block(x["good"]))
            L.append(".RE")
    elif e.get("stub"):
        L.append(".SH EXAMPLES")
        L.append("No per\\-language examples yet for this weakness. See the "
                 "authoritative MITRE definition below, or contribute a "
                 "vulnerable\\->fixed pair to \\fBcwe_data.py\\fR.")
    L.append(".SH SEE ALSO")
    see = list(e.get("see") or [])
    line = "\\fBcwe\\fR(7) (index)"
    if see:
        line += ", " + esc(", ".join(see))
    L.append(line + ".")
    L.append(".PP")
    L.append("Authoritative definition: https://cwe.mitre.org/data/definitions/%s.html"
             % e["id"].split("-")[1])
    L.append(".SH NOTES")
    L.append("Defensive reference material. Each vulnerable snippet shows a pattern "
             "to recognize and avoid; the fixed snippet shows the recommended approach.")
    return "\n".join(L) + "\n"


def make_stub(num, catalog):
    """Build a stub entry dict for a KEV CWE that isn't curated."""
    meta = catalog.get(num, {})
    name = meta.get("name") or "CWE-%d" % num
    desc = meta.get("desc") or (
        "This weakness appears in the CISA KEV catalog. A full description "
        "and mitigation are not yet curated here; see the MITRE definition.")
    ex = EXAMPLES_SINGLE.get(num)
    return {
        "id": "CWE-%d" % num,
        "name": name,
        "category": "KEV-referenced weakness",
        "rank": None,
        "prev": None,
        "desc": [desc],
        "fix_text": "",
        "see": [],
        "examples": [ex] if ex else [],
        "stub": True,
    }


def build_entries(kev, catalog):
    """Curated entries (with examples) + stub entries for the rest of KEV.

    Stubs are only emitted when the MITRE catalog is present, so an offline
    `regen` produces the curated pages (each with its KEV section) rather
    than a pile of 'CWE-N' placeholders. Run `make fetch-cwe` to expand to
    the full KEV set with real names and descriptions.
    """
    entries = [dict(e, stub=False) for e in CURATED]
    if not catalog:
        return entries
    have = {cwe_num(e) for e in entries}
    for num in sorted(kev):
        if num not in have:
            entries.append(make_stub(num, catalog))
    return entries


def index_page(entries, kev):
    # Order: Top-25 by rank, then appendix, then KEV stubs by number.
    ranked = sorted((e for e in entries if e["rank"] is not None),
                    key=lambda e: e["rank"])
    appendix = [e for e in entries if e["rank"] is None and not e.get("stub")]
    stubs = sorted((e for e in entries if e.get("stub")), key=cwe_num)
    ordered = ranked + appendix + stubs

    n_curated = sum(1 for e in entries if not e.get("stub"))
    n_kev = len(kev)
    L = []
    L.append("'\\\" t")   # preprocessor hint: this page must be run through tbl
    L.append('.TH CWE 7 "%s" "%s" "%s"' % (DATE, SOURCE, MANUAL))
    L.append(".SH NAME")
    L.append("cwe \\- index of KEV\\-referenced Common Weakness Enumerations")
    L.append(".SH DESCRIPTION")
    L.append("This manual set documents the 2025 CWE Top 25 (published by "
             "MITRE/CISA on December 11, 2025) together with every other CWE "
             "that appears in the CISA Known Exploited Vulnerabilities (KEV) "
             "catalog. %d weaknesses are documented in total." % len(entries))
    L.append(".PP")
    L.append("%d pages are hand\\-curated with a description, mitigation and a "
             "vulnerable\\->fixed code example per ecosystem (Node.js, Python, "
             "Java, Go, PHP; C/C++ for the memory\\-safety classes). The "
             "remainder are KEV stubs: MITRE name and description plus the list "
             "of exploited CVEs, pending curated examples." % n_curated)
    L.append(".PP")
    L.append("Every page has a \\fBKNOWN EXPLOITED VULNERABILITIES\\fR section "
             "listing the CVEs CISA maps to that weakness. To read one, run "
             "\\fBman\\fR with its identifier, e.g. \\fBman cwe\\-78\\fR. The "
             "KEV column below is the count of exploited CVEs.")
    L.append(".SH THE LIST")
    L.append(".TS")
    L.append("l l r lx.")
    L.append("RANK\tCWE\tKEV\tNAME")
    L.append("_")
    for e in ordered:
        rank = str(e["rank"]) if e["rank"] is not None else "\\(em"
        count = len(kev.get(cwe_num(e), []))
        L.append("%s\t%s\t%d\tT{\n%s\nT}" % (
            rank, e["id"].replace("-", "\\-"), count, esc(e["name"])))
    L.append(".TE")
    L.append(".PP")
    L.append("Rank \\(em marks weaknesses outside the official Top 25 "
             "(appendix or KEV\\-only).")
    L.append(".SH SEE ALSO")
    pages = ", ".join(e["id"].lower().replace("-", "\\-") + "(7)" for e in ordered)
    L.append(pages + ".")
    L.append(".PP")
    L.append("https://cwe.mitre.org/top25/ and https://www.cisa.gov/known\\-exploited\\-vulnerabilities\\-catalog")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    os.makedirs(OUTDIR, exist_ok=True)
    kev = load_kev()
    needed = sorted(set(kev) | {cwe_num(e) for e in CURATED})
    catalog = load_catalog(ids=needed)
    entries = build_entries(kev, catalog)

    # Refresh: drop stale generated pages so removed CWEs don't linger.
    for fn in os.listdir(OUTDIR):
        if fn.startswith("cwe-") and fn.endswith(".7"):
            os.remove(os.path.join(OUTDIR, fn))
    old = os.path.join(OUTDIR, "cwe-top25.7")
    if os.path.exists(old):
        os.remove(old)

    for e in entries:
        fn = os.path.join(OUTDIR, e["id"].lower() + ".7")
        with open(fn, "w") as f:
            f.write(page(e, kev))
    with open(os.path.join(OUTDIR, "cwe.7"), "w") as f:
        f.write(index_page(entries, kev))

    n_curated = sum(1 for e in entries if not e.get("stub"))
    n_stub = sum(1 for e in entries if e.get("stub"))
    n_with_ex = sum(1 for e in entries if e["examples"])
    n_ex = sum(len(e["examples"]) for e in entries)
    n_cve = sum(len(v) for v in kev.values())
    print("Generated %d pages + index in %s" % (len(entries), OUTDIR))
    print("  curated: %d (%d code pairs)  |  KEV stubs: %d"
          % (n_curated, n_ex, n_stub))
    print("  pages with >=1 code example: %d / %d" % (n_with_ex, len(entries)))
    print("  KEV catalog: %d CWEs, %d CVE references" % (len(kev), n_cve))
    if not catalog:
        print("  NOTE: no CWE catalog (install cwe2: pip install cwe2) -> "
              "curated pages only.")
