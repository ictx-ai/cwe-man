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
import datetime
import os
from cwe_data import ENTRIES as CURATED, DATE, SOURCE, MANUAL
from cwe_examples import EXAMPLES_SINGLE
from kev import load_kev, load_catalog, kev_date

# Date this run was produced; stamped into every page so you can tell at a
# glance when the man pages were last regenerated.
GEN_DATE = datetime.date.today().isoformat()

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
    """Each KEV CVE: catalog exploitation write-up + remediation + URLs.

    CISA does not ship exploit source. Language-level vulnerable/fixed
    pairs stay under EXAMPLES.
    """
    recs = kev.get(cwe_num(e), [])
    L = [".SH KNOWN EXPLOITED VULNERABILITIES"]
    asof = kev_date()
    stamp = (" (as of %s)" % asof) if asof else ""
    if not recs:
        L.append("No entries in the current CISA KEV catalog%s reference "
                 "this weakness." % stamp)
        return L
    n = len(recs)
    L.append("CISA KEV catalog%s: \\fB%d\\fR exploited "
             "%s mapped to this weakness. Each entry has the catalog "
             "write\\-up of how it was used in the wild (not a runnable exploit) "
             "and the required remediation. Code\\-level vulnerable\\->fixed "
             "pairs, when curated, are under \\fBEXAMPLES\\fR."
             % (stamp, n, "CVE" if n == 1 else "CVEs"))
    for r in recs:
        L.append(".SS %s" % esc(r["cveID"]))
        head = " ".join(x for x in (r.get("vendor"), r.get("product")) if x)
        name = r.get("name") or ""
        added = r.get("dateAdded") or ""
        meta = []
        if head:
            meta.append(esc(head))
        if added:
            meta.append("added " + esc(added))
        if r.get("ransomware") and r["ransomware"].lower() not in ("", "unknown"):
            meta.append("ransomware: " + esc(r["ransomware"]))
        if meta:
            L.append(", ".join(meta) + ".")
        if name and name not in head:
            L.append(".PP")
            L.append(esc(name) + ".")
        if r.get("description"):
            L.append(".PP")
            L.append("\\fIHow it is exploited (CISA):\\fR")
            L.append(esc(r["description"]))
        if r.get("action"):
            L.append(".PP")
            L.append("\\fIRemediation:\\fR")
            L.append(esc(r["action"]))
            if r.get("dueDate"):
                L.append(" Due %s." % esc(r["dueDate"]))
        urls = list(r.get("urls") or [])
        nvd = "https://nvd.nist.gov/vuln/detail/" + r["cveID"]
        if nvd not in urls:
            urls.append(nvd)
        L.append(".PP")
        L.append("\\fIReferences:\\fR")
        for u in urls:
            L.append(".br")
            L.append(esc(u))
    return L


def page(e, kev):
    title = e["id"].replace("-", "\\-")
    L = []
    L.append('.\\" Educational secure-coding reference. Generated, not hand-edited.')
    L.append('.TH %s 7 "%s" "%s" "%s"' % (e["id"], GEN_DATE, SOURCE, MANUAL))
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
    L.append(".PP")
    asof = kev_date()
    L.append("Generated %s from %s. CISA KEV data as of %s." % (
        esc(GEN_DATE), esc(SOURCE), esc(asof) if asof else "(unknown)"))
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
    L.append('.TH CWE 7 "%s" "%s" "%s"' % (GEN_DATE, SOURCE, MANUAL))
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
    L.append("OWASP Top 10 overlay: \\fBowasp\\fR(7), \\fBowasp\\-a01\\fR(7) "
             "through \\fBowasp\\-a10\\fR(7).")
    L.append(".PP")
    L.append("https://cwe.mitre.org/top25/ and https://www.cisa.gov/known\\-exploited\\-vulnerabilities\\-catalog")
    L.append(".SH GENERATED")
    asof = kev_date()
    L.append("These pages were generated on \\fB%s\\fR. CISA KEV data as of %s." % (
        esc(GEN_DATE), esc(asof) if asof else "(unknown)"))
    return "\n".join(L) + "\n"


def _have_cwe_page(num):
    return os.path.exists(os.path.join(OUTDIR, "cwe-%d.7" % num))


def owasp_category_page(cat, catalog, kev):
    """Thin OWASP category page: description + CWE map. No extra examples."""
    from owasp_data import PAGE_URL, SOURCE as OSRC
    L = []
    L.append('.\\" OWASP Top 10 overlay. Generated, not hand-edited.')
    L.append('.TH %s 7 "%s" "%s" "%s"' % (cat["man"], GEN_DATE, OSRC, MANUAL))
    L.append(".SH NAME")
    L.append("%s \\- %s (OWASP Top 10:%s %s)"
             % (cat["file"].replace("-", "\\-"), esc(cat["name"]),
                EDITION_OWASP(), cat["id"]))
    L.append(".SH RANK")
    L.append("OWASP Top 10:%s rank \\fB#%d\\fR (%s)."
             % (EDITION_OWASP(), cat["rank"], esc(cat["prev"])))
    L.append(".SH DESCRIPTION")
    for para in cat["desc"]:
        L.append(esc(para))
        L.append(".PP")
    if L[-1] == ".PP":
        L.pop()
    L.append(".PP")
    L.append("This page is an overlay. Vulnerable\\->fixed code lives on the "
             "\\fBcwe\\-*\\fR(7) pages listed below, not here.")
    L.append(".SH MAPPED CWES")
    L.append("Official mapping: \\fB%d\\fR CWEs (OWASP count %s). "
             "\\fBman\\fR after a CWE id if that page exists in this set."
             % (len(cat["cwes"]), cat["n_cwe_official"]))
    L.append(".PP")
    L.append(".TS")
    L.append("l l r lx.")
    L.append("PAGE\tCWE\tKEV\tNAME")
    L.append("_")
    for num in cat["cwes"]:
        meta = catalog.get(num, {})
        name = meta.get("name") or ("CWE-%d" % num)
        nkev = len(kev.get(num, []))
        page_col = "cwe\\-%d(7)" % num if _have_cwe_page(num) else "\\(em"
        L.append("%s\tCWE\\-%d\t%d\tT{\n%s\nT}" % (
            page_col, num, nkev, esc(name)))
    L.append(".TE")
    L.append(".PP")
    L.append("PAGE \\(em means there is no local \\fBcwe\\-*\\fR(7) for that "
             "id (not Top 25 and not in KEV). MITRE still defines it.")
    see = ["\\fBowasp\\fR(7)"]
    see += ["\\fBcwe\\-%d\\fR(7)" % n for n in cat["cwes"] if _have_cwe_page(n)]
    L.append(".SH SEE ALSO")
    L.append(", ".join(see) + ".")
    L.append(".PP")
    L.append(PAGE_URL % cat["slug"])
    L.append(".SH NOTES")
    L.append("OWASP categories group many CWEs. They are not a replacement "
             "for the CWE or KEV pages.")
    L.append(".PP")
    L.append("Generated %s from %s." % (esc(GEN_DATE), esc(OSRC)))
    return "\n".join(L) + "\n"


def EDITION_OWASP():
    from owasp_data import EDITION
    return EDITION


def owasp_index(catalog, kev):
    from owasp_data import CATEGORIES, SOURCE as OSRC, URL, EDITION
    L = []
    L.append("'\\\" t")
    L.append('.TH OWASP 7 "%s" "%s" "%s"' % (GEN_DATE, OSRC, MANUAL))
    L.append(".SH NAME")
    L.append("owasp \\- OWASP Top 10:%s index (CWE overlay)" % EDITION)
    L.append(".SH DESCRIPTION")
    L.append("The OWASP Top 10:%s lists ten web\\-application risk "
             "\\fBcategories\\fR. Each category is a bundle of CWEs, not a "
             "single weakness. These pages map each category onto the "
             "\\fBcwe\\-*\\fR(7) set. They do not duplicate examples."
             % EDITION)
    L.append(".PP")
    L.append("This is not the OWASP API, LLM, or Agentic Top 10.")
    L.append(".SH THE LIST")
    L.append(".TS")
    L.append("l l r lx.")
    L.append("ID\tPAGE\tCWEs\tNAME")
    L.append("_")
    for cat in CATEGORIES:
        L.append("%s\t%s(7)\t%d\tT{\n%s\nT}" % (
            cat["id"], cat["file"].replace("-", "\\-"),
            len(cat["cwes"]), esc(cat["name"])))
    L.append(".TE")
    L.append(".SH SEE ALSO")
    pages = ", ".join(c["file"].replace("-", "\\-") + "(7)" for c in CATEGORIES)
    L.append("\\fBcwe\\fR(7), " + pages + ".")
    L.append(".PP")
    L.append(URL)
    L.append(".SH GENERATED")
    L.append("Generated %s from %s. CWE/KEV pages are a separate MITRE/CISA set."
             % (esc(GEN_DATE), esc(OSRC)))
    return "\n".join(L) + "\n"


def write_owasp(catalog, kev):
    from owasp_data import CATEGORIES
    for fn in os.listdir(OUTDIR):
        if fn.startswith("owasp") and fn.endswith(".7"):
            os.remove(os.path.join(OUTDIR, fn))
    for cat in CATEGORIES:
        path = os.path.join(OUTDIR, cat["file"] + ".7")
        with open(path, "w") as f:
            f.write(owasp_category_page(cat, catalog, kev))
    with open(os.path.join(OUTDIR, "owasp.7"), "w") as f:
        f.write(owasp_index(catalog, kev))
    print("  OWASP overlay: owasp.7 + %d category pages" % len(CATEGORIES))


if __name__ == "__main__":
    import sys
    curated_only = "--curated-only" in sys.argv
    os.makedirs(OUTDIR, exist_ok=True)
    kev = load_kev()
    from owasp_data import CATEGORIES as OWASP_CATS
    owasp_ids = {n for c in OWASP_CATS for n in c["cwes"]}
    needed = sorted(set(kev) | {cwe_num(e) for e in CURATED} | owasp_ids)
    catalog = load_catalog(ids=needed)
    if not catalog and not curated_only:
        sys.exit(
            "ERROR: CWE catalog unavailable (install cwe2: `pip install cwe2`, "
            "or `make deps`).\nRefusing to regenerate, because that would delete "
            "the KEV stub pages and rebuild only the 26 curated ones.\n"
            "Pass --curated-only if you really want just the 26-page set.")
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
    write_owasp(catalog, kev)

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
