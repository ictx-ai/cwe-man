#!/usr/bin/env python3
"""Parse the CISA KEV catalog and (optionally) the MITRE CWE list.

Two data sources, both downloaded by the Makefile so the generated pages
stay a function of upstream data (single source of truth):

  data/known_exploited_vulnerabilities.csv  -- CISA KEV catalog
  data/cwe_catalog.csv                       -- MITRE comprehensive CWE list

Both loaders are tolerant: the KEV loader accepts either the full CISA CSV
(11 columns) or the two-column cveID,cwes extract, and every function
degrades to an empty result rather than raising when a file is absent.
"""
import csv
import os
import re

HERE = os.path.dirname(__file__)
KEV_CSV = os.path.join(HERE, "data", "known_exploited_vulnerabilities.csv")
# Catalog candidates, in priority order: MITRE's canonical XML dictionary
# (complete, stable URL) or a per-view CSV export. First one present wins.
CWE_CATALOG_XML = os.path.join(HERE, "data", "cwec_latest.xml")
CWE_CATALOG_CSV = os.path.join(HERE, "data", "cwe_catalog.csv")

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-(\d{4})-(\d+)", re.IGNORECASE)


def _cve_sort_key(cve):
    m = _CVE_RE.search(cve)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def load_kev(path=None):
    """Return {cwe_int: [sorted, de-duplicated CVE IDs]} from the KEV CSV.

    Missing file -> empty dict (so an offline `regen` still works on the
    pages that carry their own examples).
    """
    path = path or KEV_CSV
    by_cwe = {}
    if not os.path.exists(path):
        return by_cwe
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "cwes" not in reader.fieldnames:
            return by_cwe
        for row in reader:
            cve = (row.get("cveID") or "").strip()
            cwes = (row.get("cwes") or "").strip()
            if not cve or not cwes:
                continue
            for part in re.split(r"[,;]\s*", cwes):
                m = _CWE_RE.search(part)
                if m:
                    by_cwe.setdefault(int(m.group(1)), set()).add(cve)
    return {k: sorted(v, key=_cve_sort_key) for k, v in by_cwe.items()}


def kev_date(path=None):
    """Best-effort 'as of' date for the KEV catalog (file mtime, ISO)."""
    import datetime
    path = path or KEV_CSV
    if not os.path.exists(path):
        return None
    ts = os.path.getmtime(path)
    return datetime.date.fromtimestamp(ts).isoformat()


def _load_catalog_csv(path):
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # MITRE column names vary in case; normalise.
        cols = {(c or "").strip().lower(): c for c in (reader.fieldnames or [])}
        id_col = cols.get("cwe-id") or cols.get("cwe id")
        name_col = cols.get("name")
        desc_col = cols.get("description")
        if not id_col or not name_col:
            return out
        for row in reader:
            m = re.search(r"(\d+)", (row.get(id_col) or "").strip())
            if not m:
                continue
            out[int(m.group(1))] = {
                "name": (row.get(name_col) or "").strip(),
                "desc": (row.get(desc_col) or "").strip() if desc_col else "",
            }
    return out


def _local(tag):
    """Strip the XML namespace from a tag name."""
    return tag.rsplit("}", 1)[-1]


def _load_catalog_xml(path):
    """Parse MITRE's cwec_latest.xml (Weakness_Catalog) -> {id: {name, desc}}."""
    import xml.etree.ElementTree as ET
    out = {}
    for _, el in ET.iterparse(path, events=("end",)):
        if _local(el.tag) != "Weakness":
            continue
        raw = el.get("ID")
        if not raw or not raw.isdigit():
            el.clear()
            continue
        name = (el.get("Name") or "").strip()
        desc = ""
        for child in el:
            if _local(child.tag) == "Description":
                # Description may hold xhtml; flatten to text.
                desc = " ".join(t.strip() for t in child.itertext() if t.strip())
                break
        out[int(raw)] = {"name": name, "desc": desc}
        el.clear()
    return out


def _load_catalog_cwe2(ids):
    """Pull names/descriptions from the offline cwe2 package (MITRE data)."""
    try:
        from cwe2.database import Database
    except Exception:
        return {}
    db = Database()
    out = {}
    for cid in ids:
        try:
            w = db.get(cid)
        except Exception:
            continue
        name = getattr(w, "name", "") or ""
        desc = getattr(w, "description", "") or ""
        ext = getattr(w, "extended_description", "") or ""
        name = name.strip() if isinstance(name, str) else ""
        desc = desc.strip() if isinstance(desc, str) else ""
        ext = ext.strip() if isinstance(ext, str) else ""
        if ext:
            desc = (desc + " " + ext).strip()
        if name:
            out[cid] = {"name": name, "desc": desc}
    return out


def load_catalog(path=None, ids=None):
    """Return {cwe_int: {'name', 'desc'}} for the MITRE CWE dictionary.

    Source order: the offline cwe2 package (preferred, no network) for the
    requested ids, then a local XML dictionary, then a CSV export. Missing
    all of them -> empty dict (curated pages only).
    """
    if ids:
        cat = _load_catalog_cwe2(ids)
        if cat:
            return cat
    candidates = [path] if path else [CWE_CATALOG_XML, CWE_CATALOG_CSV]
    for cand in candidates:
        if cand and os.path.exists(cand):
            try:
                if cand.endswith(".xml"):
                    return _load_catalog_xml(cand)
                return _load_catalog_csv(cand)
            except Exception as exc:  # malformed download shouldn't break regen
                print("WARNING: could not parse %s (%s)" % (cand, exc))
    return {}


if __name__ == "__main__":
    kev = load_kev()
    cat = load_catalog()
    print("KEV CWEs:", len(kev), "| total CVE links:",
          sum(len(v) for v in kev.values()))
    print("MITRE catalog entries:", len(cat))
    if kev:
        top = sorted(kev.items(), key=lambda kv: -len(kv[1]))[:5]
        for cid, cves in top:
            print("  CWE-%d: %d CVEs" % (cid, len(cves)))
