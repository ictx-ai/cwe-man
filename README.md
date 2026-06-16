# CWE Top 25 (2025) — Man Pages

Unix man pages (section 7) documenting the **2025 CWE Top 25 Most Dangerous
Software Weaknesses** (published by MITRE/CISA on 2025-12-11 from analysis of
39,080 CVE records), plus every other CWE that appears in CISA's **Known
Exploited Vulnerabilities (KEV)** catalog.

Each weakness has its own page containing:

- its 2025 rank (and 2024 rank for comparison),
- a plain-language description of the weakness,
- the mitigation,
- a **vulnerable** and **fixed** code example *for each ecosystem* — Node.js,
  Python, Java, Go and PHP for the web/logic classes; C and C++ for the
  memory-safety classes (managed runtimes largely prevent those), and
- a **KNOWN EXPLOITED VULNERABILITIES** section listing every CVE that CISA
  maps to that weakness, so you can see at a glance which KEVs belong to a CWE.

Two tiers of page. The 26 Top-25 (plus appendix) pages are **hand-curated**
with full descriptions and per-ecosystem examples. The remaining KEV CWEs are
**stubs**: MITRE name and description plus the CVE list, generated on demand
from MITRE's dictionary (see *Updating the data* below). The index page,
`cwe(7)`, lists every entry with its KEV count and cross-references; the
appendix entry (`cwe-470`, Unsafe Reflection) is *not* part of the official
Top 25 but is included as a closely related weakness.

These are defensive secure-coding references: each "vulnerable" snippet is a
pattern to recognize and avoid, paired with the recommended fix — the same
teaching style used by MITRE's own demonstrative examples and the OWASP cheat
sheets.

Install straight from the repo on any machine:

```sh
git clone https://github.com/ictx-ai/cwe-man.git
cd cwe-man
./install.sh            # system-wide; or ./install.sh ~/.local for no-root
man cwe
```

## Installing (Linux + macOS)

`/usr/local/share/man` is on the default manpath on virtually every Linux
distribution and on macOS, so a single approach covers both. The pages are
section 7, so they are found as `man cwe`, `man cwe-78`, etc.

System-wide (one command, uses `sudo` only if the target isn't writable):

```sh
./install.sh                 # -> /usr/local/share/man/man7
man cwe
```

Per-user, no root:

```sh
./install.sh ~/.local        # -> ~/.local/share/man/man7
# if prompted, add to ~/.zshrc (macOS) or ~/.bashrc (Linux):
export MANPATH="$HOME/.local/share/man:$(manpath)"
```

Apple-Silicon Homebrew users may prefer their own prefix:

```sh
./install.sh /opt/homebrew
```

Uninstall: `./install.sh --uninstall [PREFIX]`.

The script refreshes the man index automatically where a tool exists
(`mandb` on GNU/Linux, `makewhatis` on mandoc/BSD/macOS); neither is required
for `man cwe` to resolve.

If you prefer `make`: `sudo make install` / `make install PREFIX="$HOME/.local"`
/ `make uninstall` do the same thing.

## Viewing without installing (Linux + macOS)

Both GNU man-db and BSD/macOS `man` treat an argument containing a slash as a
file path, so this is portable (the bare `-l` flag is GNU-only):

```sh
man ./man7/cwe.7             # the index of all 25
man ./man7/cwe-78.7          # an individual weakness

# or render directly with groff/mandoc:
groff -t -man -Tascii man7/cwe-89.7 | less     # tables need -t (index page)
mandoc man7/cwe-89.7 | less                     # mandoc (macOS/Alpine)
```

## Showing the code graphically

The man pages are terminal text, but the same content is available in richer
visual forms:

**Syntax-highlighted HTML (recommended).** A single self-contained page,
`cwe-top25.html`, shows every weakness with its description and the vulnerable
and fixed code **side by side, syntax-coloured**, plus a clickable index. It is
generated from the same data as the man pages:

```sh
pip install pygments        # one-time
make html                   # writes cwe-top25.html
open cwe-top25.html         # macOS  (Linux: xdg-open)
```

**Typeset PDF.** Render all 25 pages into one PDF (code shown in a proper
monospace block). The target auto-selects whatever you have installed
(`groff -Tpdf`, `mandoc`, or `groff -Tps | ps2pdf`):

```sh
make pdf                    # writes cwe-top25.pdf
```

**Colour in the terminal.** The plain `man` view can be colourised with a
syntax-aware pager such as `bat`, or with `most`, or by exporting
`LESS_TERMCAP_*` variables for `less`.

**One-off HTML/PDF for a single page:**

```sh
mandoc -T html man7/cwe-89.7 > cwe-89.html      # HTML (code in <pre>)
mandoc -T pdf  man7/cwe-89.7 > cwe-89.pdf       # PDF, no Ghostscript needed
groff -t -man -Tpdf man7/cwe-89.7 > cwe-89.pdf  # PDF via groff (full install)
```

## Regenerating

Outputs are a function of one curated module plus the CISA KEV catalog, with
CWE names/descriptions supplied offline by the `cwe2` package:

| Source | What it provides |
|--------|------------------|
| `cwe_data.py` | Curated descriptions, mitigations, multi-ecosystem examples (Top 25) |
| `cwe_examples.py` | One vulnerable→fixed example for additional KEV CWEs |
| `data/known_exploited_vulnerabilities.csv` | CISA KEV catalog (CVE → CWE map) |
| `cwe2` (pip) | MITRE name + description for every CWE (offline) |

```sh
make deps                    # one-time: pip install cwe2 pygments
make regen                   # pull latest KEV catalog, rebuild every KEV CWE page
python3 generate_html.py     # rewrites cwe-top25.html
make pdf                     # rewrites cwe-top25.pdf
```

`make regen` re-downloads the CISA KEV catalog **every time** and then runs
`generate.py`, which emits a section-7 page for **every CWE in the KEV catalog**
(~181) plus the curated appendix. Each page carries, in order: description,
mitigation, the **KNOWN EXPLOITED VULNERABILITIES** list (every CVE CISA maps to
the CWE), then the code example(s). The KEV download degrades gracefully: if the
network is down, it warns and reuses the cached `data/` copy (a never-clobbered
`.tmp` staging file means a failed fetch never corrupts the good one).

## Coverage of code examples

Examples come in two forms. The 26 curated Top-25 pages carry a vulnerable→fixed
pair in **every** ecosystem (Node.js, Python, Java, Go, PHP; C/C++ for memory
classes). Additional high-impact KEV CWEs carry **one** example in the language
that best illustrates them — Java, Node.js or Python, or C for memory-safety
weaknesses — defined in `cwe_examples.py`. The remaining long-tail KEV CWEs ship
as full pages (MITRE description + KEV CVE list) with examples added over time.

To add an example, drop an entry into `cwe_examples.py` keyed by CWE number; to
promote a CWE to a full multi-language curated page, add it to `cwe_data.py`
(the curated version always wins over a single-example or stub).

## The list

| Rank | CWE | Name |
|----:|-----|------|
| 1 | CWE-79 | Cross-site Scripting (XSS) |
| 2 | CWE-89 | SQL Injection |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) |
| 4 | CWE-862 | Missing Authorization |
| 5 | CWE-787 | Out-of-bounds Write |
| 6 | CWE-22 | Path Traversal |
| 7 | CWE-416 | Use After Free |
| 8 | CWE-125 | Out-of-bounds Read |
| 9 | CWE-78 | OS Command Injection |
| 10 | CWE-94 | Code Injection |
| 11 | CWE-120 | Classic Buffer Overflow |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type |
| 13 | CWE-476 | NULL Pointer Dereference |
| 14 | CWE-121 | Stack-based Buffer Overflow |
| 15 | CWE-502 | Deserialization of Untrusted Data |
| 16 | CWE-122 | Heap-based Buffer Overflow |
| 17 | CWE-863 | Incorrect Authorization |
| 18 | CWE-20 | Improper Input Validation |
| 19 | CWE-284 | Improper Access Control |
| 20 | CWE-200 | Exposure of Sensitive Information |
| 21 | CWE-306 | Missing Authentication for Critical Function |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) |
| 23 | CWE-77 | Command Injection |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR) |
| 25 | CWE-770 | Allocation of Resources Without Limits or Throttling |
| — | CWE-470 | Unsafe Reflection *(appendix — not in the official Top 25)* |

Source: <https://cwe.mitre.org/top25/> and CISA's 2025 announcement.
