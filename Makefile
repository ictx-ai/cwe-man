# Build/install the KEV-referenced CWE man pages.
PREFIX  ?= /usr/local
MANDIR  := $(PREFIX)/share/man/man7
PAGES   := $(wildcard man7/*.7)

DATA    := data
KEV_URL := https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
KEV_CSV := $(DATA)/known_exploited_vulnerabilities.csv

.PHONY: all install uninstall preview clean regen html pdf fetch-kev deps

all:
	@echo "Targets: install  uninstall  preview  regen  html  pdf  deps"
	@echo "         fetch-kev (refresh CISA KEV catalog)"
	@echo "Pages:   $(words $(PAGES)) files in man7/"

deps:
	pip install cwe2 pygments --break-system-packages

install:
	@install -d "$(MANDIR)"
	@install -m 0644 $(PAGES) "$(MANDIR)"
	@echo "Installed $(words $(PAGES)) pages to $(MANDIR)"
	@echo "Try: man cwe"

uninstall:
	@for p in $(notdir $(PAGES)); do rm -f "$(MANDIR)/$$p"; done
	@echo "Removed CWE pages from $(MANDIR)"

# Render every page to plain text (sanity check / offline reading).
preview:
	@for p in $(PAGES); do \
		echo "===== $$p ====="; \
		groff -t -man -Tascii "$$p" 2>/dev/null | sed -e 's/.\x08//g'; \
	done

# --- upstream data -------------------------------------------------------
# Always refresh the CISA KEV catalog; keep the cached copy if offline.
# (CWE names/descriptions come from the offline `cwe2` package -- `make deps`.)
fetch-kev:
	@mkdir -p "$(DATA)"
	@echo "Fetching CISA KEV catalog ..."
	@curl -fsSL -o "$(KEV_CSV).tmp" "$(KEV_URL)" \
	  && mv -f "$(KEV_CSV).tmp" "$(KEV_CSV)" \
	  && echo "  -> $(KEV_CSV)" \
	  || echo "  WARN: KEV download failed; using cached $(KEV_CSV) if present."

# Regenerate: pull the latest KEV catalog, then build every KEV CWE page.
# Needs `cwe2` for names/descriptions (run `make deps` once).
regen: fetch-kev
	python3 generate.py

# Graphical outputs -------------------------------------------------------
# Syntax-highlighted, side-by-side HTML reference (needs: pip install pygments)
html:
	python3 generate_html.py

# Typeset PDF of every man page (index first), concatenated into one file.
# Portable: prefers groff -Tpdf, then mandoc, then groff -Tps | ps2pdf.
PDFPAGES := man7/cwe.7 $(filter-out man7/cwe.7,$(sort $(PAGES)))
pdf:
	@rm -f cwe-top25.pdf
	@if groff -t -man -Tpdf man7/cwe.7 >/dev/null 2>&1; then \
	   groff -t -man -Tpdf $(PDFPAGES) > cwe-top25.pdf; \
	 elif command -v mandoc >/dev/null 2>&1; then \
	   mandoc -T pdf $(PDFPAGES) > cwe-top25.pdf; \
	 elif command -v ps2pdf >/dev/null 2>&1; then \
	   groff -t -man -Tps $(PDFPAGES) | ps2pdf - cwe-top25.pdf; \
	 else \
	   echo "Need one of: groff -Tpdf, mandoc, or ps2pdf (ghostscript)."; exit 1; \
	 fi
	@echo "Wrote cwe-top25.pdf"

clean:
	rm -f man7/*.cat cwe-top25.pdf
