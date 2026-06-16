#!/bin/sh
# Install the CWE Top 25 (2025) man pages on Linux or macOS.
#
# Usage:
#   ./install.sh                 # system-wide (/usr/local), uses sudo if needed
#   ./install.sh ~/.local        # per-user install, no root
#   ./install.sh /opt/homebrew   # e.g. Apple-Silicon Homebrew prefix
#   ./install.sh --uninstall [PREFIX]
#
# Works with GNU man-db (most Linux), mandoc (Alpine/Void), and BSD man (macOS).
set -eu

UNINSTALL=0
if [ "${1:-}" = "--uninstall" ]; then UNINSTALL=1; shift; fi

PREFIX="${1:-/usr/local}"
MANDIR="$PREFIX/share/man/man7"
SRCDIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/man7"

# Use sudo only when we don't already own/can't write the target tree.
SUDO=""
parent="$PREFIX"
[ -d "$parent" ] || parent="$(dirname -- "$parent")"
if [ ! -w "$parent" ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
        echo "Need write access to $PREFIX (run as root or pick a writable PREFIX, e.g. \$HOME/.local)." >&2
        exit 1
    fi
fi

if [ "$UNINSTALL" -eq 1 ]; then
    for f in "$SRCDIR"/*.7; do $SUDO rm -f "$MANDIR/$(basename "$f")"; done
    echo "Removed CWE pages from $MANDIR"
else
    $SUDO mkdir -p "$MANDIR"
    $SUDO cp "$SRCDIR"/*.7 "$MANDIR/"
    $SUDO chmod 0644 "$MANDIR"/cwe*.7
    echo "Installed $(ls "$SRCDIR"/*.7 | wc -l | tr -d ' ') pages to $MANDIR"
fi

# Refresh the man index where a tool exists (harmless / optional for lookup).
if command -v mandb >/dev/null 2>&1; then
    $SUDO mandb -q >/dev/null 2>&1 || true        # GNU man-db (Linux)
elif command -v makewhatis >/dev/null 2>&1; then
    $SUDO makewhatis "$PREFIX/share/man" >/dev/null 2>&1 || true   # mandoc / BSD
fi

if [ "$UNINSTALL" -eq 0 ]; then
    case ":${MANPATH:-}:" in
        *":$PREFIX/share/man:"*) : ;;
        *)
            if ! manpath 2>/dev/null | tr ':' '\n' | grep -qx "$PREFIX/share/man"; then
                echo
                echo "NOTE: $PREFIX/share/man is not on your manpath."
                echo "Add this to ~/.bashrc (Linux) or ~/.zshrc (macOS):"
                echo "  export MANPATH=\"$PREFIX/share/man:\$(manpath)\""
            fi ;;
    esac
    echo
    echo "Try:  man cwe        # index of all 25"
    echo "      man cwe-78     # an individual weakness"
fi
