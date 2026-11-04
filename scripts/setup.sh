#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links dist any2ipa==1.0.0
.venv/bin/any2ipa doctor
printf '%s\n' 'Ready. Run .venv/bin/any2ipa --help'
