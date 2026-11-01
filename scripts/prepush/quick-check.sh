#!/bin/sh
# Only the existing inert registry contract; no graph execution or installation.
set -eu
if [ ! -x .venv/bin/python ]; then
    echo 'pre-push: missing contributor venv; run python3 scripts/setup-dev.py.' >&2
    exit 127
fi
.venv/bin/python -I -c 'import sys; assert sys.version_info >= (3, 11), "Python >=3.11 is required"; import pytest' || {
    echo 'pre-push: missing/incompatible dev dependencies; run python3 scripts/setup-dev.py.' >&2
    exit 1
}
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
exec .venv/bin/python -I -m pytest -q -p no:cacheprovider tests/test_registry.py
