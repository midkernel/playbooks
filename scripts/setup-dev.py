#!/usr/bin/env python3
"""Explicit contributor setup; never invoked by CI or package installation."""
from pathlib import Path
import os
import subprocess
import sys


def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Contributor setup requires Python >=3.11")
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    venv = root / ".venv"
    if venv.is_symlink() or (venv.exists() and not venv.is_dir()):
        raise SystemExit("Preserve existing .venv path; prepare a regular contributor venv")
    if not venv.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / "bin" / "python"
    if not python.is_file():
        raise SystemExit("Existing .venv has no Python; repair it explicitly, then retry")
    subprocess.run([str(python), "-c", "import sys; assert sys.version_info >= (3, 11)"], check=True)
    subprocess.run([str(python), "-m", "pip", "install", "-e", ".[dev]"], check=True)
    subprocess.run([str(python), "-I", "scripts/prepush/install.py"], check=True)


if __name__ == "__main__":
    main()
