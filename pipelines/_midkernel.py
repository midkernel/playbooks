"""Shared Midkernel agentflow helpers.

Used by ``pipelines/*.py``. This file is not a pipeline (no Graph, no JSON
on stdout). ``list_playbooks`` does not walk ``pipelines/``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
