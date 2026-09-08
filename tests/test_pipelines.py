"""Load published graphs the same way agentflow does (script stdout → JSON)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIPELINES = ROOT / "pipelines"

EXPECTED = (
    "security-review",
    "solana-validator-security",
    "firedancer-fuzz-triage",
)

pytest.importorskip("agentflow")


def _load(slug: str, env: dict[str, str] | None = None) -> dict:
    merged = os.environ.copy()
    merged.pop("MIDKERNEL_AGENTFLOW_TARGET", None)
    if env:
        merged.update(env)
    result = subprocess.run(
        [sys.executable, str(PIPELINES / f"{slug}.py")],
        cwd=str(PIPELINES),
        capture_output=True,
        text=True,
        env=merged,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def test_security_review_graph_is_kimi_openrouter_on_midkernel_ecs() -> None:
    spec = _load("security-review")
    assert spec["name"] == "security-review"
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert set(nodes) == {"prepare", "review", "publish"}
    assert nodes["review"]["depends_on"] == ["prepare"]
    assert nodes["publish"]["depends_on"] == ["review"]

    review = nodes["review"]
    assert review["agent"] == "kimi"
    assert review["provider"]["name"] == "openrouter"
    assert review["provider"]["base_url"] == "https://openrouter.ai/api/v1"
    assert review["provider"]["api_key_env"] == "OPENROUTER_API_KEY"
    assert review["model"] == "moonshotai/kimi-k3"
    assert review["tools"] == "read_write"

    target = review["target"]
    assert target["kind"] == "ecs"
    assert target["cluster"] == "midkernel-dev"
    assert target["region"] == "us-east-1"
    assert target["subnets"]
    assert target["security_groups"]
    assert target["assign_public_ip"] is True
    assert "midkernel-agentflow-agents" in target["image"]

    assert "report.md" in review["prompt"]
    assert "s3://midkernel-dev-artifacts/runs/" in review["prompt"]
    assert any(c.get("path") == "report.md" for c in review.get("success_criteria", []))


@pytest.mark.parametrize("slug", EXPECTED)
def test_all_scan_graphs_share_contract(slug: str) -> None:
    spec = _load(slug)
    assert spec["name"] == slug
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert nodes["review"]["agent"] == "kimi"
    assert nodes["review"]["target"]["kind"] == "ecs"
    assert nodes["prepare"]["agent"] == "shell"
    assert nodes["publish"]["agent"] == "shell"


def test_local_in_task_override() -> None:
    spec = _load("security-review", env={"MIDKERNEL_AGENTFLOW_TARGET": "local"})
    review = next(node for node in spec["nodes"] if node["id"] == "review")
    assert review["target"]["kind"] == "local"
    assert review["target"]["cwd"].endswith("/repo")
