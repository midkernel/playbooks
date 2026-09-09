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

GOAL_SLUG = "goal-security-review"
GOAL_NODES = (
    "prepare",
    "threat-model",
    "goal-author",
    "surface-split",
    "hunter-1",
    "hunter-2",
    "hunter-3",
    "hunter-4",
    "hunter-5",
    "hunter-6",
    "judge-a",
    "judge-b",
    "assemble",
    "publish",
)

pytest.importorskip("agentflow")


def _load(slug: str, env: dict[str, str] | None = None) -> dict:
    merged = os.environ.copy()
    merged.pop("MIDKERNEL_AGENTFLOW_TARGET", None)
    merged.pop("RUN_ID", None)
    merged["MIDKERNEL_NODE_IO"] = "0"
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
    assert review["executable"].endswith("node_io.py")
    assert review["env"]["MIDKERNEL_NODE_ID"] == "review"
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


@pytest.mark.parametrize(
    ("slug", "repo", "ref"),
    [
        (
            "solana-validator-security",
            "midkernel/bounty-target-jito-solana",
            "master",
        ),
        (
            "firedancer-fuzz-triage",
            "midkernel/bounty-target-jito-firebam",
            "main",
        ),
    ],
)
def test_bounty_playbooks_pin_private_default_targets(
    slug: str, repo: str, ref: str
) -> None:
    spec = _load(slug)
    nodes = {node["id"]: node for node in spec["nodes"]}
    prepare = nodes["prepare"]["prompt"]
    prompt = nodes["review"]["prompt"]
    owner, name = repo.split("/", 1)
    assert f"GITHUB_NAME=\"${{GITHUB_NAME:-{name}}}\"" in prepare
    assert f"GITHUB_REF=\"${{GITHUB_REF:-{ref}}}\"" in prepare
    assert repo in prompt
    assert f"`{ref}`" in prompt
    assert spec["description"]
    assert name in spec["description"]


def test_goal_security_review_graph_nodes_and_openrouter_lock() -> None:
    spec = _load(GOAL_SLUG)
    assert spec["name"] == GOAL_SLUG
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert tuple(nodes) == GOAL_NODES or set(nodes) == set(GOAL_NODES)
    assert set(nodes) == set(GOAL_NODES)

    assert nodes["threat-model"]["depends_on"] == ["prepare"]
    assert nodes["goal-author"]["depends_on"] == ["threat-model"]
    assert nodes["surface-split"]["depends_on"] == ["goal-author"]
    for index in range(1, 7):
        hunter = nodes[f"hunter-{index}"]
        assert hunter["depends_on"] == ["surface-split"]
        assert hunter["agent"] == "kimi"
        assert hunter["provider"]["name"] == "openrouter"
        assert f"goals/{index:02d}-" in hunter["prompt"]
        assert "no-op" in hunter["prompt"].lower()
        assert "known-findings" in hunter["prompt"] or "known-issues" in hunter["prompt"]
        assert any(
            c.get("path") == f"findings/hunter-{index}/RESULT.md"
            for c in hunter.get("success_criteria", [])
        )

    assert set(nodes["judge-a"]["depends_on"]) == {f"hunter-{i}" for i in range(1, 7)}
    assert nodes["judge-b"]["depends_on"] == ["judge-a"]
    assert nodes["assemble"]["depends_on"] == ["judge-b"]
    assert nodes["publish"]["depends_on"] == ["assemble"]

    for task_id in (
        "threat-model",
        "goal-author",
        "surface-split",
        "judge-a",
        "judge-b",
        "assemble",
    ):
        node = nodes[task_id]
        assert node["agent"] == "kimi"
        assert node["provider"]["name"] == "openrouter"
        assert node["provider"]["base_url"] == "https://openrouter.ai/api/v1"
        assert node["provider"]["api_key_env"] == "OPENROUTER_API_KEY"
        assert node["tools"] == "read_write"
        assert node["target"]["kind"] == "ecs"
        assert node["target"]["cluster"] == "midkernel-dev"

    for index in range(1, 7):
        hunter = nodes[f"hunter-{index}"]
        assert hunter["env"]["MIDKERNEL_NODE_DYNAMIC"] == "1"
        assert hunter["env"]["MIDKERNEL_NODE_PARENT"] == "surface-split"
        assert hunter["executable"].endswith("node_io.py")

    assert nodes["judge-a"]["model"] == "moonshotai/kimi-k3"
    assert nodes["judge-b"]["model"] != nodes["judge-a"]["model"]
    assert nodes["judge-b"]["model"] == "anthropic/claude-sonnet-4.5"

    assert "THREAT_MODEL.md" in nodes["threat-model"]["prompt"]
    assert "GOAL_COUNT" in nodes["goal-author"]["prompt"]
    assert "Do not prescribe" in nodes["threat-model"]["prompt"]
    assert "validated-b" in nodes["assemble"]["prompt"]
    assert "Never invent" in nodes["assemble"]["prompt"] or "never invent" in nodes["assemble"]["prompt"]
    assert any(c.get("path") == "report.md" for c in nodes["assemble"].get("success_criteria", []))

    prepare = nodes["prepare"]
    publish = nodes["publish"]
    assert prepare["agent"] == "shell"
    assert publish["agent"] == "shell"
    assert "refusing to upload a stub" in publish["prompt"]
    assert "stub report" in publish["prompt"]


def test_goal_security_review_hunters_follow_goal_count() -> None:
    spec = _load(GOAL_SLUG, env={"GOAL_COUNT": "2"})
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert set(nodes) == {
        "prepare",
        "threat-model",
        "goal-author",
        "surface-split",
        "hunter-1",
        "hunter-2",
        "judge-a",
        "judge-b",
        "assemble",
        "publish",
    }
    assert nodes["hunter-1"]["depends_on"] == ["surface-split"]
    assert nodes["hunter-2"]["depends_on"] == ["surface-split"]
    assert set(nodes["judge-a"]["depends_on"]) == {"hunter-1", "hunter-2"}


def test_goal_security_review_local_in_task_override() -> None:
    spec = _load(GOAL_SLUG, env={"MIDKERNEL_AGENTFLOW_TARGET": "local"})
    assemble = next(node for node in spec["nodes"] if node["id"] == "assemble")
    assert assemble["target"]["kind"] == "local"
    assert assemble["target"]["cwd"].endswith("/repo")


def test_goal_security_review_judge_models_follow_env() -> None:
    spec = _load(
        GOAL_SLUG,
        env={
            "JUDGE_A_MODEL": "openrouter/openai/gpt-4o",
            "JUDGE_B_MODEL": "google/gemini-2.5-pro",
        },
    )
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert nodes["judge-a"]["model"] == "openai/gpt-4o"
    assert nodes["judge-b"]["model"] == "google/gemini-2.5-pro"
