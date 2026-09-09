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


def _assert_goal_hunters_serialized(nodes: dict, count: int) -> None:
    """hunter-1 depends on surface-split; hunter-k depends on hunter-(k-1).

    After surface-split completes, only hunter-1 is ready. That is the
    OpenRouter 429 fix (run cmtun51000003l704q7lyyjrf): do not fan out.
    """
    assert nodes["hunter-1"]["depends_on"] == ["surface-split"]
    for index in range(2, count + 1):
        assert nodes[f"hunter-{index}"]["depends_on"] == [f"hunter-{index - 1}"]
    ready_after_split = [
        f"hunter-{index}"
        for index in range(1, count + 1)
        if set(nodes[f"hunter-{index}"]["depends_on"]) <= {"surface-split"}
    ]
    assert ready_after_split == ["hunter-1"]
    for left in range(1, count + 1):
        for right in range(left + 1, count + 1):
            assert f"hunter-{left}" not in set(nodes[f"hunter-{right}"]["depends_on"]) or right == left + 1
            assert not (
                set(nodes[f"hunter-{left}"]["depends_on"]) <= {"surface-split"}
                and set(nodes[f"hunter-{right}"]["depends_on"]) <= {"surface-split"}
            )


def _load(slug: str, env: dict[str, str] | None = None) -> dict:
    merged = os.environ.copy()
    merged.pop("MIDKERNEL_AGENTFLOW_TARGET", None)
    merged.pop("RUN_ID", None)
    merged["MIDKERNEL_NODE_IO"] = "0"
    for name in (
        "KIMI_MAX_TOKENS",
        "OPENROUTER_MAX_TOKENS",
        "MIDKERNEL_OPENROUTER_MAX_TOKENS",
        "KIMI_MODEL_MAX_COMPLETION_TOKENS",
        "KIMI_MODEL_MAX_TOKENS",
        "OPENROUTER_MODEL",
        "MODEL",
        "JUDGE_A_MODEL",
        "JUDGE_B_MODEL",
    ):
        if not env or name not in env:
            merged.pop(name, None)
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
    assert Path(review["executable"]).name == "_node_io.py"
    assert Path(review["executable"]).is_file()
    assert os.access(review["executable"], os.X_OK)
    assert review["env"]["MIDKERNEL_KIMI_BIN"]
    assert review["env"]["BASH_ENV"] == "/dev/null"
    assert review["env"]["MIDKERNEL_NODE_ID"] == "review"
    assert review["env"]["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v1"
    assert review["env"]["KIMI_SHARE_DIR"].endswith(".midkernel/kimi")
    assert review["env"]["KIMI_MAX_TOKENS"] == "16384"
    assert review["env"]["OPENROUTER_MAX_TOKENS"] == "16384"
    assert review["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "16384"
    assert review["env"]["KIMI_MODEL_MAX_COMPLETION_TOKENS"] == "16384"
    assert review["extra_args"][0] == "--config"
    assert review["extra_args"][1].endswith("config.toml")
    assert "\n" not in review["extra_args"][1]
    assert "default_model" not in review["extra_args"][1]
    assert review["agent"] == "kimi"
    assert review["provider"]["name"] == "openrouter"
    assert review["provider"]["base_url"] == "https://openrouter.ai/api/v1"
    assert review["provider"]["api_key_env"] == "OPENROUTER_API_KEY"
    assert review["model"] == "google/gemini-3.8-flash"
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

    assert spec["concurrency"] == 1
    assert nodes["threat-model"]["depends_on"] == ["prepare"]
    assert nodes["goal-author"]["depends_on"] == ["threat-model"]
    assert nodes["surface-split"]["depends_on"] == ["goal-author"]
    _assert_goal_hunters_serialized(nodes, 6)
    for index in range(1, 7):
        hunter = nodes[f"hunter-{index}"]
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
        assert node["env"]["KIMI_MAX_TOKENS"] == "16384"
        assert node["env"]["OPENROUTER_MAX_TOKENS"] == "16384"
        assert node["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "16384"

    for index in range(1, 7):
        hunter = nodes[f"hunter-{index}"]
        assert hunter["env"]["MIDKERNEL_NODE_DYNAMIC"] == "1"
        assert hunter["env"]["MIDKERNEL_NODE_PARENT"] == "surface-split"
        assert hunter["executable"].endswith("node_io.py")
        assert os.access(hunter["executable"], os.X_OK)
        assert hunter["env"]["MIDKERNEL_KIMI_BIN"]
        assert hunter["env"]["BASH_ENV"] == "/dev/null"
        assert hunter["env"]["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v1"
        assert hunter["env"]["KIMI_SHARE_DIR"].endswith(".midkernel/kimi")
        assert hunter["env"]["KIMI_MAX_TOKENS"] == "16384"
        assert hunter["env"]["OPENROUTER_MAX_TOKENS"] == "16384"
        assert hunter["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "16384"
        assert hunter["extra_args"][0] == "--config"
        assert hunter["extra_args"][1].endswith("config.toml")
        assert "\n" not in hunter["extra_args"][1]

    threat = nodes["threat-model"]
    assert threat["env"]["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v1"
    assert threat["env"]["KIMI_SHARE_DIR"].endswith(".midkernel/kimi")
    assert threat["extra_args"][0] == "--config"
    assert threat["extra_args"][1].endswith("config.toml")
    assert "default_model" not in threat["extra_args"][1]

    assert nodes["judge-a"]["model"] == "google/gemini-3.8-flash"
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
    _assert_goal_hunters_serialized(nodes, 2)
    assert spec["concurrency"] == 1
    assert set(nodes["judge-a"]["depends_on"]) == {"hunter-1", "hunter-2"}


def test_goal_security_review_hunters_are_serialized_not_fanned_out() -> None:
    """Parallel hunter-1..6 is the OpenRouter 429 RPM root cause."""
    spec = _load(GOAL_SLUG)
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert spec["concurrency"] == 1
    _assert_goal_hunters_serialized(nodes, 6)
    for index in range(1, 7):
        deps = nodes[f"hunter-{index}"]["depends_on"]
        assert len(deps) == 1
        if index == 1:
            assert deps == ["surface-split"]
        else:
            assert deps == [f"hunter-{index - 1}"]
            assert "surface-split" not in deps


def test_goal_security_review_local_in_task_override() -> None:
    spec = _load(GOAL_SLUG, env={"MIDKERNEL_AGENTFLOW_TARGET": "local"})
    assemble = next(node for node in spec["nodes"] if node["id"] == "assemble")
    assert assemble["target"]["kind"] == "local"
    assert assemble["target"]["cwd"].endswith("/repo")


def test_openrouter_model_env_overrides_balanced_default() -> None:
    """App injects per-profile Pareto Scan presets via OPENROUTER_MODEL / MODEL."""
    spec = _load("security-review", env={"OPENROUTER_MODEL": "moonshotai/kimi-k3"})
    review = next(node for node in spec["nodes"] if node["id"] == "review")
    assert review["model"] == "moonshotai/kimi-k3"
    via_model = _load("security-review", env={"MODEL": "openrouter/anthropic/claude-sonnet-4.5"})
    review = next(node for node in via_model["nodes"] if node["id"] == "review")
    assert review["model"] == "anthropic/claude-sonnet-4.5"


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


def test_goal_security_review_max_tokens_env_override() -> None:
    spec = _load(GOAL_SLUG, env={"KIMI_MAX_TOKENS": "65536"})
    nodes = {node["id"]: node for node in spec["nodes"]}
    for task_id in (
        "threat-model",
        "goal-author",
        "surface-split",
        "hunter-1",
        "judge-a",
        "judge-b",
        "assemble",
    ):
        assert nodes[task_id]["env"]["KIMI_MAX_TOKENS"] == "65536"
        assert nodes[task_id]["env"]["OPENROUTER_MAX_TOKENS"] == "65536"
        assert nodes[task_id]["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "65536"


def test_goal_security_review_rejects_131072_opt_in() -> None:
    spec = _load(GOAL_SLUG, env={"KIMI_MAX_TOKENS": "131072"})
    nodes = {node["id"]: node for node in spec["nodes"]}
    for task_id in ("threat-model", "hunter-1", "assemble"):
        assert nodes[task_id]["env"]["KIMI_MAX_TOKENS"] == "16384"
        assert nodes[task_id]["env"]["OPENROUTER_MAX_TOKENS"] == "16384"
        assert nodes[task_id]["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "16384"


def test_goal_security_review_midkernel_alias_override() -> None:
    spec = _load(GOAL_SLUG, env={"MIDKERNEL_OPENROUTER_MAX_TOKENS": "65536"})
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert nodes["hunter-1"]["env"]["KIMI_MAX_TOKENS"] == "65536"
    assert nodes["hunter-1"]["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "65536"


def test_goal_security_review_env_first_wins_midkernel_over_kimi() -> None:
    spec = _load(
        GOAL_SLUG,
        env={
            "KIMI_MAX_TOKENS": "4096",
            "OPENROUTER_MAX_TOKENS": "8192",
            "MIDKERNEL_OPENROUTER_MAX_TOKENS": "65536",
        },
    )
    nodes = {node["id"]: node for node in spec["nodes"]}
    assert nodes["hunter-1"]["env"]["KIMI_MAX_TOKENS"] == "65536"
    assert nodes["hunter-1"]["env"]["OPENROUTER_MAX_TOKENS"] == "65536"
    assert nodes["hunter-1"]["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "65536"
