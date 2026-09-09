from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipelines import _midkernel as mk


def test_playbook_prompt_strips_frontmatter() -> None:
    prompt = mk.playbook_prompt("security-review")
    assert "Perform a /security-review" in prompt
    assert not prompt.startswith("---")
    assert "slug:" not in prompt


def test_ecs_target_is_explicit_midkernel_dev() -> None:
    target = mk.midkernel_ecs_target(profile="balanced")
    assert target["kind"] == "ecs"
    assert target["region"] == "us-east-1"
    assert target["cluster"] == "midkernel-dev"
    assert target["subnets"] == [
        "subnet-0f93686b81d5d8d7d",
        "subnet-08ae98ea51ce9ccd7",
    ]
    assert target["security_groups"] == ["sg-015a103caabc861d0"]
    assert target["assign_public_ip"] is True
    assert target["image"].endswith("/midkernel-agentflow-agents:latest")
    assert target["cpu"] == "2048"
    assert target["memory"] == "4096"
    assert target["install_agents"] == ["kimi"]


def test_openrouter_model_strips_provider_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_MODEL", "openrouter/moonshotai/kimi-k3")
    assert mk.openrouter_model() == "moonshotai/kimi-k3"


def test_env_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PLAYBOOK", raising=False)
    monkeypatch.setenv("PLAYBOOK_SLUG", "solana-validator-security")
    assert mk.env_first("PLAYBOOK", "PLAYBOOK_SLUG") == "solana-validator-security"


def test_artifact_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUN_ID", "run-abc")
    assert mk.artifact_uri() == "s3://midkernel-dev-artifacts/runs/run-abc/report.md"


def test_kimi_config_is_openrouter_legacy() -> None:
    config = mk.kimi_openrouter_config("moonshotai/kimi-k3")
    assert "type = \"openai_legacy\"" in config
    assert "openrouter.ai/api/v1" in config
    assert "moonshotai/kimi-k3" in config
    assert "bedrock" not in config.lower()


def test_kimi_extra_args_is_config_file_path() -> None:
    args = mk.kimi_extra_args("moonshotai/kimi-k3")
    assert args[0] == "--config"
    assert args[1].endswith(".midkernel/kimi/config.toml")
    assert "\n" not in args[1]
    assert "default_model" not in args[1]


def test_openrouter_node_env_passthrough(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "agent"))
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-emit")
    env = mk.openrouter_node_env(model="moonshotai/kimi-k3")
    assert env["OPENROUTER_API_KEY"] == "sk-or-emit"
    assert env["OPENAI_API_KEY"] == "sk-or-emit"
    assert env["OPENAI_BASE_URL"] == mk.OPENROUTER_BASE_URL
    assert env["HOME"] == str(tmp_path / "agent")
    assert env["KIMI_SHARE_DIR"] == str(tmp_path / ".midkernel" / "kimi")


def test_target_mode_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIDKERNEL_AGENTFLOW_TARGET", "local")
    target = mk.node_target(cwd="/workspace/repo")
    assert target == {"kind": "local", "cwd": "/workspace/repo"}


def test_default_targets_are_private_hunt_mirrors() -> None:
    solana = mk.default_target("solana-validator-security")
    firedancer = mk.default_target("firedancer-fuzz-triage")
    assert solana is not None
    assert solana.repo == "midkernel/bounty-target-jito-solana"
    assert solana.ref == "master"
    assert firedancer is not None
    assert firedancer.repo == "midkernel/bounty-target-jito-firebam"
    assert firedancer.ref == "main"
    assert mk.default_target("security-review") is None


def test_prepare_script_bakes_playbook_defaults() -> None:
    security = mk.prepare_script("security-review")
    assert "PLAYBOOK_SLUG:-security-review" in security
    assert "bounty-target-jito-solana" not in security
    assert "bounty-target-jito-firebam" not in security
    assert ": \"${GITHUB_OWNER:?GITHUB_OWNER is required" in security
    assert "--no-recurse-submodules" in security
    assert 'export MIDKERNEL_NODE_IO="${MIDKERNEL_NODE_IO:-1}"' in security
    assert "export WORKDIR" in security
    assert "node io: prepare WORKDIR=" in security
    assert "KIMI_SHARE_DIR" in security
    assert "$KIMI_SHARE_DIR/config.toml" in security
    assert "$WORKDIR/.midkernel-openrouter" in security

    solana = mk.prepare_script("solana-validator-security")
    assert "PLAYBOOK_SLUG:-solana-validator-security" in solana
    assert 'GITHUB_OWNER="${GITHUB_OWNER:-midkernel}"' in solana
    assert 'GITHUB_NAME="${GITHUB_NAME:-bounty-target-jito-solana}"' in solana
    assert 'GITHUB_REF="${GITHUB_REF:-master}"' in solana

    firedancer = mk.prepare_script("firedancer-fuzz-triage")
    assert "PLAYBOOK_SLUG:-firedancer-fuzz-triage" in firedancer
    assert 'GITHUB_NAME="${GITHUB_NAME:-bounty-target-jito-firebam}"' in firedancer
    assert 'GITHUB_REF="${GITHUB_REF:-main}"' in firedancer


def test_goal_count_defaults_and_clamps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOAL_COUNT", raising=False)
    assert mk.goal_count() == 6
    monkeypatch.setenv("GOAL_COUNT", "3")
    assert mk.goal_count() == 3
    monkeypatch.setenv("GOAL_COUNT", "99")
    assert mk.goal_count() == 6
    monkeypatch.setenv("GOAL_COUNT", "nope")
    assert mk.goal_count() == 6


def test_judge_models_stay_distinct_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JUDGE_A_MODEL", raising=False)
    monkeypatch.delenv("JUDGE_B_MODEL", raising=False)
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.delenv("MODEL", raising=False)
    assert mk.judge_a_model() == "moonshotai/kimi-k3"
    assert mk.judge_b_model() == "anthropic/claude-sonnet-4.5"
    monkeypatch.setenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4.5")
    assert mk.judge_a_model() == "anthropic/claude-sonnet-4.5"
    assert mk.judge_b_model() == "openai/gpt-4o"
    monkeypatch.setenv("JUDGE_B_MODEL", "openrouter/google/gemini-2.5-pro")
    assert mk.judge_b_model() == "google/gemini-2.5-pro"


def test_goal_playbook_prompt_and_no_default_target() -> None:
    prompt = mk.playbook_prompt("goal-security-review")
    assert "THREAT_MODEL.md" in prompt
    assert "GOAL_COUNT" in prompt
    assert "known-findings" in prompt or "known-issues" in prompt
    assert not prompt.startswith("---")
    assert mk.default_target("goal-security-review") is None


def test_goal_prompts_omit_github_dedupe() -> None:
    hunter = mk.hunter_prompt("goal-security-review", 3)
    assert "goals/03-" in hunter
    assert "no-op" in hunter.lower()
    assert "Do not search local known-findings" in hunter
    assert "open GitHub issues/PRs" in hunter
    split = mk.surface_split_prompt("goal-security-review")
    assert "GitHub-issue/PR duplicate" in split or "GitHub issues/PRs" in split
    assert "Do not prescribe" in mk.threat_model_prompt("goal-security-review")


def test_build_scan_graph_unchanged_shape() -> None:
    pytest.importorskip("agentflow")
    graph = mk.build_scan_graph(
        "security-review",
        description="unchanged scan graph",
    )
    payload = graph.to_payload()
    ids = [node["id"] for node in payload["nodes"]]
    assert ids == ["prepare", "review", "publish"]
    nodes = {node["id"]: node for node in payload["nodes"]}
    assert nodes["review"]["executable"].endswith("node_io.py")
    assert Path(nodes["review"]["executable"]).resolve() == (
        Path(__file__).resolve().parents[1] / "pipelines" / "_node_io.py"
    ).resolve()
    assert nodes["review"]["env"]["MIDKERNEL_NODE_ID"] == "review"
    assert nodes["review"]["env"]["MIDKERNEL_KIMI_BIN"]
    assert nodes["prepare"]["env"]["BASH_ENV"] == "/dev/null"
    assert nodes["publish"]["env"]["MIDKERNEL_NODE_READY"] == "1"
    assert "python3" in nodes["prepare"]["prompt"]
    assert "refusing to upload a stub" in nodes["publish"]["prompt"]
    assert "stub report" in nodes["publish"]["prompt"]


def test_goal_graph_hunters_follow_goal_count(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("agentflow")
    monkeypatch.setenv("GOAL_COUNT", "3")
    graph = mk.build_goal_scan_graph(
        "goal-security-review",
        description="dynamic hunters",
    )
    nodes = {node["id"]: node for node in graph.to_payload()["nodes"]}
    assert "hunter-1" in nodes and "hunter-2" in nodes and "hunter-3" in nodes
    assert "hunter-4" not in nodes
    assert nodes["hunter-1"]["env"]["MIDKERNEL_NODE_DYNAMIC"] == "1"
    assert nodes["hunter-1"]["env"]["MIDKERNEL_NODE_PARENT"] == "surface-split"
    assert set(nodes["judge-a"]["depends_on"]) == {"hunter-1", "hunter-2", "hunter-3"}


def test_review_prompt_names_default_targets() -> None:
    security = mk.review_prompt("security-review")
    assert "no default target" in security
    assert "bounty-target-jito-solana" not in security

    solana = mk.review_prompt("solana-validator-security")
    assert "midkernel/bounty-target-jito-solana" in solana
    assert "`master`" in solana
    assert "Banking stage" in solana

    firedancer = mk.review_prompt("firedancer-fuzz-triage")
    assert "midkernel/bounty-target-jito-firebam" in firedancer
    assert "`main`" in firedancer
    assert "sanitizer" in firedancer.lower()
    assert "agave/" in firedancer


def test_emit_is_side_effect_free_without_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("agentflow")
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.delenv("RUN_ID", raising=False)
    monkeypatch.delenv("MIDKERNEL_NODE_IO", raising=False)
    mk.emit("security-review", description="validate only")
    assert not (tmp_path / ".midkernel").exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "security-review"
    assert payload["nodes"]


def test_emit_goal_is_side_effect_free_without_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("agentflow")
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.delenv("RUN_ID", raising=False)
    monkeypatch.delenv("MIDKERNEL_NODE_IO", raising=False)
    mk.emit_goal("goal-security-review", description="validate only")
    assert not (tmp_path / ".midkernel").exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "goal-security-review"
