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


def test_openrouter_model_default_is_balanced_pareto_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.delenv("MODEL", raising=False)
    assert mk.DEFAULT_OPENROUTER_MODEL == "google/gemini-3.8-flash"
    assert mk.openrouter_model() == "google/gemini-3.8-flash"
    # App injects per-profile via either env name.
    monkeypatch.setenv("MODEL", "openrouter/moonshotai/kimi-k3")
    assert mk.openrouter_model() == "moonshotai/kimi-k3"
    monkeypatch.setenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4.5")
    assert mk.openrouter_model() == "anthropic/claude-sonnet-4.5"


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
    assert "max_tokens = 16384" in config
    assert "max_output_size = 16384" in config
    assert "131072" not in config


def test_kimi_max_tokens_default_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in mk.MAX_TOKENS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    assert mk.MAX_TOKENS_ENV_NAMES == (
        "MIDKERNEL_OPENROUTER_MAX_TOKENS",
        "OPENROUTER_MAX_TOKENS",
        "KIMI_MAX_TOKENS",
        "KIMI_MODEL_MAX_TOKENS",
        "KIMI_MODEL_MAX_COMPLETION_TOKENS",
    )
    assert mk.kimi_max_tokens() == mk.DEFAULT_KIMI_MAX_TOKENS == 16384
    assert mk.MAX_SAFE_KIMI_MAX_TOKENS == 65536
    assert mk.UNSAFE_OPENROUTER_MAX_TOKENS == 131072
    monkeypatch.setenv("KIMI_MAX_TOKENS", "0")
    assert mk.kimi_max_tokens() == 16384
    monkeypatch.setenv("KIMI_MAX_TOKENS", "-1")
    assert mk.kimi_max_tokens() == 16384
    monkeypatch.setenv("KIMI_MAX_TOKENS", "nope")
    assert mk.kimi_max_tokens() == 16384
    monkeypatch.setenv("OPENROUTER_MAX_TOKENS", "65536")
    monkeypatch.delenv("KIMI_MAX_TOKENS", raising=False)
    assert mk.kimi_max_tokens() == 65536
    monkeypatch.setenv("MIDKERNEL_OPENROUTER_MAX_TOKENS", "65536")
    monkeypatch.delenv("OPENROUTER_MAX_TOKENS", raising=False)
    assert mk.kimi_max_tokens() == 65536
    # 32768 remains a valid explicit override (under the hard ceiling).
    monkeypatch.setenv("MIDKERNEL_OPENROUTER_MAX_TOKENS", "32768")
    assert mk.kimi_max_tokens() == 32768
    # 131072 is the exact 402 reservation — not a valid opt-in.
    # Clear higher-priority aliases so KIMI_MAX_TOKENS is the first-wins source.
    for name in mk.MAX_TOKENS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KIMI_MAX_TOKENS", "131072")
    assert mk.kimi_max_tokens() == 16384
    monkeypatch.setenv("KIMI_MAX_TOKENS", "80000")
    assert mk.kimi_max_tokens() == 16384
    monkeypatch.setenv("KIMI_MAX_TOKENS", "65536")
    assert mk.kimi_max_tokens() == 65536
    assert mk.clamp_kimi_max_tokens(131072) == 16384
    assert mk.clamp_kimi_max_tokens(65537) == 16384
    assert mk.clamp_kimi_max_tokens(65536) == 65536
    assert mk.clamp_kimi_max_tokens(32768) == 32768


def test_kimi_max_tokens_env_first_wins_matches_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in mk.MAX_TOKENS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KIMI_MODEL_MAX_COMPLETION_TOKENS", "1024")
    monkeypatch.setenv("KIMI_MODEL_MAX_TOKENS", "2048")
    monkeypatch.setenv("KIMI_MAX_TOKENS", "4096")
    monkeypatch.setenv("OPENROUTER_MAX_TOKENS", "8192")
    monkeypatch.setenv("MIDKERNEL_OPENROUTER_MAX_TOKENS", "65536")
    assert mk.kimi_max_tokens() == 65536
    monkeypatch.delenv("MIDKERNEL_OPENROUTER_MAX_TOKENS")
    assert mk.kimi_max_tokens() == 8192
    monkeypatch.delenv("OPENROUTER_MAX_TOKENS")
    assert mk.kimi_max_tokens() == 4096
    monkeypatch.delenv("KIMI_MAX_TOKENS")
    assert mk.kimi_max_tokens() == 2048
    monkeypatch.delenv("KIMI_MODEL_MAX_TOKENS")
    assert mk.kimi_max_tokens() == 1024


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
    for name in mk.MAX_TOKENS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    env = mk.openrouter_node_env(model="moonshotai/kimi-k3")
    assert env["OPENROUTER_API_KEY"] == "sk-or-emit"
    assert env["OPENAI_API_KEY"] == "sk-or-emit"
    assert env["OPENAI_BASE_URL"] == mk.OPENROUTER_BASE_URL
    assert env["HOME"] == str(tmp_path / "agent")
    assert env["KIMI_SHARE_DIR"] == str(tmp_path / ".midkernel" / "kimi")
    assert env["KIMI_MAX_TOKENS"] == "16384"
    assert env["OPENROUTER_MAX_TOKENS"] == "16384"
    assert env["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "16384"
    assert env["KIMI_MODEL_MAX_TOKENS"] == "16384"
    assert env["KIMI_MODEL_MAX_COMPLETION_TOKENS"] == "16384"


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
    assert "max_tokens = ${KIMI_MAX_TOKENS}" in security
    assert "max_output_size = ${KIMI_MAX_TOKENS}" in security
    assert (
        'OPENROUTER_MODEL="${OPENROUTER_MODEL:-${MODEL:-google/gemini-3.8-flash}}"'
        in security
    )
    assert "moonshotai/kimi-k3" not in security
    assert "KIMI_MAX_TOKENS=" in security
    assert "MIDKERNEL_OPENROUTER_MAX_TOKENS=" in security
    assert (
        "${MIDKERNEL_OPENROUTER_MAX_TOKENS:-${OPENROUTER_MAX_TOKENS:-"
        "${KIMI_MAX_TOKENS:-${KIMI_MODEL_MAX_TOKENS:-"
        "${KIMI_MODEL_MAX_COMPLETION_TOKENS:-"
    ) in security
    assert "16384" in security
    assert "max_tokens = 131072" not in security
    assert "max_output_size = 131072" not in security
    assert "-gt 65536" in security

    solana = mk.prepare_script("solana-validator-security")
    assert "PLAYBOOK_SLUG:-solana-validator-security" in solana
    assert 'GITHUB_OWNER="${GITHUB_OWNER:-midkernel}"' in solana
    assert 'GITHUB_NAME="${GITHUB_NAME:-bounty-target-jito-solana}"' in solana
    assert 'GITHUB_REF="${GITHUB_REF:-master}"' in solana

    firedancer = mk.prepare_script("firedancer-fuzz-triage")
    assert "PLAYBOOK_SLUG:-firedancer-fuzz-triage" in firedancer
    assert 'GITHUB_NAME="${GITHUB_NAME:-bounty-target-jito-firebam}"' in firedancer
    assert 'GITHUB_REF="${GITHUB_REF:-main}"' in firedancer


def test_profile_timeout_seconds_hard_table() -> None:
    # Per-node kimi budget. James lock 2026-09-10 / QA cmtuvv61w0003gm0az74grqv2:
    # low stays 30m; balanced 1h; max (exhaustive) 2h. Whole-run scaling is
    # the runner's job; this table is per node.
    assert mk.PROFILE_TIMEOUT_SECONDS["low"] == 30 * 60 == 1800
    assert mk.PROFILE_TIMEOUT_SECONDS["balanced"] == 60 * 60 == 3600
    assert mk.PROFILE_TIMEOUT_SECONDS["max"] == 2 * 60 * 60 == 7200
    assert 900 not in mk.PROFILE_TIMEOUT_SECONDS.values()
    assert mk.SOFT_DEADLINE_RATIO == 0.9
    assert mk.TIMEOUT_ENV_NAMES == (
        "AGENT_TIMEOUT_SECONDS",
        "PROFILE_TIMEOUT_SECONDS",
        "NODE_TIMEOUT_SECONDS",
    )


def test_hard_timeout_honors_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in mk.TIMEOUT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PROFILE", "low")
    assert mk.hard_timeout_seconds() == 1800
    assert mk.soft_deadline_seconds() == 1620
    monkeypatch.setenv("AGENT_TIMEOUT_SECONDS", "2000")
    assert mk.hard_timeout_seconds() == 2000
    assert mk.soft_deadline_seconds() == 1800
    monkeypatch.delenv("AGENT_TIMEOUT_SECONDS")
    monkeypatch.setenv("PROFILE_TIMEOUT_SECONDS", "1000")
    assert mk.hard_timeout_seconds() == 1000
    assert mk.soft_deadline_seconds() == 900
    monkeypatch.setenv("AGENT_TIMEOUT_SECONDS", "4000")
    assert mk.hard_timeout_seconds() == 4000
    assert mk.soft_deadline_seconds() == 3600
    monkeypatch.setenv("AGENT_TIMEOUT_SECONDS", "nope")
    monkeypatch.delenv("PROFILE_TIMEOUT_SECONDS")
    assert mk.hard_timeout_seconds() == 1800
    monkeypatch.setenv("PROFILE", "balanced")
    monkeypatch.delenv("AGENT_TIMEOUT_SECONDS")
    assert mk.hard_timeout_seconds() == 3600
    assert mk.soft_deadline_seconds() == 3240
    monkeypatch.setenv("PROFILE", "max")
    assert mk.hard_timeout_seconds() == 7200
    assert mk.soft_deadline_seconds() == 6480


def test_soft_deadline_prompt_includes_27_minutes_for_low(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in mk.TIMEOUT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PROFILE", "low")
    text = mk.wall_clock_budget_prompt()
    assert "27 minutes" in text
    assert "1620s" in text
    assert "30 minutes" in text
    assert "1800s" in text
    assert "soft deadline" in text.lower()
    hunter = mk.hunter_prompt("goal-security-review", 1)
    assert "27 minutes" in hunter
    assert "1620s" in hunter
    assert "Write RESULT.md before the soft deadline" in hunter
    review = mk.review_prompt("security-review")
    assert "27 minutes" in review
    assert "1620s" in review
    balanced = mk.wall_clock_budget_prompt(hard=3600)
    assert "54 minutes" in balanced
    assert "3240s" in balanced
    exhaustive = mk.wall_clock_budget_prompt(hard=7200)
    assert "108 minutes" in exhaustive
    assert "6480s" in exhaustive


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
    assert mk.judge_a_model() == "google/gemini-3.8-flash"
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


def test_build_scan_graph_unchanged_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("agentflow")
    for name in mk.MAX_TOKENS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
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
    assert nodes["review"]["env"]["KIMI_MAX_TOKENS"] == "16384"
    assert nodes["review"]["env"]["OPENROUTER_MAX_TOKENS"] == "16384"
    assert nodes["review"]["env"]["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "16384"
    assert nodes["prepare"]["env"]["BASH_ENV"] == "/dev/null"
    assert nodes["publish"]["env"]["MIDKERNEL_NODE_READY"] == "1"
    assert "python3" in nodes["prepare"]["prompt"]
    assert "refusing to upload a stub" in nodes["publish"]["prompt"]
    assert "stub report" in nodes["publish"]["prompt"]
    assert graph.to_payload()["fail_fast"] is True


def test_low_profile_goal_kimi_nodes_use_30_minute_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("agentflow")
    monkeypatch.setenv("PROFILE", "low")
    monkeypatch.setenv("GOAL_COUNT", "2")
    graph = mk.build_goal_scan_graph(
        "goal-security-review",
        description="low profile per-node timeout",
    )
    nodes = {node["id"]: node for node in graph.to_payload()["nodes"]}
    for task_id in (
        "threat-model",
        "goal-author",
        "surface-split",
        "hunter-1",
        "hunter-2",
        "judge-a",
        "judge-b",
        "assemble",
    ):
        assert nodes[task_id]["timeout_seconds"] == 1800
        assert "27 minutes" in nodes[task_id]["prompt"]
        assert "1620s" in nodes[task_id]["prompt"]
    assert nodes["prepare"]["timeout_seconds"] == 10 * 60
    assert nodes["publish"]["timeout_seconds"] == 5 * 60
    assert nodes["hunter-1"]["depends_on"] == ["surface-split"]
    assert nodes["hunter-2"]["depends_on"] == ["surface-split"]
    assert "hunter-1" not in nodes["hunter-2"]["depends_on"]
    assert set(nodes["judge-a"]["depends_on"]) == {"hunter-1", "hunter-2"}
    assert "hunter-join" not in nodes
    assert graph.to_payload()["fail_fast"] is False
    assert nodes["hunter-1"]["env"]["KIMI_MAX_TOKENS"] == "16384"
    assert nodes["hunter-1"]["env"]["MIDKERNEL_HUNTER_CONTINUE"] == "1"
    assert nodes["hunter-1"]["env"]["MIDKERNEL_NODE_TIMEOUT_SECONDS"] == "1800"
    assert int(nodes["hunter-1"]["env"]["MIDKERNEL_NODE_TIMEOUT_SECONDS"]) == nodes["hunter-1"]["timeout_seconds"]


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
    assert nodes["hunter-1"]["depends_on"] == ["surface-split"]
    assert nodes["hunter-2"]["depends_on"] == ["surface-split"]
    assert nodes["hunter-3"]["depends_on"] == ["surface-split"]
    ready_after_split = [
        hid
        for hid in ("hunter-1", "hunter-2", "hunter-3")
        if set(nodes[hid]["depends_on"]) <= {"surface-split"}
    ]
    assert ready_after_split == ["hunter-1", "hunter-2", "hunter-3"]
    assert set(nodes["judge-a"]["depends_on"]) == {"hunter-1", "hunter-2", "hunter-3"}
    assert "hunter-join" not in nodes
    payload = graph.to_payload()
    assert payload["concurrency"] == 1
    assert payload["fail_fast"] is False


def test_goal_graph_hunter_failure_does_not_fail_fast_siblings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hunter hard-fail must not skip later hunters or judges.

    Agentflow fail_fast=True skips every remaining node (QA
    cmtuvv61w0003gm0az74grqv2). A hunter-1 → hunter-2 depends_on chain
    also skips hunter-2 via upstream_failure even when fail_fast is False.
    """
    pytest.importorskip("agentflow")
    monkeypatch.setenv("GOAL_COUNT", "3")
    graph = mk.build_goal_scan_graph(
        "goal-security-review",
        description="hunter continue-on-fail",
    )
    payload = graph.to_payload()
    nodes = {node["id"]: node for node in payload["nodes"]}
    assert payload["fail_fast"] is False
    assert payload["concurrency"] == 1
    for index in (1, 2, 3):
        assert nodes[f"hunter-{index}"]["depends_on"] == ["surface-split"]
        assert "hunter-1" not in nodes[f"hunter-{index}"]["depends_on"] or index == 1
    assert "hunter-1" not in nodes["hunter-2"]["depends_on"]
    assert "hunter-2" not in nodes["hunter-3"]["depends_on"]
    assert set(nodes["judge-a"]["depends_on"]) == {"hunter-1", "hunter-2", "hunter-3"}
    assert "hunter-join" not in nodes
    assert nodes["judge-b"]["depends_on"] == ["judge-a"]
    assert nodes["assemble"]["depends_on"] == ["judge-b"]
    assert nodes["publish"]["depends_on"] == ["assemble"]


def test_balanced_and_max_goal_kimi_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("agentflow")
    monkeypatch.setenv("GOAL_COUNT", "1")
    monkeypatch.setenv("PROFILE", "balanced")
    balanced = mk.build_goal_scan_graph(
        "goal-security-review",
        description="balanced timeout",
    )
    nodes = {node["id"]: node for node in balanced.to_payload()["nodes"]}
    assert nodes["hunter-1"]["timeout_seconds"] == 3600
    assert "54 minutes" in nodes["hunter-1"]["prompt"]
    assert "3240s" in nodes["hunter-1"]["prompt"]
    monkeypatch.setenv("PROFILE", "max")
    exhaustive = mk.build_goal_scan_graph(
        "goal-security-review",
        description="max timeout",
    )
    nodes = {node["id"]: node for node in exhaustive.to_payload()["nodes"]}
    assert nodes["hunter-1"]["timeout_seconds"] == 7200
    assert "108 minutes" in nodes["hunter-1"]["prompt"]
    assert "6480s" in nodes["hunter-1"]["prompt"]


def test_agent_timeout_env_overrides_node_timeout_and_soft_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("agentflow")
    monkeypatch.setenv("PROFILE", "low")
    monkeypatch.setenv("GOAL_COUNT", "1")
    monkeypatch.setenv("AGENT_TIMEOUT_SECONDS", "1000")
    graph = mk.build_goal_scan_graph(
        "goal-security-review",
        description="env timeout override",
    )
    nodes = {node["id"]: node for node in graph.to_payload()["nodes"]}
    assert nodes["hunter-1"]["timeout_seconds"] == 1000
    assert "900s" in nodes["hunter-1"]["prompt"]
    scan = mk.build_scan_graph("security-review", description="env timeout override")
    review = next(node for node in scan.to_payload()["nodes"] if node["id"] == "review")
    assert review["timeout_seconds"] == 1000
    assert "900s" in review["prompt"]


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


def test_goal_ready_set_holds_judge_until_every_hunter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mechanical gate: judge-a is not ready until every hunter COMPLETED.

    Replicates pinned agentflow 09df0175 ready/skip rules. Must not rely on
    declaration order or concurrency=1 FIFO of a hash set.
    """
    pytest.importorskip("agentflow")
    monkeypatch.setenv("GOAL_COUNT", "3")
    payload = mk.build_goal_scan_graph(
        "goal-security-review",
        description="ready-set gate",
    ).to_payload()
    prefix = {"prepare", "threat-model", "goal-author", "surface-split"}
    hunters = {"hunter-1", "hunter-2", "hunter-3"}

    after_split = mk.agentflow_ready_node_ids(payload, completed=prefix)
    assert after_split == hunters
    assert "judge-a" not in after_split

    one_pending = mk.agentflow_ready_node_ids(
        payload,
        completed=prefix | {"hunter-1"},
    )
    assert one_pending == {"hunter-2", "hunter-3"}
    assert "judge-a" not in one_pending

    all_completed = mk.agentflow_ready_node_ids(
        payload,
        completed=prefix | hunters,
    )
    assert "judge-a" in all_completed

    # A FAILED hunter would skip judge-a — wrap must not leave hunters FAILED.
    one_failed = mk.agentflow_ready_node_ids(
        payload,
        completed=prefix | {"hunter-2", "hunter-3"},
        failed={"hunter-1"},
    )
    assert "judge-a" not in one_failed
    assert mk.agentflow_run_failed({"hunter-1": "FAILED", "publish": "COMPLETED"})

    split_failed = mk.agentflow_ready_node_ids(payload, failed={"surface-split"})
    assert "hunter-1" not in split_failed
    assert "judge-a" not in split_failed


def test_hunter_timeout_does_not_mark_graph_node_failed() -> None:
    """Product settle: hunter timeout is COMPLETED, so the GOAL run can succeed."""
    assert mk.hunter_wrap_is_graph_completed(exit_code=0, result_exists=True) is True
    assert mk.hunter_wrap_is_graph_completed(exit_code=124, result_exists=True) is False
    assert mk.hunter_wrap_is_graph_completed(exit_code=0, result_exists=False) is False
    assert mk.agentflow_run_failed({"hunter-1": "COMPLETED", "judge-a": "COMPLETED"}) is False
    assert mk.agentflow_run_failed({"hunter-1": "FAILED", "judge-a": "COMPLETED"}) is True


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
