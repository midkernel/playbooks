from __future__ import annotations

import os
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

    solana = mk.prepare_script("solana-validator-security")
    assert "PLAYBOOK_SLUG:-solana-validator-security" in solana
    assert 'GITHUB_OWNER="${GITHUB_OWNER:-midkernel}"' in solana
    assert 'GITHUB_NAME="${GITHUB_NAME:-bounty-target-jito-solana}"' in solana
    assert 'GITHUB_REF="${GITHUB_REF:-master}"' in solana

    firedancer = mk.prepare_script("firedancer-fuzz-triage")
    assert "PLAYBOOK_SLUG:-firedancer-fuzz-triage" in firedancer
    assert 'GITHUB_NAME="${GITHUB_NAME:-bounty-target-jito-firebam}"' in firedancer
    assert 'GITHUB_REF="${GITHUB_REF:-main}"' in firedancer


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
