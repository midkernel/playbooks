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
