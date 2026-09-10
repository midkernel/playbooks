"""Public registry stays list_playbooks-readable."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = (
    "security-review",
    "solana-validator-security",
    "firedancer-fuzz-triage",
    "goal-security-review",
)


def test_root_markdown_playbooks_exist() -> None:
    for slug in EXPECTED:
        path = ROOT / f"{slug}.md"
        assert path.is_file(), f"missing listing file {path.name}"
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---\n")
        assert f"slug: {slug}" in text
        assert "kind: agentflow-graph" in text
        assert f"pipeline: pipelines/{slug}.py" in text
        assert "harness: kimi" in text
        assert "provider: openrouter" in text
        if slug == "solana-validator-security":
            assert "target_repo: midkernel/bounty-target-jito-solana" in text
            assert "target_ref: master" in text
        elif slug == "firedancer-fuzz-triage":
            assert "target_repo: midkernel/bounty-target-jito-firebam" in text
            assert "target_ref: main" in text
        else:
            assert "target_repo:" not in text
        body = text.split("---", 2)[-1].strip()
        assert body, f"{slug}.md body must remain a skill prompt"
        if slug == "goal-security-review":
            assert "GOAL_COUNT" in body
            assert "THREAT_MODEL.md" in body
            assert "known-findings" in body or "known-issues" in body


def test_pipeline_files_exist() -> None:
    for slug in EXPECTED:
        path = ROOT / "pipelines" / f"{slug}.py"
        assert path.is_file(), f"missing graph {path}"


def test_readme_documents_openrouter_lock_and_default_targets() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "OpenRouter" in readme
    assert "Kimi" in readme
    assert "google/gemini-3.8-flash" in readme
    assert "Pareto Scan" in readme
    assert "per-profile" in readme.lower() or "per Scan profile" in readme
    assert "not required" in readme.lower()
    assert "OpenCode" in readme
    assert "list_playbooks" in readme
    assert "MIDKERNEL_AGENTFLOW_TARGET" in readme
    assert "s3://midkernel-dev-artifacts/runs/" in readme
    assert "midkernel/bounty-target-jito-solana" in readme
    assert "midkernel/bounty-target-jito-firebam" in readme
    assert "goal-security-review" in readme
    assert "GOAL_COUNT" in readme
    assert "THREAT" in readme
    assert "known-issues" in readme.lower() or "known-findings" in readme.lower()
    assert "graph.json" in readme
    assert "nodes/<nodeId>/prompt.md" in readme
    assert "nodes/<nodeId>/output.md" in readme
    assert "nodes/<nodeId>/meta.json" in readme
    assert "MIDKERNEL_NODE_IO" in readme
    assert "MIDKERNEL_KIMI_BIN" in readme
    assert "KIMI_MAX_TOKENS" in readme
    assert "OPENROUTER_MAX_TOKENS" in readme
    assert "MIDKERNEL_OPENROUTER_MAX_TOKENS" in readme
    assert "KIMI_MODEL_MAX_TOKENS" in readme
    assert "first-wins" in readme.lower() or "First-wins" in readme
    assert "16384" in readme
    assert "32768" in readme
    assert "65536" in readme
    assert "valid opt-in" in readme
    assert "set the env explicitly to opt in" not in readme
    assert "131072 only if set explicitly" not in readme
    assert "cmtufzqzo0003k004mt2w0m9c" in readme
    assert "cmtulxq7v0003l2046bhhc3yl" in readme
    assert "openrouter_key_limit" in readme
    assert "in_flight_budget_exhausted" in readme
    assert "scripts/ecs-in-task.sh" in readme
    assert "--version" in readme
    assert "cmtuavpvs0003ib04bfyr7roc" in readme
    assert "sha256(text.trim())" in readme or "text.trim()" in readme
    assert "cmtun51000003l704q7lyyjrf" in readme
    assert "openrouter_new_account" in readme
    assert "20 requests/minute" in readme
    assert "429" in readme
    assert "serialized" in readme.lower() or "depends_on" in readme
    assert "90s" in readme
    assert "hunter-2..N never regain" in readme or "never regain a `surface-split` edge" in readme
    assert "cmtuvv61w0003gm0az74grqv2" in readme
    assert "AGENT_TIMEOUT_SECONDS" in readme
    assert "1620" in readme
    assert "27 minutes" in readme
    assert "fail_fast" in readme
    assert "7200" in readme
    assert "3600" in readme
