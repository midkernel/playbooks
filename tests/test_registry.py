"""Public registry stays list_playbooks-readable."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = (
    "security-review",
    "solana-validator-security",
    "firedancer-fuzz-triage",
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
        body = text.split("---", 2)[-1].strip()
        assert body, f"{slug}.md body must remain a skill prompt"


def test_pipeline_files_exist() -> None:
    for slug in EXPECTED:
        path = ROOT / "pipelines" / f"{slug}.py"
        assert path.is_file(), f"missing graph {path}"


def test_readme_documents_opencode_deferred() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "OpenCode" in readme
    assert "deferred" in readme.lower()
    assert "list_playbooks" in readme
    assert "MIDKERNEL_AGENTFLOW_TARGET" in readme
    assert "s3://midkernel-dev-artifacts/runs/" in readme
