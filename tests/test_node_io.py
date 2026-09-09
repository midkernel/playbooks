from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pipelines import _node_io as io


@pytest.fixture
def io_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-test")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.delenv("ARTIFACTS_KEY", raising=False)
    monkeypatch.setenv("ARTIFACTS_PREFIX", "runs/")
    return tmp_path


def _read_json(root: Path, key: str) -> dict:
    return json.loads((root / "s3" / key).read_text(encoding="utf-8"))


def test_artifact_keys_match_run_ui_layout(io_home: Path) -> None:
    assert io.report_key() == "runs/run-test/report.md"
    assert io.graph_key() == "runs/run-test/graph.json"
    assert io.node_artifact_keys("threat-model") == {
        "prompt": "runs/run-test/nodes/threat-model/prompt.md",
        "output": "runs/run-test/nodes/threat-model/output.md",
        "meta": "runs/run-test/nodes/threat-model/meta.json",
    }
    with pytest.raises(ValueError):
        io.node_prompt_key("../etc/passwd")


def test_progress_eta_from_elapsed_over_completed() -> None:
    nodes = [
        {"id": "a", "status": "completed", "startedAt": "2026-09-09T00:00:00Z"},
        {"id": "b", "status": "completed", "startedAt": "2026-09-09T00:00:10Z"},
        {"id": "c", "status": "running", "startedAt": "2026-09-09T00:00:20Z"},
        {"id": "d", "status": "pending"},
    ]
    progress = io.compute_progress(nodes, now="2026-09-09T00:01:00Z")
    assert progress["completed"] == 2
    assert progress["total"] == 4
    assert progress["percent"] == 50
    # 60s elapsed / 2 completed * 2 remaining = 60
    assert progress["etaSeconds"] == 60
    empty = io.compute_progress(
        [{"id": "a", "status": "running", "startedAt": "2026-09-09T00:00:00Z"}],
        now="2026-09-09T00:01:00Z",
    )
    assert empty["etaSeconds"] is None
    assert empty["percent"] == 0


def test_percent_counts_failed_as_done() -> None:
    nodes = [
        {"id": "a", "status": "completed"},
        {"id": "b", "status": "failed"},
        {"id": "c", "status": "pending"},
    ]
    progress = io.compute_progress(nodes)
    assert progress["completed"] == 1
    assert progress["percent"] == 67


def test_start_finish_and_failed_partial_output(io_home: Path) -> None:
    io.init_graph(
        [io.graph_node_record("review", kind="kimi")],
        [],
    )
    io.start_node("review", prompt="exact prompt", kind="kimi", model="moonshotai/kimi-k3")
    graph = _read_json(io_home, "runs/run-test/graph.json")
    review = next(node for node in graph["nodes"] if node["id"] == "review")
    assert review["status"] == "running"
    assert review["startedAt"]
    prompt = (io_home / "s3" / "runs/run-test/nodes/review/prompt.md").read_text(encoding="utf-8")
    assert prompt.startswith("exact prompt")

    (io_home / "repo").mkdir(parents=True)
    (io_home / "repo" / "report.md").write_text("partial finding notes\n", encoding="utf-8")
    io.finish_node(
        "review",
        status="failed",
        error="kimi exited 1",
        outputs=["report.md"],
    )
    meta = _read_json(io_home, "runs/run-test/nodes/review/meta.json")
    assert meta["status"] == "failed"
    assert meta["error"] == "kimi exited 1"
    assert meta["model"] == "moonshotai/kimi-k3"
    output = (io_home / "s3" / "runs/run-test/nodes/review/output.md").read_text(encoding="utf-8")
    assert "partial finding notes" in output
    graph = _read_json(io_home, "runs/run-test/graph.json")
    review = next(node for node in graph["nodes"] if node["id"] == "review")
    assert review["status"] == "failed"
    assert review["finishedAt"]
    assert graph["progress"]["percent"] == 100


def test_spawn_hunters_are_first_class_dynamic(io_home: Path) -> None:
    io.init_graph(
        [
            io.graph_node_record("surface-split", kind="kimi"),
            io.graph_node_record("judge-a", kind="kimi"),
        ],
        [{"source": "surface-split", "target": "judge-a"}],
    )
    graph = io.spawn_hunters(3)
    ids = [node["id"] for node in graph["nodes"]]
    assert ids == ["surface-split", "judge-a", "hunter-1", "hunter-2", "hunter-3"]
    hunters = [node for node in graph["nodes"] if node["id"].startswith("hunter-")]
    assert all(node["dynamic"] is True for node in hunters)
    assert all(node["parentId"] == "surface-split" for node in hunters)
    assert all(node["status"] == "pending" for node in hunters)
    pairs = {(edge["source"], edge["target"]) for edge in graph["edges"]}
    for index in range(1, 4):
        assert ("surface-split", f"hunter-{index}") in pairs
        assert (f"hunter-{index}", "judge-a") in pairs
    again = io.spawn_hunters(3)
    assert len([n for n in again["nodes"] if n["id"].startswith("hunter-")]) == 3


def test_surface_split_finish_spawns_hunters(io_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOAL_COUNT", "2")
    io.init_graph(
        [
            io.graph_node_record("surface-split", kind="kimi"),
            io.graph_node_record("judge-a", kind="kimi"),
        ],
        [],
    )
    io.finish_node("surface-split", status="completed", output_text="goals/MANIFEST.md")
    graph = _read_json(io_home, "runs/run-test/graph.json")
    assert {node["id"] for node in graph["nodes"]} >= {"surface-split", "hunter-1", "hunter-2", "judge-a"}
    assert "hunter-3" not in {node["id"] for node in graph["nodes"]}


def test_bootstrap_uploads_prompts_and_graph(io_home: Path) -> None:
    payload = {
        "name": "security-review",
        "nodes": [
            {"id": "prepare", "agent": "shell", "prompt": "echo prepare", "depends_on": []},
            {"id": "review", "agent": "kimi", "prompt": "review the tree", "depends_on": ["prepare"]},
            {"id": "publish", "agent": "shell", "prompt": "upload", "depends_on": ["review"]},
        ],
    }
    graph = io.bootstrap_run_io(payload)
    assert [node["id"] for node in graph["nodes"]] == ["prepare", "review", "publish"]
    assert graph["progress"]["total"] == 3
    assert graph["progress"]["percent"] == 0
    assert (io_home / "s3" / "runs/run-test/nodes/review/prompt.md").read_text(encoding="utf-8") == "review the tree\n"
    assert (io_home / ".midkernel" / "node_io.py").is_file()


def test_wrap_shell_script_keeps_body_and_uploads(io_home: Path) -> None:
    wrapped = io.wrap_shell_script("publish", "echo uploaded s3://example\n", outputs=[])
    assert "echo uploaded s3://example" in wrapped
    assert "python3" in wrapped
    assert "finish" in wrapped
    assert "failed" in wrapped


def test_utc_now_is_zulu() -> None:
    stamp = io.utc_now()
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc
