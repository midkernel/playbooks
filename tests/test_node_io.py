from __future__ import annotations

import http.client
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

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
    assert ("surface-split", "hunter-1") in pairs
    assert ("hunter-1", "hunter-2") in pairs
    assert ("hunter-2", "hunter-3") in pairs
    assert ("surface-split", "hunter-2") not in pairs
    assert ("surface-split", "hunter-3") not in pairs
    for index in range(1, 4):
        assert (f"hunter-{index}", "judge-a") in pairs
    again = io.spawn_hunters(3)
    assert len([n for n in again["nodes"] if n["id"].startswith("hunter-")]) == 3


def test_hunter_graph_predecessor_is_serialized_not_parent() -> None:
    """parentId is surface-split; the execution edge is the hunter chain."""
    assert io.hunter_graph_predecessor("hunter-1") == "surface-split"
    assert io.hunter_graph_predecessor("hunter-2") == "hunter-1"
    assert io.hunter_graph_predecessor("hunter-6") == "hunter-5"
    assert io.hunter_graph_predecessor("judge-a") is None
    assert io.hunter_graph_predecessor("review") is None


def test_start_node_hunter_2_does_not_write_surface_split_edge(
    io_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live path: start_node(hunter-2) must not reintroduce fan-out.

    parentId / MIDKERNEL_NODE_PARENT stay surface-split (UI grouping).
    Reviewer 3 REQUEST_CHANGES on PR #12: update_node used to upsert
    parentId → hunter-N on every start/finish.
    """
    monkeypatch.setenv("MIDKERNEL_NODE_PARENT", "surface-split")
    monkeypatch.setenv("MIDKERNEL_NODE_DYNAMIC", "1")
    io.init_graph(
        [
            io.graph_node_record("surface-split", kind="kimi"),
            io.graph_node_record("judge-a", kind="kimi"),
        ],
        [{"source": "surface-split", "target": "judge-a"}],
    )
    io.spawn_hunters(3)
    io.start_node("hunter-1", kind="kimi", parent_id="surface-split", dynamic=True)
    io.start_node("hunter-2", kind="kimi", parent_id="surface-split", dynamic=True)
    graph = _read_json(io_home, "runs/run-test/graph.json")
    pairs = {(edge["source"], edge["target"]) for edge in graph["edges"]}
    assert ("surface-split", "hunter-1") in pairs
    assert ("surface-split", "hunter-2") not in pairs
    assert ("surface-split", "hunter-3") not in pairs
    assert ("hunter-1", "hunter-2") in pairs
    assert ("hunter-2", "judge-a") in pairs
    hunter2 = next(node for node in graph["nodes"] if node["id"] == "hunter-2")
    assert hunter2["parentId"] == "surface-split"
    assert hunter2["status"] == "running"
    io.finish_node("hunter-2", status="completed", output_text="ok")
    graph = _read_json(io_home, "runs/run-test/graph.json")
    pairs = {(edge["source"], edge["target"]) for edge in graph["edges"]}
    assert ("surface-split", "hunter-2") not in pairs
    assert ("hunter-1", "hunter-2") in pairs


def test_update_node_drops_leftover_surface_split_fanout(io_home: Path) -> None:
    """If an old fan-out edge exists, start/finish must drop it."""
    io.init_graph(
        [
            io.graph_node_record("surface-split", kind="kimi"),
            io.graph_node_record("judge-a", kind="kimi"),
        ],
        [
            {"source": "surface-split", "target": "hunter-2"},
            {"source": "hunter-1", "target": "hunter-2"},
            {"source": "hunter-2", "target": "judge-a"},
        ],
    )
    io.update_node(
        "hunter-2",
        kind="kimi",
        status="running",
        parentId="surface-split",
        dynamic=True,
    )
    graph = _read_json(io_home, "runs/run-test/graph.json")
    pairs = {(edge["source"], edge["target"]) for edge in graph["edges"]}
    assert ("surface-split", "hunter-2") not in pairs
    assert ("hunter-1", "hunter-2") in pairs
    assert ("hunter-2", "judge-a") in pairs


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
    pairs = {(edge["source"], edge["target"]) for edge in graph["edges"]}
    assert ("surface-split", "hunter-1") in pairs
    assert ("hunter-1", "hunter-2") in pairs
    assert ("surface-split", "hunter-2") not in pairs


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
    assert "MIDKERNEL_NODE_IO" in wrapped
    assert "RUN_ID" in wrapped
    assert 'export WORKDIR="${WORKDIR:-/workspace}"' in wrapped
    mkdir_at = wrapped.index('mkdir -p "$WORKDIR"')
    gate_at = wrapped.index('[ -d "$WORKDIR" ] && [ -w "$WORKDIR" ]')
    assert mkdir_at < gate_at
    assert "node io: wrap skipped" in wrapped


def test_node_io_disabled_without_run_or_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.delenv("RUN_ID", raising=False)
    monkeypatch.delenv("MIDKERNEL_NODE_IO", raising=False)
    monkeypatch.delenv("MIDKERNEL_IO_DIR", raising=False)
    assert io.node_io_enabled() is False
    assert io.install_runtime() is None
    graph = io.bootstrap_run_io(
        {"name": "security-review", "nodes": [{"id": "prepare", "agent": "shell", "prompt": "x"}]}
    )
    assert graph["nodes"] == []
    assert not (tmp_path / ".midkernel").exists()


def test_node_io_disabled_when_workdir_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = "/this-workdir-does-not-exist-midkernel-io"
    monkeypatch.setenv("WORKDIR", missing)
    monkeypatch.setenv("RUN_ID", "run-ci")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    assert not Path(missing).exists()
    assert io.node_io_enabled() is False
    assert io.node_io_disabled_reason() == f"WORKDIR_missing:{missing}"
    io.bootstrap_run_io({"name": "x", "nodes": []})
    assert not Path(missing).exists()
    err = capsys.readouterr().err
    assert "node io: disabled during bootstrap_run_io" in err
    assert "WORKDIR_missing" in err


def test_node_io_explicit_off_even_with_run(io_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "0")
    assert io.node_io_enabled() is False
    assert io.install_runtime() is None
    assert not (io_home / ".midkernel" / "node_io.py").exists()


def test_node_io_explicit_on_without_run_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.delenv("RUN_ID", raising=False)
    assert io.node_io_enabled() is True
    dest = io.install_runtime()
    assert dest is not None and dest.is_file()


def test_wrap_mkdirs_missing_workdir_and_installs_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prepare used to mkdir only inside the inner script; wrap must create first."""
    work = tmp_path / "task-disk"
    assert not work.exists()
    monkeypatch.setenv("WORKDIR", str(work))
    monkeypatch.setenv("RUN_ID", "run-wrap")
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(work / "s3"))
    monkeypatch.delenv("MIDKERNEL_NODE_IO", raising=False)
    wrapped = io.wrap_shell_script("prepare", "echo prepared-ok\n", outputs=[])
    script = tmp_path / "wrap.sh"
    script.write_text("#!/bin/bash\n" + wrapped + "\n", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "WORKDIR": str(work),
            "RUN_ID": "run-wrap",
            "MIDKERNEL_IO_SKIP_S3": "1",
            "MIDKERNEL_IO_DIR": str(work / "s3"),
        }
    )
    env.pop("MIDKERNEL_NODE_IO", None)
    result = subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert "prepared-ok" in result.stdout
    assert work.is_dir()
    assert (work / ".midkernel" / "node_io.py").is_file()
    assert (work / "s3" / "runs" / "run-wrap" / "graph.json").is_file()


def test_kimi_executable_is_source_helper() -> None:
    path = io.kimi_executable()
    assert path.endswith("pipelines/_node_io.py") or path.endswith("_node_io.py")
    assert Path(path).is_file()
    assert Path(path).resolve() == io.source_script_path()
    assert os.access(Path(path), os.X_OK)


def test_agentflow_style_direct_exec_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Doctor runs ``[executable, "--version"]`` — shebang + +x, no python3."""
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\necho kimi-probe-ok\n", encoding="utf-8")
    fake.chmod(0o755)
    env = os.environ.copy()
    env["MIDKERNEL_KIMI_BIN"] = str(fake)
    env["WORKDIR"] = str(tmp_path / "missing-workdir")
    env.pop("RUN_ID", None)
    env.pop("MIDKERNEL_NODE_IO", None)
    result = subprocess.run(
        [str(io.source_script_path()), "--version"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert "kimi-probe-ok" in result.stdout
    assert not (tmp_path / "missing-workdir").exists()


def test_version_and_help_forward_to_real_kimi_without_node_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    """agentflow preflight execs ``_node_io.py --version``; must not write S3/disk."""
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\necho kimi-probe-ok \"$@\"\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path / "missing-workdir"))
    monkeypatch.delenv("RUN_ID", raising=False)
    monkeypatch.delenv("MIDKERNEL_NODE_IO", raising=False)

    code = io.main(["--version"])
    captured = capfd.readouterr()
    assert code == 0
    assert "kimi-probe-ok" in captured.out
    assert "--version" in captured.out
    assert not (tmp_path / "missing-workdir").exists()

    code = io.main(["--help"])
    captured = capfd.readouterr()
    assert code == 0
    assert "kimi-probe-ok" in captured.out


def test_version_succeeds_without_real_kimi_bin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """CI / laptop: --version must still exit 0 so agentflow doctor kimi_ready passes."""
    missing = str(tmp_path / "missing-kimi.bin")
    monkeypatch.setattr(io, "IMAGE_KIMI_BIN", missing)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", missing)
    monkeypatch.setenv("WORKDIR", str(tmp_path / "missing-workdir"))
    monkeypatch.delenv("RUN_ID", raising=False)
    monkeypatch.delenv("MIDKERNEL_NODE_IO", raising=False)
    code = io.main(["--version"])
    captured = capsys.readouterr()
    assert code == 0
    assert "kimi (midkernel-node-io)" in captured.out
    assert not (tmp_path / "missing-workdir").exists()


def test_wrap_kimi_real_run_uploads_prompt_and_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\necho kimi-ran\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-wrap-kimi")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_ID", "threat-model")
    assert io.main(["-p", "do the hunt"]) == 0
    prompt = (tmp_path / "s3" / "runs/run-wrap-kimi/nodes/threat-model/prompt.md").read_text(
        encoding="utf-8"
    )
    assert "do the hunt" in prompt
    meta = json.loads(
        (tmp_path / "s3" / "runs/run-wrap-kimi/nodes/threat-model/meta.json").read_text(
            encoding="utf-8"
        )
    )
    assert meta["status"] == "completed"


def test_version_probe_skips_start_finish_on_live_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\necho kimi-probe-ok\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-probe")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    assert io.main(["--version"]) == 0
    assert not (tmp_path / ".midkernel" / "graph.json").exists()
    assert not (tmp_path / "s3" / "runs" / "run-probe").exists()


def test_real_kimi_bin_skips_report_md_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapper = tmp_path / "kimi"
    wrapper.write_text(
        "#!/bin/sh\nREAL=${KIMI_REAL_BIN:-/opt/midkernel/kimi.bin}\n"
        "midkernel-publish-report --require\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    real = tmp_path / "kimi.bin"
    real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(wrapper))
    monkeypatch.setenv("PATH", str(tmp_path))
    assert io.is_report_md_wrapper(wrapper)
    # Pinned wrapper is skipped; fall through to image default path string.
    assert io.real_kimi_bin() == io.IMAGE_KIMI_BIN
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(real))
    assert io.real_kimi_bin() == str(real)


def test_kimi_io_env_always_pins_real_bin(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in io.MAX_TOKENS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.delenv("MODEL", raising=False)
    env = io.kimi_io_env("threat-model", outputs=["THREAT_MODEL.md"])
    assert env["MIDKERNEL_KIMI_BIN"]
    assert env["BASH_ENV"] == "/dev/null"
    assert env["MIDKERNEL_NODE_READY"] == "1"
    assert env["MIDKERNEL_NODE_ID"] == "threat-model"
    assert env["OPENAI_BASE_URL"] == io.OPENROUTER_BASE_URL
    assert io.DEFAULT_OPENROUTER_MODEL == "google/gemini-3.8-flash"
    assert env["OPENROUTER_MODEL"] == "google/gemini-3.8-flash"
    assert env["KIMI_SHARE_DIR"].endswith(".midkernel/kimi")


def test_kimi_io_env_passes_openrouter_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENROUTER_MODEL", "openrouter/anthropic/claude-sonnet-4.5")
    env = io.kimi_io_env("hunter-1", outputs=["findings/hunter-1/RESULT.md"], model="anthropic/claude-sonnet-4.5")
    assert env["OPENROUTER_API_KEY"] == "sk-or-test"
    assert env["OPENAI_API_KEY"] == "sk-or-test"
    assert env["KIMI_API_KEY"] == "sk-or-test"
    assert env["HOME"] == str(tmp_path / "home")
    assert env["OPENROUTER_MODEL"] == "anthropic/claude-sonnet-4.5"
    assert env["KIMI_SHARE_DIR"] == str(tmp_path / ".midkernel" / "kimi")
    assert env["KIMI_MAX_TOKENS"] == "16384"
    assert env["OPENROUTER_MAX_TOKENS"] == "16384"
    assert env["MIDKERNEL_OPENROUTER_MAX_TOKENS"] == "16384"
    assert env["KIMI_MODEL_MAX_TOKENS"] == "16384"
    assert env["KIMI_MODEL_MAX_COMPLETION_TOKENS"] == "16384"


def test_ensure_kimi_config_rewrites_inline_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-live")
    inline = io.render_kimi_openrouter_config("moonshotai/kimi-k3")
    argv, path = io.ensure_kimi_config_argv(
        ["--print", "--yolo", "-p", "hi", "--config", inline],
        model="moonshotai/kimi-k3",
    )
    assert path.is_file()
    assert argv[-2:] == ["--config", str(path)]
    assert "\n" not in argv[-1]
    text = path.read_text(encoding="utf-8")
    assert "openai_legacy" in text
    assert "sk-or-live" in text
    assert "moonshotai/kimi-k3" in text
    assert "max_tokens = 16384" in text
    assert "max_output_size = 16384" in text
    assert "131072" not in text


def test_resolve_openrouter_key_from_workdir_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("KIMI_API_KEY", raising=False)
    (tmp_path / ".midkernel-openrouter").write_text("sk-from-prepare\n", encoding="utf-8")
    assert io.resolve_openrouter_api_key() == "sk-from-prepare"


def test_node_io_gate_silent_without_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.delenv("RUN_ID", raising=False)
    monkeypatch.delenv("MIDKERNEL_NODE_IO", raising=False)
    io.log_node_io_gate("emit")
    assert capsys.readouterr().err == ""


def test_ecs_in_task_script_exports_contract() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "ecs-in-task.sh"
    text = script.read_text(encoding="utf-8")
    assert script.is_file()
    assert "MIDKERNEL_NODE_IO" in text
    assert "MIDKERNEL_AGENTFLOW_TARGET" in text
    assert 'WORKDIR="${WORKDIR:-/workspace}"' in text
    assert "MIDKERNEL_KIMI_BIN" in text
    assert "agentflow run" in text
    assert "--preflight never" in text
    assert "BASH_ENV=/dev/null" in text
    assert "MIDKERNEL_NODE_READY" in text
    assert "pipelines/${PLAYBOOK}.py" in text or 'pipelines/${PLAYBOOK}.py' in text
    assert "git clone" in text
    assert "MIDKERNEL_PLAYBOOKS_DIR" in text


def test_utc_now_is_zulu() -> None:
    stamp = io.utc_now()
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc


def test_cap_openrouter_payload_never_leaves_131072() -> None:
    cap = io.DEFAULT_KIMI_MAX_TOKENS
    injected = io.cap_openrouter_payload({"model": "moonshotai/kimi-k3"}, cap)
    assert injected["max_tokens"] == 16384
    clamped = io.cap_openrouter_payload(
        {"max_tokens": io.UNSAFE_OPENROUTER_MAX_TOKENS, "max_completion_tokens": 200000},
        cap,
    )
    assert clamped["max_tokens"] == 16384
    assert clamped["max_completion_tokens"] == 16384
    kept = io.cap_openrouter_payload({"max_tokens": 1024}, cap)
    assert kept["max_tokens"] == 1024
    zeroed = io.cap_openrouter_payload({"max_tokens": 0}, cap)
    assert zeroed["max_tokens"] == 16384
    # A caller-supplied cap of 131072 is itself unsafe and becomes 16384.
    unsafe_cap = io.cap_openrouter_payload({"max_tokens": 131072}, 131072)
    assert unsafe_cap["max_tokens"] == 16384


def test_cap_openrouter_request_body_empty_or_non_json_never_passthrough() -> None:
    cap = io.DEFAULT_KIMI_MAX_TOKENS
    empty = json.loads(io.cap_openrouter_request_body(b"", cap).decode("utf-8"))
    assert empty == {"max_tokens": 16384}
    whitespace = json.loads(io.cap_openrouter_request_body(b"  \n", cap).decode("utf-8"))
    assert whitespace == {"max_tokens": 16384}
    missing = json.loads(
        io.cap_openrouter_request_body(b'{"model":"moonshotai/kimi-k3"}', cap).decode("utf-8")
    )
    assert missing["max_tokens"] == 16384
    assert missing["model"] == "moonshotai/kimi-k3"
    rewritten = json.loads(
        io.cap_openrouter_request_body(b'{"max_tokens":131072}', cap).decode("utf-8")
    )
    assert rewritten["max_tokens"] == 16384
    with pytest.raises(io.OpenRouterMaxTokensCapError):
        io.cap_openrouter_request_body(b"not-json", cap)
    with pytest.raises(io.OpenRouterMaxTokensCapError):
        io.cap_openrouter_request_body(b"[1,2,3]", cap)


def test_read_http_request_body_missing_content_length_is_empty() -> None:
    assert io.read_http_request_body({}, BytesIO(b'{"max_tokens":131072}')) == b""
    headers = {"Content-Length": "0"}
    assert io.read_http_request_body(headers, BytesIO(b'{"x":1}')) == b""
    headers = {"Content-Length": "18"}
    assert io.read_http_request_body(headers, BytesIO(b'{"max_tokens":1}')) == b'{"max_tokens":1}'


def test_render_kimi_config_writes_max_tokens_and_rejects_131072() -> None:
    text = io.render_kimi_openrouter_config("moonshotai/kimi-k3", max_tokens=16384)
    assert "max_tokens = 16384" in text
    assert "max_output_size = 16384" in text
    assert "131072" not in text
    defaulted = io.render_kimi_openrouter_config("moonshotai/kimi-k3")
    assert "max_tokens = 16384" in defaulted
    # 32768 remains a valid explicit override under the hard ceiling.
    kept = io.render_kimi_openrouter_config("moonshotai/kimi-k3", max_tokens=32768)
    assert "max_tokens = 32768" in kept
    rejected = io.render_kimi_openrouter_config("moonshotai/kimi-k3", max_tokens=131072)
    assert "max_tokens = 16384" in rejected
    assert "max_tokens = 131072" not in rejected
    ceiling = io.render_kimi_openrouter_config("moonshotai/kimi-k3", max_tokens=65536)
    assert "max_tokens = 65536" in ceiling


@contextmanager
def _openrouter_proxy_harness() -> Iterator[tuple[str, dict[str, object]]]:
    received: dict[str, object] = {}

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            received["path"] = self.path
            received["raw"] = raw
            received["body"] = json.loads(raw.decode("utf-8")) if raw else None
            payload = b'{"id":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        _host, port = upstream.server_address
        proxy = io.OpenRouterMaxTokensProxy(
            upstream_base=f"http://127.0.0.1:{int(port)}/api/v1"
        )
        base = proxy.start()
        try:
            yield base, received
        finally:
            proxy.stop()
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_openrouter_proxy_injects_max_tokens() -> None:
    with _openrouter_proxy_harness() as (base, received):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps({"model": "moonshotai/kimi-k3", "max_tokens": 131072}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        assert received["body"]["max_tokens"] == 16384
        assert received["path"].endswith("/chat/completions")


def test_openrouter_proxy_injects_missing_max_tokens() -> None:
    with _openrouter_proxy_harness() as (base, received):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps({"model": "moonshotai/kimi-k3"}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        assert received["body"]["max_tokens"] == 16384
        assert received["body"]["model"] == "moonshotai/kimi-k3"


def test_openrouter_proxy_injects_empty_body() -> None:
    with _openrouter_proxy_harness() as (base, received):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=b"",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        assert received["body"] == {"max_tokens": 16384}


def test_openrouter_proxy_injects_missing_content_length() -> None:
    with _openrouter_proxy_harness() as (base, received):
        parts = urlsplit(base)
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
        try:
            conn.putrequest("POST", "/api/v1/chat/completions")
            conn.putheader("Content-Type", "application/json")
            conn.endheaders()
            resp = conn.getresponse()
            assert resp.status == 200
            resp.read()
        finally:
            conn.close()
        assert received["body"] == {"max_tokens": 16384}


def test_openrouter_proxy_rejects_non_json_chat_completions() -> None:
    with _openrouter_proxy_harness() as (base, received):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=b"not-json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code == 400
        assert "body" not in received


def test_wrap_kimi_does_not_invent_hunter_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-hunter-fail")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_ID", "hunter-1")
    monkeypatch.setenv("MIDKERNEL_NODE_OUTPUTS", "findings/hunter-1/RESULT.md")
    assert io.main(["-p", "hunt"]) == 1
    result = tmp_path / "repo" / "findings" / "hunter-1" / "RESULT.md"
    assert not result.exists()
    assert not (tmp_path / "findings" / "hunter-1" / "RESULT.md").exists()


def test_wrap_kimi_hunter_continue_writes_incomplete_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-hunter-continue")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_ID", "hunter-1")
    monkeypatch.setenv("MIDKERNEL_NODE_OUTPUTS", "findings/hunter-1/RESULT.md")
    monkeypatch.setenv("MIDKERNEL_HUNTER_CONTINUE", "1")
    assert io.main(["-p", "hunt"]) == 0
    result = tmp_path / "repo" / "findings" / "hunter-1" / "RESULT.md"
    assert result.is_file()
    text = result.read_text(encoding="utf-8")
    assert io.INCOMPLETE_HUNTER_MARKER in text


def test_wrap_kimi_hunter_continue_soft_timeout_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\nexec sleep 30\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-hunter-soft-timeout")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_ID", "hunter-1")
    monkeypatch.setenv("MIDKERNEL_NODE_OUTPUTS", "findings/hunter-1/RESULT.md")
    monkeypatch.setenv("MIDKERNEL_HUNTER_CONTINUE", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_TIMEOUT_SECONDS", "2")
    assert io.hunter_inner_timeout_seconds() == 1
    assert io.main(["-p", "hunt"]) == 0
    result = tmp_path / "repo" / "findings" / "hunter-1" / "RESULT.md"
    assert result.is_file()
    assert io.INCOMPLETE_HUNTER_MARKER in result.read_text(encoding="utf-8")


def test_wrap_kimi_uploads_result_when_model_writes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "repo" / "findings" / "hunter-1" / "RESULT.md"
    fake = tmp_path / "kimi.bin"
    fake.write_text(
        "#!/bin/sh\n"
        f"mkdir -p '{dest.parent}'\n"
        f"printf '%s\\n' 'clean miss: read goals/01 and THREAT_MODEL.md' > '{dest}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-hunter-ok")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_ID", "hunter-1")
    monkeypatch.setenv("MIDKERNEL_NODE_OUTPUTS", "findings/hunter-1/RESULT.md")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    assert io.main(["-p", "hunt"]) == 0
    assert dest.is_file()
    output = (tmp_path / "s3" / "runs/run-hunter-ok/nodes/hunter-1/output.md").read_text(
        encoding="utf-8"
    )
    assert "clean miss" in output
    assert "invent" not in output.lower()
    config = (tmp_path / ".midkernel" / "kimi" / "config.toml").read_text(encoding="utf-8")
    assert "max_tokens = 16384" in config
    assert "max_tokens = 131072" not in config


def test_wrap_kimi_rejects_131072_env_in_written_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "kimi.bin"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MIDKERNEL_KIMI_BIN", str(fake))
    monkeypatch.setenv("WORKDIR", str(tmp_path))
    monkeypatch.setenv("RUN_ID", "run-cap-131072")
    monkeypatch.setenv("MIDKERNEL_IO_DIR", str(tmp_path / "s3"))
    monkeypatch.setenv("MIDKERNEL_IO_SKIP_S3", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_IO", "1")
    monkeypatch.setenv("MIDKERNEL_NODE_ID", "hunter-1")
    monkeypatch.setenv("KIMI_MAX_TOKENS", "131072")
    assert io.main(["-p", "hunt"]) == 0
    config = (tmp_path / ".midkernel" / "kimi" / "config.toml").read_text(encoding="utf-8")
    assert "max_tokens = 16384" in config
    assert "max_tokens = 131072" not in config


def test_parse_retry_after_seconds_and_http_date() -> None:
    assert io.parse_retry_after("2") == 2.0
    assert io.parse_retry_after("0") == 0.0
    assert io.parse_retry_after("") is None
    assert io.parse_retry_after(None) is None
    assert io.parse_retry_after("not-a-date") is None
    now = datetime(2026, 9, 9, 22, 0, 0, tzinfo=timezone.utc)
    assert io.parse_retry_after("Wed, 09 Sep 2026 22:00:03 GMT", now=now) == 3.0
    assert io.parse_retry_after("Wed, 09 Sep 2026 21:59:50 GMT", now=now) == 0.0


def test_openrouter_429_delay_prefers_retry_after_then_backoff() -> None:
    assert io.openrouter_429_delay_seconds(0, "5") == 5.0
    # 20 RPM window is 60s; do not clamp Retry-After to the old 32s cap.
    assert io.openrouter_429_delay_seconds(0, "60") == 60.0
    assert io.openrouter_429_delay_seconds(0, "90") == 90.0
    assert io.openrouter_429_delay_seconds(0, "999") == io.OPENROUTER_429_BACKOFF_CAP_SECONDS
    assert io.OPENROUTER_429_BACKOFF_CAP_SECONDS == 90.0
    assert io.openrouter_429_delay_seconds(0, None) == 1.0
    assert io.openrouter_429_delay_seconds(1, None) == 2.0
    assert io.openrouter_429_delay_seconds(2, None) == 4.0
    assert io.openrouter_429_delay_seconds(3, None) == 8.0
    assert io.openrouter_429_delay_seconds(6, None) == 64.0
    assert io.openrouter_429_delay_seconds(7, None) == io.OPENROUTER_429_BACKOFF_CAP_SECONDS
    assert io.openrouter_429_delay_seconds(10, None) == io.OPENROUTER_429_BACKOFF_CAP_SECONDS
    assert io.should_retry_openrouter(429, 0, 8) is True
    assert io.should_retry_openrouter(429, 7, 8) is True
    assert io.should_retry_openrouter(429, 8, 8) is False
    assert io.should_retry_openrouter(402, 0, 8) is False
    assert io.should_retry_openrouter(500, 0, 8) is False


def test_openrouter_429_retries_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIDKERNEL_OPENROUTER_429_RETRIES", raising=False)
    assert io.openrouter_429_retries() == 8
    monkeypatch.setenv("MIDKERNEL_OPENROUTER_429_RETRIES", "2")
    assert io.openrouter_429_retries() == 2
    monkeypatch.setenv("MIDKERNEL_OPENROUTER_429_RETRIES", "99")
    assert io.openrouter_429_retries() == io.MAX_OPENROUTER_429_RETRIES
    monkeypatch.setenv("MIDKERNEL_OPENROUTER_429_RETRIES", "nope")
    assert io.openrouter_429_retries() == 8


@contextmanager
def _openrouter_scripted_proxy(
    script: list[dict[str, object]],
) -> Iterator[tuple[str, dict[str, object]]]:
    hits: dict[str, object] = {"n": 0, "bodies": []}

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            bodies = hits["bodies"]
            assert isinstance(bodies, list)
            bodies.append(json.loads(raw.decode("utf-8")) if raw else None)
            n = int(hits["n"])
            step = script[min(n, len(script) - 1)]
            hits["n"] = n + 1
            payload = step.get("body", b'{"id":"ok"}')
            assert isinstance(payload, (bytes, bytearray))
            self.send_response(int(step["status"]))
            if "retry_after" in step:
                self.send_header("Retry-After", str(step["retry_after"]))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        _host, port = upstream.server_address
        proxy = io.OpenRouterMaxTokensProxy(
            retries=4,
            upstream_base=f"http://127.0.0.1:{int(port)}/api/v1",
        )
        base = proxy.start()
        try:
            yield base, hits
        finally:
            proxy.stop()
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_openrouter_proxy_honors_retry_after_60s_rpm_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """New-account 20 RPM is a 60s window; do not clamp Retry-After to 32s."""
    slept: list[float] = []
    monkeypatch.setattr(io, "_sleep", slept.append)
    script = [
        {"status": 429, "retry_after": "60", "body": b'{"error":"rate"}'},
        {"status": 200, "body": b'{"id":"ok"}'},
    ]
    with _openrouter_scripted_proxy(script) as (base, hits):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps({"model": "moonshotai/kimi-k3"}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        assert hits["n"] == 2
        assert slept == [60.0]


def test_openrouter_proxy_retries_429_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(io, "_sleep", slept.append)
    script = [
        {"status": 429, "retry_after": "2", "body": b'{"error":"rate"}'},
        {"status": 429, "body": b'{"error":"rate"}'},
        {"status": 200, "body": b'{"id":"ok"}'},
    ]
    with _openrouter_scripted_proxy(script) as (base, hits):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps({"model": "moonshotai/kimi-k3", "max_tokens": 131072}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8"))["id"] == "ok"
        assert hits["n"] == 3
        bodies = hits["bodies"]
        assert isinstance(bodies, list)
        assert all(body["max_tokens"] == 16384 for body in bodies)
        # Retry-After=2 on the first 429; second 429 has no header → 2**1 = 2s.
        assert slept == [2.0, 2.0]


def test_openrouter_proxy_exhausted_429_is_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(io, "_sleep", slept.append)
    script = [{"status": 429, "retry_after": "1", "body": b'{"error":"rate"}'}]
    with _openrouter_scripted_proxy(script) as (base, hits):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps({"model": "moonshotai/kimi-k3"}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code == 429
        assert hits["n"] == 5
        assert len(slept) == 4


def test_openrouter_proxy_does_not_retry_402(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(io, "_sleep", slept.append)
    script = [{"status": 402, "body": b'{"error":"in_flight_budget_exhausted"}'}]
    with _openrouter_scripted_proxy(script) as (base, hits):
        req = urllib.request.Request(
            f"{base}/chat/completions",
            data=json.dumps({"model": "moonshotai/kimi-k3"}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code == 402
        assert hits["n"] == 1
        assert slept == []
