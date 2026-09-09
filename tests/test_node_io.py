from __future__ import annotations

import json
import os
import subprocess
import threading
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    for name in (
        "KIMI_MAX_TOKENS",
        "OPENROUTER_MAX_TOKENS",
        "KIMI_MODEL_MAX_COMPLETION_TOKENS",
        "KIMI_MODEL_MAX_TOKENS",
    ):
        monkeypatch.delenv(name, raising=False)
    env = io.kimi_io_env("threat-model", outputs=["THREAT_MODEL.md"])
    assert env["MIDKERNEL_KIMI_BIN"]
    assert env["BASH_ENV"] == "/dev/null"
    assert env["MIDKERNEL_NODE_READY"] == "1"
    assert env["MIDKERNEL_NODE_ID"] == "threat-model"
    assert env["OPENAI_BASE_URL"] == io.OPENROUTER_BASE_URL
    assert env["OPENROUTER_MODEL"]
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
    assert env["KIMI_MAX_TOKENS"] == "32768"
    assert env["OPENROUTER_MAX_TOKENS"] == "32768"


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
    assert "max_output_size = 32768" in text
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
    assert injected["max_tokens"] == 32768
    clamped = io.cap_openrouter_payload(
        {"max_tokens": io.UNSAFE_OPENROUTER_MAX_TOKENS, "max_completion_tokens": 200000},
        cap,
    )
    assert clamped["max_tokens"] == 32768
    assert clamped["max_completion_tokens"] == 32768
    kept = io.cap_openrouter_payload({"max_tokens": 1024}, cap)
    assert kept["max_tokens"] == 1024
    zeroed = io.cap_openrouter_payload({"max_tokens": 0}, cap)
    assert zeroed["max_tokens"] == 32768


def test_openrouter_proxy_injects_max_tokens() -> None:
    received: dict[str, object] = {}

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            received["path"] = self.path
            received["body"] = json.loads(raw.decode("utf-8"))
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
            32768, upstream_base=f"http://127.0.0.1:{int(port)}/api/v1"
        )
        base = proxy.start()
        try:
            req = urllib.request.Request(
                f"{base}/chat/completions",
                data=json.dumps({"model": "moonshotai/kimi-k3", "max_tokens": 131072}).encode(),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
            assert received["body"]["max_tokens"] == 32768
            assert received["path"].endswith("/chat/completions")
        finally:
            proxy.stop()
    finally:
        upstream.shutdown()
        upstream.server_close()


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
