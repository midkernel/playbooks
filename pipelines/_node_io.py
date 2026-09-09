#!/usr/bin/env python3
"""Per-node I/O artifacts for the Midkernel Run UI (ReactFlow).

S3 layout (bucket default ``midkernel-dev-artifacts``; prefix default ``runs/``)::

    runs/<RUN_ID>/report.md                 # final assemble (unchanged; stub-refusing)
    runs/<RUN_ID>/graph.json                # live topology + status + progress + ETA
    runs/<RUN_ID>/nodes/<nodeId>/prompt.md  # exact prompt given to that node
    runs/<RUN_ID>/nodes/<nodeId>/output.md  # node output (report / RESULT / manifest / …)
    runs/<RUN_ID>/nodes/<nodeId>/meta.json  # status, model, timestamps, error, parentId?, dynamic?

``graph.json`` nodes include ``id``, ``label``, ``kind``, ``status``
(``pending|running|completed|failed``), optional ``startedAt`` / ``finishedAt`` /
``parentId`` / ``dynamic``, and artifact keys. Edges are ``{id, source, target}``.
Progress is ``{completed, total, percent, etaSeconds}``. Dynamic hunters
(``hunter-1``…``hunter-N`` from ``GOAL_COUNT``) are first-class: spawned into
``graph.json`` when the graph is initialized and again when ``surface-split``
finishes (idempotent), with edges ``surface-split → hunter-N → judge-a``.

This module is stdlib + optional ``boto3``. The helper is copied onto the
shared task disk only when a run is actually executing so in-task nodes
(``MIDKERNEL_AGENTFLOW_TARGET=local``) can upload without importing
``pipelines``. Graph emit / ``agentflow validate`` stay side-effect free:
no disk or S3 writes unless ``node_io_enabled()``. Shell nodes wrap
start/finish around the existing script. Kimi nodes set ``executable`` to
this file so the same process uploads prompt at start and output + meta on
success or failure.

Final ``report.md`` still uses the existing publish stub-refusal path.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ARTIFACTS_BUCKET = "midkernel-dev-artifacts"
ARTIFACTS_PREFIX = "runs/"
REPORT_NAME = "report.md"
GRAPH_NAME = "graph.json"
DEFAULT_GOAL_COUNT = 6
MAX_GOAL_HUNTERS = 6
IMAGE_KIMI_BIN = "/opt/midkernel/kimi.bin"
KIMI_PROBE_FLAGS = {"--version", "-V", "--help", "-h"}
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "moonshotai/kimi-k3"
OPENROUTER_KEY_PLACEHOLDER = "OVERRIDE_VIA_ENV"
NODE_STATUSES = ("pending", "running", "completed", "failed")
SAFE_NODE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

NODE_LABELS = {
    "prepare": "Prepare",
    "review": "Review",
    "publish": "Publish",
    "threat-model": "Threat model",
    "goal-author": "Goal author",
    "surface-split": "Surface split",
    "judge-a": "Judge A",
    "judge-b": "Judge B",
    "assemble": "Assemble",
}


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return default


def workdir() -> str:
    return os.environ.get("WORKDIR", "/workspace").rstrip("/") or "/workspace"


def workdir_is_writable() -> bool:
    """True when WORKDIR already exists and is writable. Never creates it."""
    try:
        path = Path(workdir())
        return path.is_dir() and os.access(path, os.W_OK)
    except OSError:
        return False


def node_io_flag() -> str:
    return env_first("MIDKERNEL_NODE_IO").lower()


def node_io_requested() -> bool:
    """True when a live run asked for I/O (flag on, or RUN_ID set)."""
    flag = node_io_flag()
    if flag in {"0", "false", "no", "off"}:
        return False
    return flag in {"1", "true", "yes", "on"} or bool(run_id())


def node_io_enabled() -> bool:
    """Whether per-node I/O may touch disk or S3.

    On only for a real run: ``MIDKERNEL_NODE_IO=1`` (ECS prepare/runtime) or
    ``RUN_ID`` is set, **and** WORKDIR exists and is writable. Explicit
    ``MIDKERNEL_NODE_IO=0`` disables writes. Graph emit and CI validate
    must stay side-effect free — this never creates ``/workspace``.
    """
    return node_io_requested() and workdir_is_writable()


def node_io_disabled_reason() -> str | None:
    """Why I/O is off, or ``None`` when enabled. Used for fail-visible logs."""
    if node_io_enabled():
        return None
    flag = node_io_flag()
    if flag in {"0", "false", "no", "off"}:
        return "MIDKERNEL_NODE_IO=off"
    if not node_io_requested():
        return "no_run_id_or_flag"
    path = workdir()
    if not Path(path).is_dir():
        return f"WORKDIR_missing:{path}"
    if not os.access(path, os.W_OK):
        return f"WORKDIR_not_writable:{path}"
    return "disabled"


def log_node_io_gate(context: str) -> None:
    """Print why I/O is off when a run was requested. Silent in CI validate."""
    reason = node_io_disabled_reason()
    if reason is None or reason == "no_run_id_or_flag":
        return
    print(
        f"node io: disabled during {context} ({reason}) "
        f"WORKDIR={workdir()!r} RUN_ID_set={bool(run_id())} "
        f"MIDKERNEL_NODE_IO={env_first('MIDKERNEL_NODE_IO')!r}",
        file=sys.stderr,
    )


def repo_dir() -> str:
    return os.path.join(workdir(), "repo")


def outputs_dir() -> str:
    return os.environ.get("OUTPUTS_DIR", "/outputs").rstrip("/") or "/outputs"


def runtime_dir() -> Path:
    return Path(workdir()) / ".midkernel"


def runtime_script_path() -> Path:
    return runtime_dir() / "node_io.py"


def source_script_path() -> Path:
    """This file, next to the playbooks graph (exists at in-task emit)."""
    return Path(__file__).resolve()


def kimi_executable() -> str:
    """Absolute path agentflow should exec for Kimi nodes.

    Always this playbooks ``_node_io.py`` (present when ``agentflow run
    pipelines/<slug>.py`` emits in-task). Do **not** point at
    ``$WORKDIR/.midkernel/node_io.py`` only — emit-time ``install_runtime``
    is a no-op when WORKDIR is missing, which left Kimi nodes executing a
    path that did not exist (PATH ``kimi`` then ran with no per-node I/O).

    Agentflow local preflight execs ``<executable> --version`` directly
    (not ``python3 <file>``). The file must be ``+x`` or the probe gets
    ``EACCES``, the run exits 1 after bootstrap, and prepare never starts.
    chmod is only applied when a live run is on (CI emit stays side-effect
    free).
    """
    path = source_script_path()
    if node_io_enabled():
        try:
            path.chmod(path.stat().st_mode | 0o111)
        except OSError as exc:
            print(f"node io: could not chmod +x {path}: {exc}", file=sys.stderr)
    return str(path)


def local_state_path() -> Path:
    return runtime_dir() / GRAPH_NAME


def lock_path() -> Path:
    return runtime_dir() / "graph.lock"


def artifacts_mirror_dir() -> Path:
    override = env_first("MIDKERNEL_IO_DIR")
    if override:
        return Path(override)
    return runtime_dir() / "artifacts"


def run_id() -> str:
    return env_first("RUN_ID")


def artifacts_bucket() -> str:
    return env_first("ARTIFACTS_BUCKET", default=ARTIFACTS_BUCKET)


def artifacts_prefix() -> str:
    prefix = env_first("ARTIFACTS_PREFIX", default=ARTIFACTS_PREFIX)
    return prefix.strip().strip("/") or "runs"


def aws_region() -> str:
    return env_first("AWS_REGION", default="us-east-1")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def safe_node_id(node_id: str) -> str:
    nid = (node_id or "").strip()
    if not SAFE_NODE_ID.match(nid):
        raise ValueError(f"unsafe node id: {node_id!r}")
    return nid


def run_key(*parts: str) -> str:
    """``runs/<RUN_ID>/...`` (or ``<RUN_ID>`` placeholder when unset)."""
    rid = run_id() or "<RUN_ID>"
    if rid != "<RUN_ID>" and not SAFE_RUN_ID.match(rid):
        raise ValueError(f"unsafe RUN_ID: {rid!r}")
    prefix = artifacts_prefix()
    tail = "/".join(part.strip("/") for part in parts if part)
    return f"{prefix}/{rid}/{tail}" if tail else f"{prefix}/{rid}"


def report_key() -> str:
    override = env_first("ARTIFACTS_KEY")
    if override:
        return override.lstrip("/")
    return run_key(REPORT_NAME)


def graph_key() -> str:
    return run_key(GRAPH_NAME)


def node_prompt_key(node_id: str) -> str:
    return run_key("nodes", safe_node_id(node_id), "prompt.md")


def node_output_key(node_id: str) -> str:
    return run_key("nodes", safe_node_id(node_id), "output.md")


def node_meta_key(node_id: str) -> str:
    return run_key("nodes", safe_node_id(node_id), "meta.json")


def node_artifact_keys(node_id: str) -> dict[str, str]:
    return {
        "prompt": node_prompt_key(node_id),
        "output": node_output_key(node_id),
        "meta": node_meta_key(node_id),
    }


def node_label(node_id: str) -> str:
    if node_id in NODE_LABELS:
        return NODE_LABELS[node_id]
    if node_id.startswith("hunter-"):
        suffix = node_id.split("-", 1)[1]
        return f"Hunter {suffix}"
    return node_id


def is_dynamic_node(node_id: str) -> bool:
    return node_id.startswith("hunter-")


def goal_count() -> int:
    raw = env_first("GOAL_COUNT", default=str(DEFAULT_GOAL_COUNT))
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_GOAL_COUNT
    return max(1, min(value, MAX_GOAL_HUNTERS))


def hunter_index(node_id: str) -> int | None:
    if not node_id.startswith("hunter-"):
        return None
    try:
        return int(node_id.split("-", 1)[1])
    except ValueError:
        return None


def content_type_for_key(key: str) -> str:
    if key.endswith(".json"):
        return "application/json"
    return "text/markdown; charset=utf-8"


def skip_s3() -> bool:
    if env_first("MIDKERNEL_IO_SKIP_S3") == "1":
        return True
    if not run_id():
        return True
    return False


def put_bytes(key: str, body: bytes, *, content_type: str | None = None) -> None:
    """Write a local mirror always; PutObject when RUN_ID is set."""
    if not node_io_enabled():
        log_node_io_gate(f"put {key}")
        return
    ctype = content_type or content_type_for_key(key)
    mirror = artifacts_mirror_dir() / key
    mirror.parent.mkdir(parents=True, exist_ok=True)
    mirror.write_bytes(body)
    if skip_s3():
        if env_first("MIDKERNEL_IO_SKIP_S3") != "1" and not run_id():
            print(
                f"node io: skipped s3://{artifacts_bucket()}/{key} (RUN_ID unset; local mirror only)",
                file=sys.stderr,
            )
        return
    try:
        import boto3
    except ImportError as exc:
        print(f"node io: boto3 missing, skipped s3://{artifacts_bucket()}/{key}: {exc}", file=sys.stderr)
        return
    try:
        boto3.client("s3", region_name=aws_region()).put_object(
            Bucket=artifacts_bucket(),
            Key=key,
            Body=body,
            ContentType=ctype,
        )
    except Exception as exc:  # noqa: BLE001 — never fail the hunt on UI upload
        print(f"node io: upload failed s3://{artifacts_bucket()}/{key}: {exc}", file=sys.stderr)


def put_text(key: str, text: str, *, content_type: str | None = None) -> None:
    put_bytes(key, text.encode("utf-8"), content_type=content_type)


def put_json(key: str, payload: Any) -> None:
    put_text(key, json.dumps(payload, indent=2, ensure_ascii=False) + "\n", content_type="application/json")


def _empty_graph() -> dict[str, Any]:
    return {
        "nodes": [],
        "edges": [],
        "progress": {"completed": 0, "total": 0, "percent": 0, "etaSeconds": None},
        "updatedAt": utc_now(),
    }


def compute_progress(nodes: list[dict[str, Any]], *, now: str | None = None) -> dict[str, Any]:
    """``completed`` is successful nodes; ``percent`` counts completed+failed as done.

    ETA is ``elapsed / completed * remaining`` when at least one node completed;
    otherwise ``null``.
    """
    total = len(nodes)
    completed = sum(1 for node in nodes if node.get("status") == "completed")
    failed = sum(1 for node in nodes if node.get("status") == "failed")
    done = completed + failed
    percent = int(round(100 * done / total)) if total else 0
    eta: int | None = None
    started: list[datetime] = []
    for node in nodes:
        parsed = parse_utc(node.get("startedAt"))
        if parsed is not None:
            started.append(parsed)
    if completed > 0 and started:
        current = parse_utc(now) or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        first = min(started)
        if first.tzinfo is None:
            first = first.replace(tzinfo=timezone.utc)
        elapsed = max(0.0, (current - first).total_seconds())
        remaining = max(0, total - done)
        eta = int(round((elapsed / completed) * remaining)) if remaining else 0
    return {
        "completed": completed,
        "total": total,
        "percent": percent,
        "etaSeconds": eta,
    }


class _NullLock:
    def close(self) -> None:
        return None


def _with_graph_lock() -> Any:
    if not node_io_enabled():
        return _NullLock()
    runtime_dir().mkdir(parents=True, exist_ok=True)
    handle = lock_path().open("a+")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def load_graph() -> dict[str, Any]:
    path = local_state_path()
    if not path.is_file():
        return _empty_graph()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_graph()
    if not isinstance(data, dict):
        return _empty_graph()
    data.setdefault("nodes", [])
    data.setdefault("edges", [])
    data.setdefault("progress", {"completed": 0, "total": 0, "percent": 0, "etaSeconds": None})
    data.setdefault("updatedAt", utc_now())
    return data


def save_graph(graph: dict[str, Any]) -> dict[str, Any]:
    graph["progress"] = compute_progress(list(graph.get("nodes") or []))
    graph["updatedAt"] = utc_now()
    if not node_io_enabled():
        return graph
    local_state_path().parent.mkdir(parents=True, exist_ok=True)
    local_state_path().write_text(json.dumps(graph, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    put_json(graph_key(), graph)
    return graph


def _upsert_node(graph: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    nid = safe_node_id(str(node["id"]))
    nodes = list(graph.get("nodes") or [])
    for index, existing in enumerate(nodes):
        if existing.get("id") == nid:
            merged = {**existing, **node, "id": nid}
            nodes[index] = merged
            graph["nodes"] = nodes
            return merged
    record = {**node, "id": nid}
    nodes.append(record)
    graph["nodes"] = nodes
    return record


def _upsert_edge(graph: dict[str, Any], source: str, target: str) -> None:
    source = safe_node_id(source)
    target = safe_node_id(target)
    edge_id = f"e-{source}-{target}"
    edges = list(graph.get("edges") or [])
    for existing in edges:
        if existing.get("id") == edge_id or (
            existing.get("source") == source and existing.get("target") == target
        ):
            return
    edges.append({"id": edge_id, "source": source, "target": target})
    graph["edges"] = edges


def graph_node_record(
    node_id: str,
    *,
    kind: str,
    status: str = "pending",
    label: str | None = None,
    parent_id: str | None = None,
    dynamic: bool | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    nid = safe_node_id(node_id)
    record: dict[str, Any] = {
        "id": nid,
        "label": label or node_label(nid),
        "kind": kind,
        "status": status if status in NODE_STATUSES else "pending",
        "dynamic": bool(is_dynamic_node(nid) if dynamic is None else dynamic),
        "artifacts": node_artifact_keys(nid),
    }
    if parent_id:
        record["parentId"] = parent_id
    elif is_dynamic_node(nid):
        record["parentId"] = "surface-split"
    if model:
        record["model"] = model
    return record


def init_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    """Create/replace live topology. Safe to call again (merges by id)."""
    if not node_io_enabled():
        return _empty_graph()
    lock = _with_graph_lock()
    try:
        graph = load_graph()
        existing = {node.get("id"): node for node in graph.get("nodes") or []}
        for spec in nodes:
            nid = spec["id"]
            prior = existing.get(nid) or {}
            record = graph_node_record(
                nid,
                kind=str(spec.get("kind") or "shell"),
                status=str(prior.get("status") or spec.get("status") or "pending"),
                label=spec.get("label"),
                parent_id=spec.get("parentId") or spec.get("parent_id"),
                dynamic=spec.get("dynamic"),
                model=spec.get("model"),
            )
            for key in ("startedAt", "finishedAt", "error"):
                if prior.get(key) and key not in spec:
                    record[key] = prior[key]
            _upsert_node(graph, record)
        for edge in edges:
            _upsert_edge(graph, str(edge["source"]), str(edge["target"]))
        return save_graph(graph)
    finally:
        lock.close()


def graph_from_pipeline(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for raw in payload.get("nodes") or []:
        nid = str(raw["id"])
        kind = "kimi" if raw.get("agent") == "kimi" else "shell"
        nodes.append(
            graph_node_record(
                nid,
                kind=kind,
                model=raw.get("model"),
            )
        )
        for dep in raw.get("depends_on") or []:
            edges.append({"id": f"e-{dep}-{nid}", "source": dep, "target": nid})
    return nodes, edges


def spawn_hunters(
    count: int,
    *,
    source: str = "surface-split",
    target: str = "judge-a",
    model: str | None = None,
) -> dict[str, Any]:
    """Add hunter-1..N as first-class dynamic nodes + edges. Idempotent."""
    if not node_io_enabled():
        return load_graph()
    n = max(1, min(int(count), MAX_GOAL_HUNTERS))
    lock = _with_graph_lock()
    try:
        graph = load_graph()
        for index in range(1, n + 1):
            nid = f"hunter-{index}"
            existing = next((node for node in graph.get("nodes") or [] if node.get("id") == nid), None)
            record = graph_node_record(
                nid,
                kind="kimi",
                status=str((existing or {}).get("status") or "pending"),
                parent_id=source,
                dynamic=True,
                model=model or (existing or {}).get("model"),
            )
            if existing:
                for key in ("startedAt", "finishedAt", "error"):
                    if existing.get(key):
                        record[key] = existing[key]
            _upsert_node(graph, record)
            _upsert_edge(graph, source, nid)
            _upsert_edge(graph, nid, target)
        return save_graph(graph)
    finally:
        lock.close()


def update_node(node_id: str, **fields: Any) -> dict[str, Any]:
    if not node_io_enabled():
        return graph_node_record(
            node_id,
            kind=str(fields.get("kind") or "kimi"),
            status=str(fields.get("status") or "pending"),
            label=fields.get("label"),
            parent_id=fields.get("parentId") or fields.get("parent_id"),
            dynamic=fields.get("dynamic"),
            model=fields.get("model"),
        )
    lock = _with_graph_lock()
    try:
        graph = load_graph()
        existing = next((node for node in graph.get("nodes") or [] if node.get("id") == node_id), None)
        if existing is None:
            record = graph_node_record(
                node_id,
                kind=str(fields.get("kind") or "kimi"),
                status=str(fields.get("status") or "pending"),
                label=fields.get("label"),
                parent_id=fields.get("parentId") or fields.get("parent_id"),
                dynamic=fields.get("dynamic"),
                model=fields.get("model"),
            )
        else:
            record = {**existing}
        for key, value in fields.items():
            if key in {"parent_id"}:
                record["parentId"] = value
            elif value is not None:
                record[key] = value
        record["artifacts"] = node_artifact_keys(node_id)
        _upsert_node(graph, record)
        if record.get("dynamic") or is_dynamic_node(node_id):
            parent = record.get("parentId") or "surface-split"
            _upsert_edge(graph, parent, node_id)
            _upsert_edge(graph, node_id, "judge-a")
        save_graph(graph)
        return record
    finally:
        lock.close()


def _search_roots() -> list[Path]:
    roots: list[Path] = []
    for raw in (os.getcwd(), repo_dir(), workdir(), outputs_dir()):
        path = Path(raw)
        if path not in roots:
            roots.append(path)
    return roots


def read_output_files(paths: list[str]) -> str:
    chunks: list[str] = []
    seen: set[Path] = set()
    for rel in paths:
        rel = rel.strip()
        if not rel:
            continue
        candidates = [Path(rel)] if Path(rel).is_absolute() else [root / rel for root in _search_roots()]
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved in seen or not resolved.is_file():
                continue
            text = resolved.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            seen.add(resolved)
            heading = rel if len(paths) > 1 else ""
            chunks.append(f"# {heading}\n\n{text}" if heading else text)
            break
    log = runtime_dir() / "nodes" / (os.environ.get("MIDKERNEL_NODE_ID") or "node") / "stdout.log"
    if not chunks and log.is_file():
        text = log.read_text(encoding="utf-8", errors="replace").strip()
        if text:
            chunks.append(text)
    return "\n\n".join(chunks).strip()


def stdout_log_path(node_id: str) -> Path:
    return runtime_dir() / "nodes" / safe_node_id(node_id) / "stdout.log"


def parse_outputs(raw: str | None) -> list[str]:
    if not raw:
        raw = env_first("MIDKERNEL_NODE_OUTPUTS")
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def write_meta(node_id: str, meta: dict[str, Any]) -> dict[str, Any]:
    payload = {key: value for key, value in meta.items() if value is not None}
    put_json(node_meta_key(node_id), payload)
    return payload


def start_node(
    node_id: str,
    *,
    prompt: str | None = None,
    kind: str = "kimi",
    label: str | None = None,
    model: str | None = None,
    parent_id: str | None = None,
    dynamic: bool | None = None,
) -> dict[str, Any]:
    nid = safe_node_id(node_id)
    if not node_io_enabled():
        log_node_io_gate(f"start {nid}")
        return {}
    started = utc_now()
    if prompt is not None:
        put_text(node_prompt_key(nid), prompt if prompt.endswith("\n") else f"{prompt}\n")
    record = update_node(
        nid,
        kind=kind,
        label=label or node_label(nid),
        status="running",
        startedAt=started,
        finishedAt=None,
        error=None,
        model=model or env_first("MIDKERNEL_NODE_MODEL", "OPENROUTER_MODEL", "MODEL") or None,
        parentId=parent_id or env_first("MIDKERNEL_NODE_PARENT") or None,
        dynamic=is_dynamic_node(nid) if dynamic is None else dynamic,
    )
    write_meta(
        nid,
        {
            "status": "running",
            "model": record.get("model"),
            "startedAt": started,
            "finishedAt": None,
            "error": None,
            "parentId": record.get("parentId"),
            "dynamic": bool(record.get("dynamic")),
        },
    )
    return record


def finish_node(
    node_id: str,
    *,
    status: str,
    error: str | None = None,
    outputs: list[str] | None = None,
    output_text: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    nid = safe_node_id(node_id)
    if not node_io_enabled():
        log_node_io_gate(f"finish {nid}")
        return {}
    if status not in {"completed", "failed"}:
        status = "failed"
    finished = utc_now()
    text = output_text if output_text is not None else read_output_files(outputs or parse_outputs(None))
    if text:
        put_text(node_output_key(nid), text if text.endswith("\n") else f"{text}\n")
    else:
        # Still upload so the UI can open a file on failure.
        put_text(node_output_key(nid), "")
    existing = next((node for node in load_graph().get("nodes") or [] if node.get("id") == nid), {})
    started = existing.get("startedAt")
    record = update_node(
        nid,
        status=status,
        finishedAt=finished,
        error=error or None,
        model=model or existing.get("model") or env_first("MIDKERNEL_NODE_MODEL") or None,
    )
    write_meta(
        nid,
        {
            "status": status,
            "model": record.get("model"),
            "startedAt": started,
            "finishedAt": finished,
            "error": error or None,
            "parentId": record.get("parentId"),
            "dynamic": bool(record.get("dynamic")),
        },
    )
    if nid == "surface-split" and status == "completed":
        spawn_hunters(goal_count())
    return record


def install_runtime() -> Path | None:
    dest = runtime_script_path()
    if not node_io_enabled():
        log_node_io_gate("install_runtime")
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).read_text(encoding="utf-8")
    dest.write_text(source, encoding="utf-8")
    dest.chmod(0o755)
    install_kimi_shim()
    return dest


def bootstrap_run_io(payload: dict[str, Any]) -> dict[str, Any]:
    """Install the helper and seed graph.json + prompts when a run is live.

    No-op (no disk / S3) unless ``node_io_enabled()`` — graph emit and
    ``agentflow validate`` stay side-effect free.
    """
    if not node_io_enabled():
        log_node_io_gate("bootstrap_run_io")
        return _empty_graph()
    install_runtime()
    nodes, edges = graph_from_pipeline(payload)
    graph = init_graph(nodes, edges)
    hunters = [node["id"] for node in nodes if is_dynamic_node(node["id"])]
    if hunters:
        spawn_hunters(len(hunters))
    for raw in payload.get("nodes") or []:
        prompt = raw.get("prompt")
        if isinstance(prompt, str):
            put_text(node_prompt_key(str(raw["id"])), prompt if prompt.endswith("\n") else f"{prompt}\n")
    return graph


def pinned_kimi_bin() -> str:
    """Preferred real kimi-cli. Never the PATH report.md wrapper."""
    return env_first("MIDKERNEL_KIMI_BIN", default=IMAGE_KIMI_BIN) or IMAGE_KIMI_BIN


def kimi_shim_dir() -> Path:
    return runtime_dir() / "bin"


def is_report_md_wrapper(path: str | Path) -> bool:
    """True when *path* is the runner PATH ``kimi`` that requires report.md."""
    candidate = Path(path)
    try:
        if not candidate.is_file():
            return False
        text = candidate.read_text(encoding="utf-8", errors="replace")[:8000]
    except OSError:
        return False
    return "midkernel-publish-report" in text or "KIMI_REAL_BIN" in text


def kimi_share_dir() -> Path:
    """cwd-stable Kimi config dir (review/threat-model cwd is ``$WORKDIR/repo``)."""
    override = env_first("KIMI_SHARE_DIR")
    if override:
        return Path(override)
    return Path(workdir()) / ".midkernel" / "kimi"


def kimi_config_file() -> Path:
    return kimi_share_dir() / "config.toml"


def normalize_openrouter_slug(raw: str | None, *, default: str = DEFAULT_OPENROUTER_MODEL) -> str:
    slug = (raw or "").strip()
    if slug.startswith("openrouter/"):
        slug = slug[len("openrouter/") :]
    if "/" not in slug:
        return default
    return slug


def resolve_openrouter_api_key() -> str:
    """Emit-time env, then files prepare/runner write (HOME or WORKDIR)."""
    key = env_first("OPENROUTER_API_KEY", "OPENAI_API_KEY", "KIMI_API_KEY")
    if key:
        return key
    home = env_first("HOME")
    candidates = []
    if home:
        candidates.append(Path(home) / ".midkernel-openrouter")
    candidates.append(Path(workdir()) / ".midkernel-openrouter")
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text
    return ""


def render_kimi_openrouter_config(model: str | None = None, *, api_key: str | None = None) -> str:
    slug = normalize_openrouter_slug(
        model or env_first("MIDKERNEL_NODE_MODEL", "OPENROUTER_MODEL", "MODEL"),
        default=DEFAULT_OPENROUTER_MODEL,
    )
    key = (api_key if api_key is not None else resolve_openrouter_api_key()) or OPENROUTER_KEY_PLACEHOLDER
    return "\n".join(
        [
            'default_model = "midkernel"',
            "default_thinking = false",
            "default_yolo = true",
            "",
            "[providers.openrouter]",
            'type = "openai_legacy"',
            f'base_url = "{OPENROUTER_BASE_URL}"',
            f'api_key = "{key}"',
            "",
            "[models.midkernel]",
            'provider = "openrouter"',
            f'model = "{slug}"',
            "max_context_size = 262144",
            "",
        ]
    )


def write_kimi_openrouter_config(model: str | None = None, *, api_key: str | None = None) -> Path:
    """Write OpenRouter config where kimi.bin will find it after BASH_ENV skip."""
    path = kimi_config_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_kimi_openrouter_config(model, api_key=api_key), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    home = env_first("HOME")
    if home:
        home_cfg = Path(home) / ".kimi" / "config.toml"
        try:
            home_cfg.parent.mkdir(parents=True, exist_ok=True)
            if home_cfg.resolve() != path.resolve():
                home_cfg.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
                home_cfg.chmod(0o600)
        except OSError:
            pass
    return path


def is_kimi_config_path(value: str) -> bool:
    """True when ``--config`` is a filesystem path, not inline TOML."""
    text = (value or "").strip()
    if not text or "\n" in text or text.startswith("default_model"):
        return False
    try:
        return Path(text).is_file()
    except OSError:
        return False


def ensure_kimi_config_argv(argv: list[str], *, model: str | None = None) -> tuple[list[str], Path]:
    """agentflow appends ``extra_args``; ``--config`` must be a real file path."""
    path = write_kimi_openrouter_config(model)
    out = list(argv)
    if "--config" in out:
        index = out.index("--config")
        if index + 1 < len(out) and is_kimi_config_path(out[index + 1]):
            return out, Path(out[index + 1])
        if index + 1 < len(out):
            out[index + 1] = str(path)
        else:
            out.append(str(path))
    else:
        out.extend(["--config", str(path)])
    return out, path


def openrouter_passthrough_env(*, model: str | None = None) -> dict[str, str]:
    """Env kimi.bin needs when runner ``prepare_node`` is skipped (BASH_ENV=/dev/null).

    Agentflow ``KimiAdapter`` merges only provider.env + node.env (not a fresh
    isolated env), then LocalRunner overlays that on ``os.environ``. Still put
    OpenRouter keys on the node so emit_goal hunters/threat-model match review.
    """
    slug = normalize_openrouter_slug(
        model or env_first("MIDKERNEL_NODE_MODEL", "OPENROUTER_MODEL", "MODEL"),
        default=DEFAULT_OPENROUTER_MODEL,
    )
    env = {
        "OPENAI_BASE_URL": OPENROUTER_BASE_URL,
        "OPENROUTER_MODEL": slug,
        "KIMI_SHARE_DIR": str(kimi_share_dir()),
        "WORKDIR": workdir(),
    }
    key = resolve_openrouter_api_key()
    if key:
        env["OPENROUTER_API_KEY"] = key
        env["OPENAI_API_KEY"] = key
        env["KIMI_API_KEY"] = key
        env["MOONSHOT_API_KEY"] = key
    home = env_first("HOME")
    if home:
        env["HOME"] = home
    return env


def graph_runtime_env() -> dict[str, str]:
    """Env that keeps in-task nodes off the runner ``BASH_ENV`` / PATH kimi hooks.

    LocalRunner copies ``os.environ`` then overlays node env, so these win
    on the already-published runner image (no new ECR build required).
    Strings only — no disk writes. Safe to embed in emitted PipelineSpec.

    ``BASH_ENV=/dev/null`` + ``MIDKERNEL_NODE_READY=1`` skip runner
    ``prepare_node`` (avoids re-clone). OpenRouter config must therefore
    travel on the node env / ``$WORKDIR/.midkernel/kimi/config.toml``.
    """
    bin_path = pinned_kimi_bin()
    shim = str(kimi_shim_dir())
    path = os.environ.get("PATH", "")
    parts = [part for part in path.split(os.pathsep) if part and part != shim]
    env = {
        "BASH_ENV": "/dev/null",
        "MIDKERNEL_NODE_READY": "1",
        "MIDKERNEL_NODE_IO": "1",
        "MIDKERNEL_KIMI_BIN": bin_path,
        "KIMI_REAL_BIN": bin_path,
        "PATH": os.pathsep.join([shim, *parts]) if parts else shim,
    }
    env.update(openrouter_passthrough_env())
    return env


def shell_io_env(node_id: str) -> dict[str, str]:
    """Env for prepare/publish so ``bash -c`` does not source node-env.sh."""
    env = graph_runtime_env()
    env["MIDKERNEL_NODE_ID"] = safe_node_id(node_id)
    env["MIDKERNEL_NODE_KIND"] = "shell"
    return env


def install_kimi_shim() -> Path | None:
    """``$WORKDIR/.midkernel/bin/kimi`` execs ``MIDKERNEL_KIMI_BIN``, not PATH kimi."""
    if not node_io_enabled():
        return None
    dest_dir = kimi_shim_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "kimi"
    bin_path = pinned_kimi_bin()
    dest.write_text(
        "#!/bin/sh\n"
        "# Graph shim: never the runner PATH wrapper (report.md after every node).\n"
        f'REAL="${{MIDKERNEL_KIMI_BIN:-{bin_path}}}"\n'
        'if [ ! -x "$REAL" ]; then\n'
        '  echo "node io: MIDKERNEL_KIMI_BIN missing or not executable: $REAL" >&2\n'
        "  exit 127\n"
        "fi\n"
        'exec "$REAL" "$@"\n',
        encoding="utf-8",
    )
    dest.chmod(0o755)
    return dest


def wrap_shell_script(
    node_id: str,
    script: str,
    *,
    kind: str = "shell",
    label: str | None = None,
    outputs: list[str] | None = None,
    model: str | None = None,
    parent_id: str | None = None,
    dynamic: bool | None = None,
) -> str:
    """Prefix/suffix a shell node so it uploads prompt + output + meta itself."""
    nid = safe_node_id(node_id)
    outputs = outputs or []
    label_text = label or node_label(nid)
    dyn = "1" if (is_dynamic_node(nid) if dynamic is None else dynamic) else ""
    parent = parent_id or ("surface-split" if is_dynamic_node(nid) else "")
    prompt_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    helper_src = str(source_script_path())
    kimi_bin = pinned_kimi_bin()
    return f"""
set -euo pipefail
# Shared-disk contract: WORKDIR must match the task volume (image default /workspace).
export WORKDIR="${{WORKDIR:-/workspace}}"
export OUTPUTS_DIR="${{OUTPUTS_DIR:-/outputs}}"
# Runner image BASH_ENV=/opt/midkernel/node-env.sh clones into /workspace
# (non-empty after bootstrap) and installs a publish-report EXIT trap.
# Nested bash in this script must not re-enter that hook.
export BASH_ENV=/dev/null
export MIDKERNEL_NODE_READY=1
export MIDKERNEL_KIMI_BIN="${{MIDKERNEL_KIMI_BIN:-{kimi_bin}}}"
export KIMI_REAL_BIN="${{KIMI_REAL_BIN:-$MIDKERNEL_KIMI_BIN}}"
# Create the shared disk *before* the I/O gate. Prepare used to mkdir only
# inside the inner script, so the wrap saw a missing WORKDIR and skipped
# helper install for the whole node (and left Kimi executable missing).
mkdir -p "$WORKDIR" "$OUTPUTS_DIR" "$WORKDIR/.midkernel" || true
IO_DIR="$WORKDIR/.midkernel"
IO="$IO_DIR/node_io.py"
NODE_ID={_bash_single(nid)}
export MIDKERNEL_NODE_ID="$NODE_ID"
export MIDKERNEL_NODE_KIND={_bash_single(kind)}
export MIDKERNEL_NODE_LABEL={_bash_single(label_text)}
export MIDKERNEL_NODE_OUTPUTS={_bash_single(",".join(outputs))}
export MIDKERNEL_NODE_MODEL={_bash_single(model or "")}
export MIDKERNEL_NODE_PARENT={_bash_single(parent)}
export MIDKERNEL_NODE_DYNAMIC={_bash_single(dyn)}
LOG="/dev/null"
PROMPT_FILE=""
# Disk / S3 I/O after mkdir unless explicitly off (CI / MIDKERNEL_NODE_IO=0).
NODE_IO=1
case "${{MIDKERNEL_NODE_IO:-}}" in
  0|false|no|off|FALSE|NO|OFF) NODE_IO=0 ;;
esac
export MIDKERNEL_NODE_IO="${{MIDKERNEL_NODE_IO:-1}}"
if [ "$NODE_IO" = "1" ] && [ -d "$WORKDIR" ] && [ -w "$WORKDIR" ]; then
  export MIDKERNEL_NODE_IO=1
  mkdir -p "$IO_DIR/nodes/$NODE_ID" "$IO_DIR/bin"
  LOG="$IO_DIR/nodes/$NODE_ID/stdout.log"
  PROMPT_FILE="$IO_DIR/nodes/$NODE_ID/prompt.md"
  python3 -c "import base64,pathlib; pathlib.Path('$PROMPT_FILE').write_bytes(base64.b64decode('{prompt_b64}'))"
  if [ ! -f "$IO" ]; then
    SRC={_bash_single(helper_src)}
    if [ -f "$SRC" ]; then
      cp "$SRC" "$IO"
    fi
  fi
  if [ -f "$IO" ]; then
    chmod 755 "$IO" || echo "node io: chmod +x $IO failed" >&2
  fi
  if [ -f "$IO" ]; then
    python3 "$IO" start --node "$NODE_ID" --kind {_bash_single(kind)} --label {_bash_single(label_text)} --prompt-file "$PROMPT_FILE" \
      || echo "node io: start failed for $NODE_ID (exit $?) — continuing node body" >&2
  else
    echo "node io: helper missing at $IO (src={_bash_single(helper_src)}); skipping per-node upload" >&2
  fi
else
  echo "node io: wrap skipped for $NODE_ID (NODE_IO=$NODE_IO WORKDIR=$WORKDIR writable=$([ -w "$WORKDIR" ] && echo yes || echo no) RUN_ID=${{RUN_ID:-unset}})" >&2
fi
set +e
(
set -euo pipefail
{script}
) 2>&1 | tee "$LOG"
STATUS=${{PIPESTATUS[0]}}
set -e
if [ -n "$PROMPT_FILE" ] && [ -f "$IO" ]; then
  if [ "$STATUS" -eq 0 ]; then
    python3 "$IO" finish --node "$NODE_ID" --status completed \
      || echo "node io: finish/completed failed for $NODE_ID (exit $?)" >&2
  else
    python3 "$IO" finish --node "$NODE_ID" --status failed --error "exit $STATUS" \
      || echo "node io: finish/failed upload failed for $NODE_ID (exit $?)" >&2
  fi
fi
if [ "$STATUS" -ne 0 ]; then
  echo "node io: $NODE_ID exited $STATUS" >&2
  exit "$STATUS"
fi
""".strip()


def _bash_single(value: str) -> str:
    return "'" + (value or "").replace("'", "'\"'\"'") + "'"


def kimi_io_env(
    node_id: str,
    *,
    outputs: list[str] | None = None,
    label: str | None = None,
    model: str | None = None,
    parent_id: str | None = None,
    dynamic: bool | None = None,
) -> dict[str, str]:
    nid = safe_node_id(node_id)
    env = graph_runtime_env()
    env.update(openrouter_passthrough_env(model=model))
    env.update(
        {
            "MIDKERNEL_NODE_ID": nid,
            "MIDKERNEL_NODE_KIND": "kimi",
            "MIDKERNEL_NODE_LABEL": label or node_label(nid),
            "MIDKERNEL_NODE_OUTPUTS": ",".join(outputs or []),
            "MIDKERNEL_NODE_IO": "1",
        }
    )
    if model:
        env["MIDKERNEL_NODE_MODEL"] = model
        env["OPENROUTER_MODEL"] = normalize_openrouter_slug(model)
    if parent_id or is_dynamic_node(nid):
        env["MIDKERNEL_NODE_PARENT"] = parent_id or "surface-split"
    if is_dynamic_node(nid) if dynamic is None else dynamic:
        env["MIDKERNEL_NODE_DYNAMIC"] = "1"
    return env


def real_kimi_bin() -> str:
    """Resolve the real kimi-cli. Never PATH ``kimi`` (report.md wrapper)."""
    candidates: list[Path] = []
    pinned = env_first("MIDKERNEL_KIMI_BIN")
    if pinned:
        candidates.append(Path(pinned))
    candidates.append(Path(IMAGE_KIMI_BIN))
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        if is_report_md_wrapper(candidate):
            print(f"node io: skipping report.md kimi wrapper at {candidate}", file=sys.stderr)
            continue
        return str(candidate)
    print(
        "node io: no real kimi binary "
        f"(MIDKERNEL_KIMI_BIN={env_first('MIDKERNEL_KIMI_BIN')!r} "
        f"default={IMAGE_KIMI_BIN}; PATH kimi is the runner report.md wrapper)",
        file=sys.stderr,
    )
    return IMAGE_KIMI_BIN


def _prompt_from_kimi_argv(argv: list[str]) -> str:
    for flag in ("-p", "--prompt"):
        if flag in argv:
            index = argv.index(flag)
            if index + 1 < len(argv):
                return argv[index + 1]
    return ""


def _is_kimi_probe(argv: list[str]) -> bool:
    """Agentflow local preflight execs ``<executable> --version`` (or --help)."""
    return bool(argv) and argv[0] in KIMI_PROBE_FLAGS


def _synthetic_kimi_probe(argv: list[str]) -> int:
    """Doctor-friendly stdout when the image bin is not on this host (CI)."""
    if any(flag in argv for flag in ("--help", "-h")):
        print("Usage: kimi [options]")
        print(
            "midkernel node_io wrap — forwards to MIDKERNEL_KIMI_BIN "
            "or /opt/midkernel/kimi.bin"
        )
    else:
        print("kimi (midkernel-node-io)")
    return 0


def _forward_kimi_probe(argv: list[str]) -> int:
    """Succeed ``--version`` / ``--help`` without node I/O (CI / doctor)."""
    binary = real_kimi_bin()
    if Path(binary).is_file() and os.access(binary, os.X_OK) and not is_report_md_wrapper(binary):
        print(f"node io: kimi probe → {binary} {' '.join(argv)}", file=sys.stderr)
        try:
            return int(subprocess.run([binary, *argv], check=False).returncode)
        except OSError as exc:
            print(f"node io: kimi probe failed ({binary}): {exc}", file=sys.stderr)
    elif is_report_md_wrapper(binary):
        print(f"node io: refusing PATH kimi wrapper for probe: {binary}", file=sys.stderr)
    else:
        print(f"node io: kimi probe synthetic (no real bin at {binary})", file=sys.stderr)
    return _synthetic_kimi_probe(argv)


def wrap_kimi(argv: list[str]) -> int:
    if _is_kimi_probe(argv):
        return _forward_kimi_probe(argv)
    node_id = env_first("MIDKERNEL_NODE_ID") or "kimi"
    prompt = _prompt_from_kimi_argv(argv)
    if node_io_enabled():
        install_runtime()
    start_node(
        node_id,
        prompt=prompt,
        kind=env_first("MIDKERNEL_NODE_KIND", default="kimi") or "kimi",
        label=env_first("MIDKERNEL_NODE_LABEL") or None,
        model=env_first("MIDKERNEL_NODE_MODEL") or None,
        parent_id=env_first("MIDKERNEL_NODE_PARENT") or None,
        dynamic=env_first("MIDKERNEL_NODE_DYNAMIC") == "1" or None,
    )
    binary = real_kimi_bin()
    if is_report_md_wrapper(binary):
        error = f"refusing PATH kimi wrapper: {binary} (set MIDKERNEL_KIMI_BIN={IMAGE_KIMI_BIN})"
        print(f"node io: {error}", file=sys.stderr)
        finish_node(node_id, status="failed", error=error)
        return 1
    model = env_first("MIDKERNEL_NODE_MODEL", "OPENROUTER_MODEL", "MODEL") or None
    argv, config_path = ensure_kimi_config_argv(argv, model=model)
    child_env = os.environ.copy()
    child_env.update(openrouter_passthrough_env(model=model))
    key = resolve_openrouter_api_key()
    if key:
        child_env["OPENROUTER_API_KEY"] = key
        child_env["OPENAI_API_KEY"] = key
        child_env["KIMI_API_KEY"] = key
        child_env["MOONSHOT_API_KEY"] = key
    child_env["KIMI_SHARE_DIR"] = str(config_path.parent)
    print(
        f"node io: kimi OpenRouter config={config_path} "
        f"model={child_env.get('OPENROUTER_MODEL', '')} "
        f"key_set={'yes' if key else 'no'} bin={binary}",
        file=sys.stderr,
    )
    command = [binary, *argv]
    error = None
    try:
        result = subprocess.run(command, check=False, env=child_env)
        code = int(result.returncode)
    except Exception as exc:  # noqa: BLE001
        code = 1
        error = str(exc)
        print(f"node io: kimi wrapper failed ({binary}): {exc}", file=sys.stderr)
    status = "completed" if code == 0 else "failed"
    if code != 0 and not error:
        error = f"exit {code}"
    finish_node(node_id, status=status, error=error)
    return code


def _cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="node_io")
    sub = parser.add_subparsers(dest="cmd", required=True)

    start = sub.add_parser("start")
    start.add_argument("--node", default=env_first("MIDKERNEL_NODE_ID"))
    start.add_argument("--kind", default=env_first("MIDKERNEL_NODE_KIND", default="shell"))
    start.add_argument("--label", default=env_first("MIDKERNEL_NODE_LABEL") or None)
    start.add_argument("--model", default=env_first("MIDKERNEL_NODE_MODEL") or None)
    start.add_argument("--parent", default=env_first("MIDKERNEL_NODE_PARENT") or None)
    start.add_argument("--prompt-file", default="")
    start.add_argument("--prompt", default="")
    start.add_argument("--dynamic", action="store_true")

    finish = sub.add_parser("finish")
    finish.add_argument("--node", default=env_first("MIDKERNEL_NODE_ID"))
    finish.add_argument("--status", required=True, choices=("completed", "failed"))
    finish.add_argument("--error", default="")
    finish.add_argument("--outputs", default=env_first("MIDKERNEL_NODE_OUTPUTS"))
    finish.add_argument("--output-file", default="")

    init = sub.add_parser("init")
    init.add_argument("--pipeline-json", required=True)

    spawn = sub.add_parser("spawn-hunters")
    spawn.add_argument("--count", type=int, default=0)
    spawn.add_argument("--from", dest="source", default="surface-split")
    spawn.add_argument("--to", dest="target", default="judge-a")

    args = parser.parse_args(argv)
    if args.cmd == "start":
        prompt = args.prompt
        if args.prompt_file:
            prompt = Path(args.prompt_file).read_text(encoding="utf-8", errors="replace")
        start_node(
            args.node,
            prompt=prompt,
            kind=args.kind,
            label=args.label,
            model=args.model,
            parent_id=args.parent,
            dynamic=True if args.dynamic else None,
        )
        return 0
    if args.cmd == "finish":
        output_text = None
        if args.output_file:
            output_text = Path(args.output_file).read_text(encoding="utf-8", errors="replace")
        finish_node(
            args.node,
            status=args.status,
            error=args.error or None,
            outputs=parse_outputs(args.outputs),
            output_text=output_text,
        )
        return 0
    if args.cmd == "init":
        payload = json.loads(Path(args.pipeline_json).read_text(encoding="utf-8"))
        bootstrap_run_io(payload)
        return 0
    if args.cmd == "spawn-hunters":
        spawn_hunters(args.count or goal_count(), source=args.source, target=args.target)
        return 0
    return 2


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"start", "finish", "init", "spawn-hunters"}:
        return _cli(argv)
    return wrap_kimi(argv)


if __name__ == "__main__":
    raise SystemExit(main())
