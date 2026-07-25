from __future__ import annotations

import argparse
import threading
from collections.abc import Mapping

import pytest

from ida_re_mcp.worker import runtime
from ida_re_mcp.worker.errors import WorkerError


class _FakeIdaPro:
    def __init__(self, *, open_result: int = 0) -> None:
        self.open_result = open_result
        self.open_calls: list[tuple[str, bool]] = []
        self.open_thread_ids: list[int] = []
        self.close_calls: list[bool] = []

    def open_database(
        self,
        file_name: str,
        run_auto_analysis: bool,
        args: str | None = None,
        enable_history: bool = False,
    ) -> int:
        del args, enable_history
        self.open_calls.append((file_name, run_auto_analysis))
        self.open_thread_ids.append(threading.get_ident())
        return self.open_result

    def close_database(self, save: bool = True) -> None:
        self.close_calls.append(save)


class _FakeHandler:
    def __init__(self) -> None:
        self.bindings: list[threading.Event | None] = []
        self.executions: list[tuple[str, dict[str, object]]] = []
        self.execution_thread_ids: list[int] = []
        self.poll_count = 0
        self.close_count = 0

    def bind_cancellation(self, cancellation: threading.Event | None) -> None:
        self.bindings.append(cancellation)

    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
        self.executions.append((operation, dict(input)))
        self.execution_thread_ids.append(threading.get_ident())
        return {"operation": operation}

    def poll(self) -> None:
        self.poll_count += 1

    def close(self) -> None:
        self.close_count += 1


def _arguments() -> argparse.Namespace:
    return argparse.Namespace(
        kind="bootstrap",
        sample="C:/samples/native.exe",
        checkout=None,
        revision=None,
        allow_attach=False,
    )


def test_ida_session_handler_opens_lazily_on_first_owner_thread_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idapro = _FakeIdaPro()
    worker = _FakeHandler()

    def load_idapro(_name: str) -> _FakeIdaPro:
        return idapro

    def build_handler(_arguments: argparse.Namespace) -> _FakeHandler:
        return worker

    monkeypatch.setattr(runtime.importlib, "import_module", load_idapro)
    monkeypatch.setattr(runtime, "_build_handler", build_handler)

    session = runtime.IdaSessionHandler(_arguments())
    owner_thread_id = threading.get_ident()
    cancellation = threading.Event()
    session.bind_cancellation(cancellation)
    session.poll()

    assert idapro.open_calls == []
    assert worker.bindings == []
    assert session.execute("workspace.bootstrap", {"staging_path": "C:/staging"}) == {
        "operation": "workspace.bootstrap"
    }
    assert idapro.open_calls == [("C:/samples/native.exe", True)]
    assert idapro.open_thread_ids == [owner_thread_id]
    assert worker.execution_thread_ids == [owner_thread_id]
    assert worker.bindings == [cancellation]

    session.execute("workspace.bootstrap", {"staging_path": "C:/staging-2"})
    session.poll()
    session.bind_cancellation(None)
    session.close()
    session.close()

    assert len(idapro.open_calls) == 1
    assert worker.poll_count == 1
    assert worker.bindings[-1] is None
    assert worker.close_count == 1
    assert idapro.close_calls == [False]


def test_ida_session_handler_returns_structured_open_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idapro = _FakeIdaPro(open_result=7)

    def load_idapro(_name: str) -> _FakeIdaPro:
        return idapro

    def unexpected_build(_arguments: argparse.Namespace) -> object:
        pytest.fail("打开数据库失败后不得创建 worker handler")

    monkeypatch.setattr(runtime.importlib, "import_module", load_idapro)
    monkeypatch.setattr(runtime, "_build_handler", unexpected_build)
    session = runtime.IdaSessionHandler(_arguments())

    with pytest.raises(WorkerError) as raised:
        session.execute("workspace.bootstrap", {})

    assert raised.value.code == "ida_open_failed"
    assert raised.value.details == {"ida_result": 7, "kind": "bootstrap"}
    session.close()
    assert idapro.close_calls == []


def test_ida_session_handler_closes_database_when_handler_construction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idapro = _FakeIdaPro()

    def load_idapro(_name: str) -> _FakeIdaPro:
        return idapro

    monkeypatch.setattr(runtime.importlib, "import_module", load_idapro)

    def fail_build(_arguments: argparse.Namespace) -> object:
        raise RuntimeError("handler construction failed")

    monkeypatch.setattr(runtime, "_build_handler", fail_build)
    session = runtime.IdaSessionHandler(_arguments())

    with pytest.raises(RuntimeError, match="handler construction failed"):
        session.execute("workspace.bootstrap", {})

    assert idapro.close_calls == [False]
    session.close()
    assert idapro.close_calls == [False]
