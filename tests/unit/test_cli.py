import io
import json
from pathlib import Path

import pytest

from ida_re_mcp.cli import ApplicationLike, main
from ida_re_mcp.domain.base import JsonObject


def _wire_result(request_id: object) -> bytes:
    return (
        json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "result": {"ok": True}},
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


class _Protocol:
    async def handle_line(self, line: bytes | str) -> bytes | None:
        assert isinstance(line, bytes)
        request = json.loads(line)
        return _wire_result(request["id"])


class _Application:
    def __init__(self, *, healthy: bool = True, doctor_error: Exception | None = None) -> None:
        self.protocol = _Protocol()
        self.healthy = healthy
        self.doctor_error = doctor_error
        self.closed = False
        self.gc_apply: list[bool] = []

    async def doctor(self) -> tuple[bool, JsonObject]:
        if self.doctor_error is not None:
            raise self.doctor_error
        return self.healthy, {"healthy": self.healthy, "checks": ["runtime", "worker"]}

    async def gc(self, *, apply: bool) -> JsonObject:
        self.gc_apply.append(apply)
        return {"applied": apply, "reclaimed_bytes": 0}

    async def aclose(self) -> None:
        self.closed = True


class _Factory:
    def __init__(self, application: _Application) -> None:
        self.application = application
        self.config_paths: list[Path | None] = []

    def __call__(self, config_path: Path | None) -> ApplicationLike:
        self.config_paths.append(config_path)
        return self.application


def test_serve_writes_only_protocol_messages_and_closes() -> None:
    application = _Application()
    factory = _Factory(application)
    stdout = io.BytesIO()
    stderr = io.StringIO()

    exit_code = main(
        ["serve"],
        application_factory=factory,
        stdin=io.BytesIO(b'{"jsonrpc":"2.0","id":5}\n'),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert json.loads(stdout.getvalue())["id"] == 5
    assert len(stdout.getvalue().splitlines()) == 1
    assert stderr.getvalue() == ""
    assert application.closed


def test_doctor_uses_explicit_config_and_nonzero_for_unhealthy() -> None:
    application = _Application(healthy=False)
    factory = _Factory(application)
    stdout = io.BytesIO()

    exit_code = main(
        ["doctor", "--config", "C:/runtime/current.toml"],
        application_factory=factory,
        stdin=io.BytesIO(),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert exit_code == 1
    assert factory.config_paths == [Path("C:/runtime/current.toml")]
    assert json.loads(stdout.getvalue())["healthy"] is False
    assert application.closed


@pytest.mark.parametrize(
    ("flag", "expected_apply"),
    [("--dry-run", False), ("--apply", True)],
)
def test_gc_requires_an_explicit_mode(flag: str, expected_apply: bool) -> None:
    application = _Application()
    stdout = io.BytesIO()

    exit_code = main(
        ["gc", flag],
        application_factory=_Factory(application),
        stdin=io.BytesIO(),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert exit_code == 0
    assert application.gc_apply == [expected_apply]
    assert json.loads(stdout.getvalue())["applied"] is expected_apply
    assert application.closed


def test_gc_without_mode_is_usage_error() -> None:
    with pytest.raises(SystemExit) as raised:
        main(
            ["gc"],
            application_factory=_Factory(_Application()),
            stdin=io.BytesIO(),
            stdout=io.BytesIO(),
            stderr=io.StringIO(),
        )

    assert raised.value.code == 2


def test_command_failure_is_stderr_only_and_still_closes() -> None:
    application = _Application(doctor_error=RuntimeError("worker\nfailed"))
    stdout = io.BytesIO()
    stderr = io.StringIO()

    exit_code = main(
        ["doctor"],
        application_factory=_Factory(application),
        stdin=io.BytesIO(),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == b""
    assert "worker failed" in stderr.getvalue()
    assert application.closed
