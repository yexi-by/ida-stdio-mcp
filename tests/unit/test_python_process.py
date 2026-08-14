from __future__ import annotations

import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import cast

import mcp

import ida_re_mcp
from ida_re_mcp.supervisor._python_process import prepare_python_process_launch


def test_python_process_launch_tracks_real_venv_process() -> None:
    executable, environment = prepare_python_process_launch(os.environ)
    probe = (
        "import ida_re_mcp,json,mcp,os,sys,sysconfig;"
        "print(json.dumps({"
        "'pid':os.getpid(),"
        "'executable':sys.executable,"
        "'prefix':sys.prefix,"
        "'base_prefix':sys.base_prefix,"
        "'purelib':sysconfig.get_path('purelib'),"
        "'package':ida_re_mcp.__file__,"
        "'mcp':mcp.__file__"
        "},ensure_ascii=False))"
    )
    process = subprocess.Popen(
        [executable, "-c", probe],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 0, stderr
    result = cast(dict[str, object], json.loads(stdout))
    assert result == {
        "pid": process.pid,
        "executable": sys.executable,
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "purelib": sysconfig.get_path("purelib"),
        "package": str(Path(ida_re_mcp.__file__).resolve()),
        "mcp": str(Path(mcp.__file__).resolve()),
    }
