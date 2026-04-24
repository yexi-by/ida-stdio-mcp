"""日志系统单元测试。"""

from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from loguru import logger

from ida_stdio_mcp.config import LoggingConfig
from ida_stdio_mcp.logging import configure_logging, log_tool_call_exception, log_tool_call_finished, log_tool_call_started
from ida_stdio_mcp.models import JsonObject
from ida_stdio_mcp.result import build_error_info, build_result


class LoggingTests(unittest.TestCase):
    """覆盖 MCP 调用日志的文件落盘与失败可观测性。"""

    def test_configure_logging_uses_one_daily_file(self) -> None:
        """同一天多次初始化应追加到同一个日志文件。"""
        with TemporaryDirectory() as temp_dir:
            try:
                directory = Path(temp_dir)
                log_path = configure_logging(LoggingConfig(level="INFO", directory=directory))
                second_log_path = configure_logging(LoggingConfig(level="INFO", directory=directory))

                expected_name = f"ida-stdio-mcp-{datetime.now().strftime('%Y%m%d')}.log"
                self.assertEqual(log_path, second_log_path)
                self.assertEqual(log_path.name, expected_name)
                self.assertTrue(log_path.exists())
            finally:
                logger.remove()

    def test_tool_success_call_writes_start_and_finish(self) -> None:
        """成功工具调用必须记录开始、结束、参数、状态与耗时。"""
        with TemporaryDirectory() as temp_dir:
            try:
                log_path = configure_logging(LoggingConfig(level="INFO", directory=Path(temp_dir)))

                log_tool_call_started(
                    "open_binary",
                    1,
                    {"path": "D:/samples/sample.exe", "session_id": "sample"},
                )
                log_tool_call_finished(
                    "open_binary",
                    1,
                    {"path": "D:/samples/sample.exe", "session_id": "sample"},
                    build_result(status="ok", source="runtime.open_binary", data={"session_id": "sample"}),
                    duration_ms=12.345,
                )
                logger.complete()

                text = log_path.read_text(encoding="utf-8")
                self.assertIn("工具调用开始：open_binary", text)
                self.assertIn("工具调用完成：open_binary status=ok duration=12.3ms", text)
                self.assertIn("event=tool_call_start", text)
                self.assertIn("event=tool_call_finish", text)
                self.assertIn("path", text)
                self.assertIn("duration_ms=12.345", text)
            finally:
                logger.remove()

    def test_tool_error_call_writes_attention_event(self) -> None:
        """失败工具调用必须额外记录醒目的错误事件。"""
        with TemporaryDirectory() as temp_dir:
            try:
                log_path = configure_logging(LoggingConfig(level="INFO", directory=Path(temp_dir)))

                error = cast(JsonObject, build_error_info(code="file_not_found", message="样本不存在"))
                log_tool_call_finished(
                    "open_binary",
                    "req-1",
                    {"path": "D:/missing.exe"},
                    build_result(status="error", source="runtime.open_binary", data=None, error=error),
                    duration_ms=20.0,
                )
                logger.complete()

                text = log_path.read_text(encoding="utf-8")
                self.assertIn("ERROR", text)
                self.assertIn("event=tool_call_attention", text)
                self.assertIn("样本不存在", text)
            finally:
                logger.remove()

    def test_tool_exception_writes_traceback_to_file(self) -> None:
        """未知异常必须在文件日志中保留完整 traceback。"""
        with TemporaryDirectory() as temp_dir:
            try:
                log_path = configure_logging(LoggingConfig(level="INFO", directory=Path(temp_dir)))

                try:
                    raise RuntimeError("模拟未知异常")
                except RuntimeError as exc:
                    log_tool_call_exception("summarize_binary", "req-2", {}, exc, duration_ms=5.0)
                logger.complete()

                text = log_path.read_text(encoding="utf-8")
                self.assertIn("工具调用异常：summarize_binary", text)
                self.assertIn("Traceback", text)
                self.assertIn("RuntimeError: 模拟未知异常", text)
            finally:
                logger.remove()
