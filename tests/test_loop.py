"""
Integration test for the agentic loop. No live Ollama, Metasploit, or target required.
Patches the ollama.Client.chat call to feed canned model responses so the loop can
be driven deterministically.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
import orchestrator


def _make_tool_call_message(name: str, arguments: dict):
    """Build a fake ollama response message that contains one tool call."""
    tc = MagicMock()
    tc.function.name = name
    tc.function.arguments = arguments

    msg = MagicMock()
    msg.tool_calls = [tc]
    msg.content = ""

    resp = MagicMock()
    resp.message = msg
    return resp


def _make_complete_response(summary: str = "done", findings: list | None = None):
    return _make_tool_call_message(
        "complete",
        {"summary": summary, "findings": findings or []},
    )


class TestLoopCompletesImmediately(unittest.TestCase):
    """Model calls complete() on the very first turn."""

    @patch("ollama.Client.chat")
    def test_loop_exits_on_complete(self, mock_chat):
        mock_chat.return_value = _make_complete_response("nothing to do")

        result = orchestrator.run(config.AUTHORIZED_SCOPE[0])

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["summary"], "nothing to do")
        mock_chat.assert_called_once()


class TestLoopScopeEnforcement(unittest.TestCase):
    """The loop refuses to start against an out-of-scope target."""

    def test_rejects_out_of_scope_target(self):
        result = orchestrator.run("10.0.0.99")
        self.assertEqual(result["status"], "error")
        self.assertIn("not in authorized scope", result["error"])


class TestLoopToolDispatch(unittest.TestCase):
    """Model calls scan_ports then complete()."""

    @patch("ollama.Client.chat")
    @patch("tools.recon.scan_ports")
    def test_scan_then_complete(self, mock_scan, mock_chat):
        mock_scan.return_value = {
            "status":     "ok",
            "target":     config.AUTHORIZED_SCOPE[0],
            "open_ports": [{"port": 22, "service": "ssh", "version": "OpenSSH 7.4"}],
        }

        target = config.AUTHORIZED_SCOPE[0]
        mock_chat.side_effect = [
            _make_tool_call_message("scan_ports", {"target": target}),
            _make_complete_response("found ssh on 22"),
        ]

        result = orchestrator.run(target)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["summary"], "found ssh on 22")
        self.assertEqual(mock_chat.call_count, 2)
        mock_scan.assert_called_once()


class TestLoopUnknownTool(unittest.TestCase):
    """Model hallucinates a tool name; dispatcher returns error; loop continues."""

    @patch("ollama.Client.chat")
    def test_unknown_tool_returns_error_and_continues(self, mock_chat):
        target = config.AUTHORIZED_SCOPE[0]
        mock_chat.side_effect = [
            _make_tool_call_message("nonexistent_tool", {"foo": "bar"}),
            _make_complete_response("recovered from bad tool call"),
        ]

        result = orchestrator.run(target)

        self.assertEqual(result["status"], "complete")
        # The tool result message with the error should be in the chat history
        call_args_list = mock_chat.call_args_list
        second_call_messages = call_args_list[1][1]["messages"]
        tool_results = [m for m in second_call_messages if m["role"] == "tool"]
        self.assertTrue(any("unknown tool" in m["content"] for m in tool_results))


class TestLoopMaxIterations(unittest.TestCase):
    """Loop exits with limit_reached when the model never calls complete()."""

    @patch("ollama.Client.chat")
    def test_limit_reached(self, mock_chat):
        # Model keeps calling memory_query forever
        target = config.AUTHORIZED_SCOPE[0]
        mock_chat.return_value = _make_tool_call_message(
            "memory_query", {"category": "tried_module"}
        )

        original_max = config.MAX_ITERATIONS
        config.MAX_ITERATIONS = 3
        try:
            result = orchestrator.run(target)
        finally:
            config.MAX_ITERATIONS = original_max

        self.assertEqual(result["status"], "limit_reached")


class TestLoopOutOfScopeToolCall(unittest.TestCase):
    """Model tries to scan an out-of-scope IP; dispatcher blocks it."""

    @patch("ollama.Client.chat")
    def test_scope_blocked_at_dispatch(self, mock_chat):
        target = config.AUTHORIZED_SCOPE[0]
        mock_chat.side_effect = [
            _make_tool_call_message("scan_ports", {"target": "1.2.3.4"}),
            _make_complete_response("blocked"),
        ]

        result = orchestrator.run(target)

        self.assertEqual(result["status"], "complete")
        call_args_list = mock_chat.call_args_list
        second_call_messages = call_args_list[1][1]["messages"]
        tool_results = [m for m in second_call_messages if m["role"] == "tool"]
        self.assertTrue(any("not in authorized scope" in m["content"] for m in tool_results))


class TestLoopTextResponseNudge(unittest.TestCase):
    """Model returns plain text instead of a tool call; loop nudges it back."""

    @patch("ollama.Client.chat")
    def test_text_response_gets_nudge(self, mock_chat):
        target = config.AUTHORIZED_SCOPE[0]

        text_msg = MagicMock()
        text_msg.tool_calls = None
        text_msg.content = "I am thinking about what to do next."
        text_resp = MagicMock()
        text_resp.message = text_msg

        mock_chat.side_effect = [
            text_resp,
            _make_complete_response("done after nudge"),
        ]

        result = orchestrator.run(target)

        self.assertEqual(result["status"], "complete")
        # The nudge message should appear in the second call's message history
        second_messages = mock_chat.call_args_list[1][1]["messages"]
        user_msgs = [m for m in second_messages if m["role"] == "user"]
        self.assertTrue(any("call a tool" in m["content"].lower() for m in user_msgs))


if __name__ == "__main__":
    unittest.main()
