from rag_firewall.detectors.tools import scan_tools


def test_empty_allowlist_allows_everything():
    payload = {"tools": [{"type": "function", "function": {"name": "send_email"}}]}
    result = scan_tools(payload, allowlist=[])
    assert result.blocked is False


def test_disallowed_openai_tool_is_blocked():
    payload = {"tools": [{"type": "function", "function": {"name": "send_email"}}]}
    result = scan_tools(payload, allowlist=["search_docs"])
    assert result.blocked is True
    assert "send_email" in result.rejected_tools


def test_anthropic_style_tool_is_inspected():
    payload = {"tools": [{"name": "delete_user", "input_schema": {}}]}
    result = scan_tools(payload, allowlist=["search_docs"])
    assert result.blocked is True
    assert "delete_user" in result.rejected_tools


def test_legacy_functions_array():
    payload = {"functions": [{"name": "exec_shell"}]}
    result = scan_tools(payload, allowlist=["search_docs"])
    assert result.blocked is True


def test_allowed_tool_passes():
    payload = {"tools": [{"type": "function", "function": {"name": "search_docs"}}]}
    result = scan_tools(payload, allowlist=["search_docs"])
    assert result.blocked is False
