"""Caller-side text for one published-memory turn.

These functions do not read the catalog, write state, call recall, or call
``ContextAssembler.assemble``. The tool result must not be appended to the question.
"""

from __future__ import annotations

from typing import Any

MEMORY_USER_NOTE = "已發布筆記不在這則訊息裡，只能經由工具 recall_published_memory 取得。"


def memory_user_message(question: str) -> str:
    """Return the fixed note, a newline, and the question."""
    if not isinstance(question, str) or not 1 <= len(question) <= 500:
        raise ValueError("question must be a str of length 1 to 500")
    return MEMORY_USER_NOTE + "\n" + question


def memory_tool_result(items: list[Any]) -> str:
    """Format published L2 items. Other layers and non-strings are omitted."""
    if not isinstance(items, list):
        return ""
    blocks: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("layer") != "l2" or item.get("approval") != "published":
            continue
        content = item.get("content")
        if not isinstance(content, str):
            continue
        blocks.append("layer: l2\napproval: published\n" + content)
    return "\n\n".join(blocks)
