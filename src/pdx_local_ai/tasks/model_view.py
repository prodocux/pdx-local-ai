"""Model-facing text for one assembled context packet.

This function does not read the catalog, write state, or call ``ContextAssembler.assemble``.
"""

from __future__ import annotations

from typing import Any


def _label(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    if "\\" in value or ":/" in value or value.startswith("/"):
        return ""
    return value


def render_model_view(packet: dict[str, Any]) -> str:
    """Render evidence windows as plain text with citation and hop labels."""
    volatile = packet.get("volatile") if isinstance(packet, dict) else None
    if not isinstance(volatile, dict):
        return ""
    entities: dict[Any, str] = {}
    hops = volatile.get("hops")
    if isinstance(hops, list):
        for hop in hops:
            if isinstance(hop, dict):
                entities[hop.get("hop_id")] = _label(hop.get("entity"))
    windows = volatile.get("evidence_windows")
    if not isinstance(windows, list):
        return ""
    blocks: list[str] = []
    for window in windows:
        if not isinstance(window, dict):
            continue
        text = window.get("text")
        blocks.append("\n".join((
            f"citation_id: {_label(window.get('citation_id'))}",
            f"source_version_id: {_label(window.get('source_version_id'))}",
            f"entity: {entities.get(window.get('hop_id'), '')}",
            text if isinstance(text, str) else "",
        )))
    return "\n\n".join(blocks)


def _hop_no(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return 0
    if isinstance(value, int):
        return value
    sign = value[0] if value[:1] in "+-" else ""
    digits = value[1:] if sign else value
    if not digits.isdigit():
        return 0
    return int(value)


def _hop_id_key(value: Any) -> str:
    return value if isinstance(value, str) else ""


def render_hop_chain(packet: dict[str, Any]) -> str:
    """Render hops in order with parent entity and that hop's window text."""
    volatile = packet.get("volatile") if isinstance(packet, dict) else None
    if not isinstance(volatile, dict):
        return ""
    hops = volatile.get("hops")
    if not isinstance(hops, list) or not hops:
        return ""
    usable = [hop for hop in hops if isinstance(hop, dict)]
    ordered = sorted(usable, key=lambda hop: (_hop_no(hop.get("hop_no")), _hop_id_key(hop.get("hop_id"))))
    by_id: dict[Any, dict[str, Any]] = {}
    for hop in usable:
        hop_id = hop.get("hop_id")
        if hop_id is not None and hop_id not in by_id:
            by_id[hop_id] = hop
    windows = volatile.get("evidence_windows")
    window_list = windows if isinstance(windows, list) else []
    blocks: list[str] = []
    for hop in ordered:
        hop_id = hop.get("hop_id")
        parent = by_id.get(hop.get("parent_hop_id")) if hop.get("parent_hop_id") is not None else None
        parent_entity = _label(parent.get("entity")) if isinstance(parent, dict) else ""
        lines = [
            f"hop_no: {_hop_no(hop.get('hop_no'))}",
            f"parent_entity: {parent_entity}",
            f"entity: {_label(hop.get('entity'))}",
        ]
        if hop_id is not None:
            for window in window_list:
                if isinstance(window, dict) and window.get("hop_id") == hop_id:
                    text = window.get("text")
                    lines.append(text if isinstance(text, str) else "")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)
