from __future__ import annotations

import hashlib

import pytest

from pdx_local_ai.validation import ContractError, validate_citation_against_block


def test_astral_code_point_offsets_are_not_utf16_units():
    text = "A😀B"
    quote = "😀"
    citation = {
        "block_instance_id": "block",
        "projection_id": "projection",
        "quote_start": 1,
        "quote_end": 2,
        "quote_normalization": "unicode_nfc_codepoint_v1",
        "quoted_text_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
    }
    assert validate_citation_against_block(
        citation, {"block_instance_id": "block", "projection_id": "projection", "text": text}
    ) == quote


def test_unpaired_surrogate_fails_closed():
    citation = {
        "block_instance_id": "block",
        "projection_id": "projection",
        "quote_start": 0,
        "quote_end": 1,
        "quote_normalization": "unicode_nfc_codepoint_v1",
        "quoted_text_sha256": "0" * 64,
    }
    with pytest.raises(ContractError, match="surrogate"):
        validate_citation_against_block(
            citation,
            {"block_instance_id": "block", "projection_id": "projection", "text": "\ud800"},
        )
