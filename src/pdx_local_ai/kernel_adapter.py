from __future__ import annotations

import base64
import hashlib
import tempfile
from collections.abc import Callable
from importlib import metadata
from pathlib import Path
from typing import Any
from uuid import uuid4

from .versions import ENGINE_VERSION, KERNEL_VERSION


class _InProcessKernelBridge:
    """Product adapter glue over public Kernel APIs; no parser logic lives here."""

    def __init__(self, artifact_root: Path) -> None:
        from prodocux_kernel.rendering.derived_store import DerivedArtifactStore

        self.store = DerivedArtifactStore(artifact_root)
        self.responses: list[dict[str, Any]] = []

    def projection_capabilities(self) -> dict[str, Any]:
        from api.main import projection_capabilities

        return projection_capabilities().model_dump(exclude_none=True)

    def continue_projection(self, **request: Any) -> dict[str, Any]:
        if request["format_name"] != "pdf":
            raise ValueError("Local AI in-process bridge currently routes PDF only")
        from prodocux_kernel.intake import extract_pdf_continuable_projection

        response = extract_pdf_continuable_projection(
            base64.b64decode(request["document_b64"], validate=True),
            cursor=request.get("continuation_descriptor"),
            max_pages=int(request["range_limit"]),
            ocr_requested=bool(request.get("ocr_requested", False)),
        )
        self.responses.append(response)
        return response

    def store_derived(
        self, *, output_name: str, content_b64: str, media_type: str,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        return dict(
            self.store.store(
                output_name=output_name,
                media_type=media_type,
                payload=base64.b64decode(content_b64, validate=True),
                sha256=sha256,
            )
        )


class KernelAdapter:
    required_version = KERNEL_VERSION
    required_engine_version = ENGINE_VERSION

    def __init__(
        self,
        *,
        max_blocks: int = 200,
        engine_database: str | Path | None = None,
        engine_artifact_root: str | Path | None = None,
        after_range: Callable[[int, dict[str, Any]], None] | None = None,
    ) -> None:
        observed = metadata.version("prodocux")
        if observed != self.required_version:
            raise RuntimeError(f"prodocux {self.required_version} required, got {observed}")
        from prodocux_kernel.rendering.service import execute_continuable_projection

        self._extract_range = execute_continuable_projection
        self.max_blocks = max_blocks
        self.after_range = after_range
        observed_engine = metadata.version("pdx-artifact-engine")
        if observed_engine != self.required_engine_version:
            raise RuntimeError(
                f"pdx-artifact-engine {self.required_engine_version} required, "
                f"got {observed_engine}"
            )
        from pdx_adapter_prodocux.verified_projection import validate_kernel_projection
        from pdx_artifact_engine.continuable_extraction import (
            ContinuableExtractionService,
            ContinuableExtractionStore,
        )

        if engine_database is None:
            engine_database = Path(tempfile.gettempdir()) / "pdx-local-ai-engine.sqlite3"
        if engine_artifact_root is None:
            engine_artifact_root = Path(tempfile.gettempdir()) / "pdx-local-ai-artifacts"
        self._engine_store = ContinuableExtractionStore(Path(engine_database))
        self._kernel_bridge = _InProcessKernelBridge(Path(engine_artifact_root))
        self._engine = ContinuableExtractionService(
            self._engine_store,
            kernel=self._kernel_bridge,
            projection_validator=validate_kernel_projection,
        )

    def close(self) -> None:
        self._engine_store.close()

    def extract(self, filename: str, payload: bytes) -> dict[str, Any]:
        suffix = Path(filename).suffix.casefold()
        if suffix == ".docx":
            return self._extract_docx(filename, payload)
        if suffix == ".pdf":
            return self._extract_pdf(filename, payload)
        from .document_dispatch import dispatch_document

        result = dispatch_document(filename, payload)
        if result.get("kernel_version") != self.required_version:
            raise RuntimeError("Kernel result version mismatch")
        return result

    def _extract_pdf(self, filename: str, payload: bytes) -> dict[str, Any]:
        from pdx_artifact_core import create_continuable_extraction

        source_sha256 = hashlib.sha256(payload).hexdigest()
        operation_id = f"local-pdf-{uuid4()}"
        initial = create_continuable_extraction(
            operation_id=operation_id,
            source_artifact_digest=source_sha256,
            source_sha256=source_sha256,
            media_type="application/pdf",
            parser_contract_name="prodocux_pdf_page_projection_v1",
            parser_contract_version="1",
            capability_digest="0" * 64,
            first_range={"continuation_descriptor": None},
            limits={"ranges": 10_000, "blocks": 1_000_000, "bytes": 100_000_000, "retries": 3},
        )
        del initial["capability_digest"]
        self._engine.create_from_kernel(initial)
        document_b64 = base64.b64encode(payload).decode("ascii")
        self._kernel_bridge.responses.clear()
        state = self._engine.get(operation_id)
        for range_index in range(10_000):
            state = self._engine.execute_next(
                operation_id,
                expected_revision=int(state["revision"]),
                idempotency_key=f"{operation_id}:{state['revision']}",
                format_name="pdf",
                document_b64=document_b64,
                document_filename=filename,
                range_limit=50,
            )
            if self.after_range is not None:
                self.after_range(range_index, self._kernel_bridge.responses[-1])
            if state["state"] != "pending":
                break
        else:
            raise RuntimeError("PDF continuation exceeded the range safety bound")

        responses = list(self._kernel_bridge.responses)
        if not responses:
            raise RuntimeError("Kernel returned no PDF projection ranges")
        pages = [page for response in responses for page in response["pages"]]
        omissions = sorted(
            {
                item
                for response in responses
                for item in response["coverage"]["omitted_content_classes"]
            }
        )
        receipt = self._engine.receipt(operation_id)
        text_items = [
            {
                "id": f"pdf-page-{page['page_number']}",
                "type": "page_text",
                "text": page["text"],
                "source_locator": f"page:{page['page_number']}",
            }
            for page in pages
        ]
        return {
            "schema_version": "pdx_local_kernel_projection_aggregate_v1",
            "kernel_version": self.required_version,
            "source_sha256": source_sha256,
            "parser_contract": responses[-1]["parser_contract"],
            "coverage": {
                "disposition": receipt["coverage"],
                "warnings": [],
                "omitted_content_classes": omissions,
            },
            "counts": {
                "processed_through_range_end": {"pages": len(pages)},
                "known_total": {
                    "pages": responses[-1]["coverage"]["known_total_pages"]
                },
            },
            "ocr_disposition": receipt["ocr_disposition"],
            "ranges": [dict(response["range"]) for response in responses],
            "text_items": text_items,
            "engine_receipt": receipt,
        }

    def _extract_docx(self, filename: str, payload: bytes) -> dict[str, Any]:
        cursor: dict[str, Any] | None = None
        expected_start = 0
        source_sha256: str | None = None
        text_items: list[dict[str, Any]] = []
        seen_item_ids: set[str] = set()
        ranges: list[dict[str, int]] = []
        final: dict[str, Any] | None = None

        for range_index in range(10_000):
            result = self._extract_range(
                filename,
                payload,
                cursor=cursor,
                max_blocks=self.max_blocks,
            )
            if result.get("kernel_version") != self.required_version:
                raise RuntimeError("Kernel result version mismatch")
            observed_source = str(result["source"]["sha256"])
            if source_sha256 is None:
                source_sha256 = observed_source
            elif observed_source != source_sha256:
                raise RuntimeError("Kernel continuation source changed")
            range_info = result["range"]
            if range_info["start"] != expected_start:
                raise RuntimeError("Kernel continuation range is not contiguous")
            if range_info["end_exclusive"] <= range_info["start"]:
                raise RuntimeError("Kernel continuation range made no progress")
            if range_info["returned_blocks"] > range_info["requested_max_blocks"]:
                raise RuntimeError("Kernel continuation exceeded requested bound")
            for item in result["text_items"]:
                item_id = str(item["id"])
                if item_id in seen_item_ids:
                    raise RuntimeError("Kernel continuation repeated a text item identity")
                seen_item_ids.add(item_id)
                text_items.append(dict(item))
            ranges.append(
                {
                    "start": int(range_info["start"]),
                    "end_exclusive": int(range_info["end_exclusive"]),
                }
            )
            if self.after_range is not None:
                self.after_range(range_index, result)
            expected_start = int(range_info["end_exclusive"])
            cursor = result["next_cursor"]
            final = result
            if cursor is None:
                break
            if cursor["next_block"] != expected_start:
                raise RuntimeError("Kernel next range descriptor is not contiguous")
        else:
            raise RuntimeError("Kernel continuation exceeded the range safety bound")

        assert final is not None and source_sha256 is not None
        return {
            "schema_version": "pdx_local_kernel_projection_aggregate_v1",
            "kernel_version": self.required_version,
            "source_sha256": source_sha256,
            "parser_contract": final["parser_contract"],
            "coverage": final["coverage"],
            "counts": final["counts"],
            "ocr_disposition": final["ocr_disposition"],
            "ranges": ranges,
            "text_items": text_items,
        }
