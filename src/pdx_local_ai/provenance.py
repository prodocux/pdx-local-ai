from __future__ import annotations

from importlib import metadata
from typing import Any

from .versions import ENGINE_VERSION, KERNEL_VERSION


def create_index_provenance(
    *, attempt_id: str, source_version_id: str, projection_id: str,
    source_sha256: str, projection_sha256: str, generated_at: str,
    parser_contract: str = "", archive_profile: str = "not_applicable",
    catalog_revision: str = "",
) -> dict[str, Any]:
    observed = metadata.version("pdx-artifact-engine")
    if observed != ENGINE_VERSION:
        raise RuntimeError(f"pdx-artifact-engine {ENGINE_VERSION} required, got {observed}")
    observed_kernel = metadata.version("prodocux")
    if observed_kernel != KERNEL_VERSION:
        raise RuntimeError(f"prodocux {KERNEL_VERSION} required, got {observed_kernel}")
    from pdx_artifact_core import create_provenance_bundle

    source = f"entity:source:{source_version_id}"
    projection = f"entity:projection:{projection_id}"
    activity = f"activity:index:{attempt_id}"
    agent = "agent:pdx-local-ai-gate0"
    attributes: dict[str, Any] = {
        "engine_version": observed,
        "kernel_version": observed_kernel,
        "parser_contract": parser_contract or "",
        "archive_profile": archive_profile or "not_applicable",
        "catalog_revision": catalog_revision or "",
    }
    return create_provenance_bundle(
        bundle_id=f"bundle:{projection_id}",
        source_run_id=attempt_id,
        generated_at=generated_at,
        entities=[
            {"id": source, "type": "source_version", "digest": source_sha256},
            {"id": projection, "type": "document_projection", "digest": projection_sha256},
        ],
        activities=[{"id": activity, "type": "kernel_extract"}],
        agents=[{"id": agent, "type": "software", "attributes": attributes}],
        relations=[
            {"type": "used", "subject_id": activity, "object_id": source},
            {"type": "wasGeneratedBy", "subject_id": projection, "object_id": activity},
            {"type": "wasAssociatedWith", "subject_id": activity, "object_id": agent},
            {"type": "wasDerivedFrom", "subject_id": projection, "object_id": source},
        ],
    )
