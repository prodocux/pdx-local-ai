"""Host admission wrapper. Catalog dispatch lives in document_dispatch."""

from .document_dispatch import MEDIA, dispatch_document

__all__ = ["MEDIA", "ExpandedFormats"]


class ExpandedFormats:
    media = {key: value for key, value in MEDIA.items() if key not in {".txt", ".md", ".markdown", ".log", ".tsv"}}

    def __init__(self, *, enabled=False, conversion=False, ocr=False, record_store=None):
        if enabled is not True:
            raise ValueError("EXPANDED_FORMATS_DISABLED")
        if (conversion or ocr) and record_store is None:
            raise ValueError("PERSISTENT_BACKEND_RECORDS_REQUIRED")
        self.conversion, self.ocr, self.record_store = conversion, ocr, record_store

    def __call__(self, filename, raw):
        return dispatch_document(
            filename, raw, conversion=self.conversion, ocr=self.ocr, record_store=self.record_store,
        )
