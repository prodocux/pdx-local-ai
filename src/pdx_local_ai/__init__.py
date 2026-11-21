"""PDX Local AI Gate 0 catalog and lexical retrieval."""

from .canonical_memory import (
    propose_canonical_from_working_memory,
    publish_canonical_proposal,
    record_canonical_human_decision,
    withdraw_canonical_knowledge,
)
from .catalog import Catalog, RetrievalLimits
from .governed_recall import recall_governed_memory
from .hybrid import HybridRetrieval
from .layered_memory import LayeredMemoryStore
from .maintenance import Maintenance
from .memory import EmbeddingAdapter, MemoryStore
from .retrieval_orchestration import orchestrate_retrieval
from .vector_generation import VectorGenerationStore, VectorNormTooSmall

__all__ = [
    "Catalog",
    "EmbeddingAdapter",
    "HybridRetrieval",
    "LayeredMemoryStore",
    "Maintenance",
    "MemoryStore",
    "RetrievalLimits",
    "propose_canonical_from_working_memory",
    "publish_canonical_proposal",
    "orchestrate_retrieval",
    "recall_governed_memory",
    "record_canonical_human_decision",
    "VectorGenerationStore",
    "VectorNormTooSmall",
    "withdraw_canonical_knowledge",
]
