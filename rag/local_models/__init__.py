"""Local GPU Model Adapters (FP8 Embedding + FP16 Reranker)."""
from .embedding_qwen import get_qwen_embedding_func
from .reranker_qwen import get_qwen_rerank_func

__all__ = ["get_qwen_embedding_func", "get_qwen_rerank_func"]
