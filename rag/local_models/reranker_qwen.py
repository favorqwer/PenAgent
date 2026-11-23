import asyncio
from typing import Any, Dict, List, Optional
import torch
from sentence_transformers import CrossEncoder
from utils.log_common import build_logger

logger = build_logger()

DEFAULT_RERANK_PATH = r"D:\local_models\Qwen3-Reranker-0.6B"


class QwenFP16Reranker:
    _instance = None

    def __init__(self, model_path: str = DEFAULT_RERANK_PATH, device: str = "cuda"):
        self.device = device
        self.model_path = model_path
        logger.info(f"Loading Qwen3-Reranker-0.6B from {model_path} into {device} (FP16)...")
        
        self.model = CrossEncoder(
            model_path,
            model_kwargs={"torch_dtype": torch.float16},
            device=device,
            max_length=4096
        )
        
        vram_gb = round(torch.cuda.memory_allocated() / (1024**3), 2)
        logger.success(f"Qwen3-Reranker-0.6B loaded with FP16 on {device}. VRAM allocated: {vram_gb} GB")

    @classmethod
    def get_instance(cls, model_path: str = DEFAULT_RERANK_PATH):
        if cls._instance is None:
            cls._instance = cls(model_path=model_path)
        return cls._instance

    def rerank_sync(
        self,
        query: str,
        documents: List[str],
        top_n: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        if not documents:
            return []

        # sentence-transformers CrossEncoder rank method returns [{'corpus_id': idx, 'score': val}, ...]
        ranked = self.model.rank(query, documents, top_k=top_n or len(documents), return_documents=False)
        
        results = []
        for item in ranked:
            results.append({
                "index": int(item["corpus_id"]),
                "relevance_score": float(item["score"])
            })
        return results

    async def rerank_async(
        self,
        query: str,
        documents: List[str],
        top_n: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.rerank_sync, query, documents, top_n)


def get_qwen_rerank_func(model_path: str = DEFAULT_RERANK_PATH):
    engine = QwenFP16Reranker.get_instance(model_path=model_path)

    async def _rerank(
        query: str,
        documents: List[str],
        top_n: Optional[int] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        return await engine.rerank_async(query, documents, top_n=top_n)

    return _rerank
