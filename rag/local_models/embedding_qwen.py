import asyncio
import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer
from torchao.quantization.quant_api import Float8WeightOnlyConfig, quantize_
from lightrag.utils import EmbeddingFunc
from utils.log_common import build_logger

logger = build_logger()

DEFAULT_EMBED_PATH = r"D:\local_models\Qwen3-Embedding-4B"
QUERY_INSTRUCTION = "Instruct: Given a cybersecurity attack surface, retrieve relevant multi-step attack chains and exploit preconditions\nQuery: "


def last_token_pool(last_hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
    left_padding = (attention_mask[:, -1].sum() == attention_mask.shape[0])
    if left_padding:
        return last_hidden_states[:, -1]
    else:
        sequence_lengths = attention_mask.sum(dim=1) - 1
        batch_size = last_hidden_states.shape[0]
        return last_hidden_states[torch.arange(batch_size, device=last_hidden_states.device), sequence_lengths]


class QwenFP8Embedding:
    _instance = None

    def __init__(self, model_path: str = DEFAULT_EMBED_PATH, device: str = "cuda"):
        self.device = device
        self.model_path = model_path
        logger.info(f"Loading Qwen3-Embedding-4B from {model_path} into {device} (FP8)...")
        
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, padding_side="left")
        
        # Load base model in bfloat16, then quantize linear layers to FP8 on Blackwell architecture
        base_model = AutoModel.from_pretrained(model_path, torch_dtype=torch.bfloat16, device_map=device)
        quantize_(base_model, Float8WeightOnlyConfig())
        torch.cuda.empty_cache()
        self.model = base_model.eval()
        
        vram_gb = round(torch.cuda.memory_allocated() / (1024**3), 2)
        logger.success(f"Qwen3-Embedding-4B loaded with FP8 on {device}. VRAM allocated: {vram_gb} GB")

    @classmethod
    def get_instance(cls, model_path: str = DEFAULT_EMBED_PATH):
        if cls._instance is None:
            cls._instance = cls(model_path=model_path)
        return cls._instance

    def embed_sync(self, texts: list[str], is_query: bool = False, batch_size: int = 32) -> np.ndarray:
        if not texts:
            return np.empty((0, 2560), dtype=np.float32)

        formatted = [f"{QUERY_INSTRUCTION}{t}" if is_query else t for t in texts]
        all_embeddings = []

        with torch.no_grad():
            for i in range(0, len(formatted), batch_size):
                batch_texts = formatted[i : i + batch_size]
                inputs = self.tokenizer(
                    batch_texts,
                    padding=True,
                    truncation=True,
                    max_length=8192,
                    return_tensors="pt"
                ).to(self.device)

                outputs = self.model(**inputs)
                pooled = last_token_pool(outputs.last_hidden_state, inputs["attention_mask"])
                # Normalize embeddings for cosine similarity
                normalized = torch.nn.functional.normalize(pooled, p=2, dim=1)
                all_embeddings.append(normalized.cpu().to(torch.float32).numpy())

        return np.vstack(all_embeddings)

    async def embed_async(self, texts: list[str], is_query: bool = False) -> np.ndarray:
        # Offload GPU tensor operations to thread pool
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.embed_sync, texts, is_query)


def get_qwen_embedding_func(model_path: str = DEFAULT_EMBED_PATH) -> EmbeddingFunc:
    engine = QwenFP8Embedding.get_instance(model_path=model_path)

    async def _embed(texts: list[str], context: str = "document") -> np.ndarray:
        return await engine.embed_async(texts, is_query=(context == "query"))

    return EmbeddingFunc(
        embedding_dim=2560,
        max_token_size=8192,
        func=_embed,
        model_name="Qwen3-Embedding-4B-FP8",
        supports_asymmetric=True,
    )
