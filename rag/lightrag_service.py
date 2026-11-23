import asyncio
from pathlib import Path
from typing import Optional
import uuid

from config.config import Configs
from lightrag import LightRAG, QueryParam
from lightrag.llm.openai import openai_complete_if_cache
from lightrag.prompt import PROMPTS
from rag.local_models import get_qwen_embedding_func, get_qwen_rerank_func
from utils.log_common import build_logger

logger = build_logger()

DEFAULT_STORE_DIR = Path(r"C:\Users\Favor\Desktop\PenAgent\data\lightrag_store")
_SESSION_ID = str(uuid.uuid4())

# Cyber Attack Chain Specific Entities
SECURITY_ENTITY_TYPES = [
    "Service",
    "Version",
    "Vulnerability",
    "Prerequisite",
    "ExploitAction",
    "Impact"
]

# Custom extraction prompt extension for cyber security entities
SECURITY_ENTITY_GUIDANCE = (
    "Entity Types:\n"
    "- Service: Network or web services, frameworks, servers (e.g. Apache, OpenSSH, Redis, Tomcat, Jenkins, MySQL).\n"
    "- Version: Version strings or identifiers (e.g. 2.4.49, 9.0.43, < 5.0.5).\n"
    "- Vulnerability: CVE identifiers, vulnerability names, or flaw categories (e.g. CVE-2021-41773, Ghostcat, Path Traversal, S2-045).\n"
    "- Prerequisite: Conditions required to exploit (e.g. Port 8009 open, default credentials admin:admin, writable /root/.ssh, SUID permission).\n"
    "- ExploitAction: Specific offensive tactics or execution methods (e.g. PUT request upload, Gopher injection, War file deployment, find SUID execution).\n"
    "- Impact: Gained access or effect (e.g. Arbitrary File Read, webshell access, www-data command execution, Root shell privilege).\n\n"
    "Relationships must accurately connect: Service -> VULNERABLE_TO -> Vulnerability -> REQUIRES -> Prerequisite -> EXPLOITED_BY -> ExploitAction -> LEADS_TO -> Impact."
)


async def opencode_llm_complete(
    prompt: str,
    system_prompt: Optional[str] = None,
    history_messages: Optional[list] = None,
    **kwargs
) -> str:
    """Async LLM completion wrapper using PenAgent configured opencode/deepseek gateway."""
    return await openai_complete_if_cache(
        model=Configs.llm_config.llm_model_name,
        prompt=prompt,
        system_prompt=system_prompt,
        history_messages=history_messages,
        base_url=Configs.llm_config.base_url,
        api_key=Configs.llm_config.api_key,
        extra_headers={"x-opencode-session": _SESSION_ID},
        **kwargs
    )


class PenAgentLightRAG:
    _instance = None

    def __init__(self, store_dir: Path = DEFAULT_STORE_DIR):
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initializing LightRAG instance at {self.store_dir}...")

        # Inject domain-specific entity extraction guidance
        PROMPTS["default_entity_types_guidance"] = SECURITY_ENTITY_GUIDANCE

        self.rag = LightRAG(
            working_dir=str(self.store_dir),
            embedding_func=get_qwen_embedding_func(),
            rerank_model_func=get_qwen_rerank_func(),
            llm_model_func=opencode_llm_complete,
            addon_params={"entity_types": SECURITY_ENTITY_TYPES},
            chunk_token_size=800,
            chunk_overlap_token_size=150,
            top_k=25,
            chunk_top_k=15,
            embedding_batch_num=32,
            embedding_func_max_async=4,
            default_embedding_timeout=180,
            auto_manage_storages_states=True
        )
        logger.success("PenAgentLightRAG initialized successfully with FP8 Embedding & FP16 Reranker.")

        self._initialized = False

    async def ensure_initialized(self):
        if not self._initialized:
            await self.rag.initialize_storages()
            self._initialized = True

    @classmethod
    def get_instance(cls, store_dir: Path = DEFAULT_STORE_DIR) -> "PenAgentLightRAG":
        if cls._instance is None:
            cls._instance = cls(store_dir=store_dir)
        return cls._instance

    async def ainsert(self, text: str):
        """Insert a single text document into the knowledge graph."""
        await self.ensure_initialized()
        await self.rag.ainsert(text)

    def insert(self, text: str):
        """Sync wrapper for inserting text."""
        asyncio.run(self.ainsert(text))

    async def aquery_attack_chain(self, target_facts: str, mode: str = "hybrid") -> str:
        """Query multi-hop attack paths and exploitation strategies for the Phase Planner."""
        await self.ensure_initialized()
        query = (
            f"Given the following target asset fingerprints and discovered facts:\n"
            f"{target_facts}\n\n"
            f"Based on the knowledge graph, what are the confirmed and potential multi-step attack chains, "
            f"vulnerability prerequisites, and sequential exploitation paths for these services? "
            f"Provide a structured, prioritized tactical attack tree for penetration planning."
        )
        param = QueryParam(mode=mode, top_k=15)
        return await self.rag.aquery(query, param=param)

    def query_attack_chain(self, target_facts: str, mode: str = "hybrid") -> str:
        """Sync wrapper for planner node usage."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # In nested event loop, use run_in_executor
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, self.aquery_attack_chain(target_facts, mode=mode)).result()
            return loop.run_until_complete(self.aquery_attack_chain(target_facts, mode=mode))
        except RuntimeError:
            return asyncio.run(self.aquery_attack_chain(target_facts, mode=mode))
