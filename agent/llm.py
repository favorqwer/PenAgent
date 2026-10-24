"""LLM factory with per-node routing and a structured-output fallback chain.

The fallback chain matters in practice: not every OpenAI-compatible gateway
supports tool-style structured output, so we degrade to JSON mode and finally
to plain JSON parsing with validation.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, List, Optional, Type

from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from config.config import Configs
from agent.settings import cfg

_FACTORY = None


def set_llm_factory(factory) -> None:
    """Inject a fake model factory (tests / dry-run)."""
    global _FACTORY
    _FACTORY = factory


def reset_llm_factory() -> None:
    global _FACTORY
    _FACTORY = None


def _model_name(node: str) -> str:
    models = cfg("models", {}) or {}
    return models.get(node) or Configs.llm_config.llm_model_name


def get_llm(node: str = "command", temperature: Optional[float] = None):
    if _FACTORY is not None:
        return _FACTORY(node)

    if temperature is None:
        temperature = (cfg("temperatures", {}) or {}).get(node, 0.1)

    headers = {}
    if "opencode" in str(Configs.llm_config.base_url).lower():
        headers["x-opencode-session"] = str(uuid.uuid4())

    return ChatOpenAI(
        model=_model_name(node),
        api_key=Configs.llm_config.api_key,
        base_url=Configs.llm_config.base_url,
        default_headers=headers or None,
        temperature=temperature,
        timeout=Configs.llm_config.timeout,
        max_retries=2,
    )


def chat(messages: List[BaseMessage], node: str = "summarizer") -> str:
    llm = get_llm(node)
    response = llm.invoke(messages)
    content = getattr(response, "content", "")
    if isinstance(content, list):
        content = "".join(str(part) for part in content)
    return (content or "").strip()


_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
_JSON_OBJECT = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)


def _parse_json(text: str) -> Any:
    text = (text or "").strip()
    block = _JSON_BLOCK.search(text)
    if block:
        text = block.group(1).strip()
    try:
        return json.loads(text)
    except Exception:
        match = _JSON_OBJECT.search(text)
        if match:
            return json.loads(match.group(1))
        raise


def structured(
    schema: Type[BaseModel],
    messages: List[BaseMessage],
    node: str = "planner",
    temperature: Optional[float] = None,
) -> BaseModel:
    llm = get_llm(node, temperature)

    try:
        return llm.with_structured_output(schema).invoke(messages)
    except Exception as tool_error:  # noqa: BLE001 - deliberate fallback chain
        try:
            return llm.with_structured_output(schema, method="json_mode").invoke(messages)
        except Exception:  # noqa: BLE001
            raw = chat(messages, node=node)
            data = _parse_json(raw)
            if isinstance(data, dict) and "tasks" in data and hasattr(schema, "model_validate"):
                return schema.model_validate(data)
            if hasattr(schema, "model_validate"):
                return schema.model_validate(data)
            raise tool_error


def model_label() -> str:
    return Configs.llm_config.llm_model_name or "unknown-model"
