"""LLM factory with per-node routing and a structured-output fallback chain.

The fallback chain matters in practice: not every OpenAI-compatible gateway
supports tool-style structured output, so we degrade to JSON mode and finally
to plain JSON parsing with validation.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional, Type

import httpx
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from config.config import Configs
from agent import telemetry
from agent.settings import cfg

_FACTORY = None

# One gateway session for the whole process.
#
# The gateway (opencode) routes requests by the ``x-opencode-session`` header and
# rejects requests without it. Generating a new id per call made every call a
# cold session: 10.0s per call versus 1.8s with a stable id (measured with an
# identical 3.9k-token prompt). Clients are cached for the same reason.
_SESSION_ID = uuid.uuid4()
_CLIENTS: Dict[tuple, ChatOpenAI] = {}
_HTTP_CLIENT: Optional[httpx.Client] = None


_HTTP_CLIENT: Optional[httpx.Client] = None
_HTTP_ASYNC_CLIENT: Optional[httpx.AsyncClient] = None


def _limits() -> httpx.Limits:
    return httpx.Limits(max_connections=8, max_keepalive_connections=4)


def _timeout() -> httpx.Timeout:
    return httpx.Timeout(float(Configs.llm_config.timeout or 600), connect=15.0)


def http_client() -> httpx.Client:
    """Shared sync connection pool.

    Constructing ``ChatOpenAI`` costs ~7.9s on this machine: it builds both a
    sync and an async httpx client, and each one builds an SSL context. Passing
    both in makes construction free. A client created with ``trust_env`` also
    resolves proxy env vars (~2.7s), so env proxies are ignored unless
    ``models.respect_env_proxy`` is enabled.
    """
    global _HTTP_CLIENT
    if _HTTP_CLIENT is None:
        _HTTP_CLIENT = httpx.Client(
            timeout=_timeout(),
            limits=_limits(),
            trust_env=bool(cfg("models.respect_env_proxy", False)),
        )
    return _HTTP_CLIENT


def http_async_client() -> httpx.AsyncClient:
    """Shared async pool; only built to keep ``ChatOpenAI`` construction cheap."""
    global _HTTP_ASYNC_CLIENT
    if _HTTP_ASYNC_CLIENT is None:
        _HTTP_ASYNC_CLIENT = httpx.AsyncClient(
            timeout=_timeout(),
            limits=_limits(),
            trust_env=bool(cfg("models.respect_env_proxy", False)),
        )
    return _HTTP_ASYNC_CLIENT


def warm_up() -> None:
    """Pay the TLS handshake and gateway session setup off the critical path.

    The first call in a process costs ~9.7s instead of ~1s. Running one cheap
    request in the background while the graph starts hides almost all of it.
    """
    try:
        get_llm("summarizer").invoke(
            [HumanMessage(content="ok")], config=call_config("summarizer")
        )
    except Exception:  # noqa: BLE001 - a failed warm-up must never matter
        return


def reset_llm_clients() -> None:
    """Drop cached clients and rotate the gateway session (new engagement).

    The shared connection pool survives: it is process infrastructure, and
    rebuilding it would pay the SSL/proxy setup cost again.
    """
    global _SESSION_ID
    _CLIENTS.clear()
    _SESSION_ID = uuid.uuid4()


def session_id() -> str:
    return str(_SESSION_ID)


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

    model = _model_name(node)
    effort = cfg("models.reasoning_effort", "none")
    by_node = cfg("models.reasoning_effort_by_node", {}) or {}
    effort = by_node.get(node, effort)
    key = (node, model, float(temperature), str(effort))
    cached = _CLIENTS.get(key)
    if cached is not None:
        return cached

    headers = {}
    if "opencode" in str(Configs.llm_config.base_url).lower():
        headers["x-opencode-session"] = session_id()

    client = ChatOpenAI(
        model=model,
        api_key=Configs.llm_config.api_key,
        base_url=Configs.llm_config.base_url,
        default_headers=headers or None,
        temperature=temperature,
        timeout=Configs.llm_config.timeout,
        max_retries=2,
        http_client=http_client(),
        http_async_client=http_async_client(),
        extra_body={"reasoning_effort": effort} if effort else None,
    )
    _CLIENTS[key] = client
    return client


def call_config(node: str) -> Dict[str, Any]:
    """RunnableConfig that labels a call so usage accounting can attribute it."""
    return {
        "metadata": {telemetry.NODE_METADATA_KEY: node},
        "tags": [f"{telemetry.NODE_TAG_PREFIX}{node}"],
        "callbacks": [telemetry.TRACKER],
    }


def chat(messages: List[BaseMessage], node: str = "summarizer") -> str:
    llm = get_llm(node)
    response = llm.invoke(messages, config=call_config(node))
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


def _json_contract(schema: Type[BaseModel]) -> HumanMessage:
    """Explicit JSON contract for gateways without tool-calling support.

    Two things matter here and both were missing before: the word "json" has to
    appear in the prompt for ``json_mode`` gateways to honour it, and the final
    fallback has to state the schema, otherwise the model answers in prose and
    the parse always fails.
    """
    try:
        spec = json.dumps(schema.model_json_schema(), ensure_ascii=False)
    except Exception:  # noqa: BLE001 - a broken schema must not hide the call
        spec = str(getattr(schema, "__name__", "object"))
    return HumanMessage(
        content=(
            "Reply with one JSON object and nothing else: no prose, no markdown fences, no comments.\n"
            "It must validate against this JSON schema:\n" + spec
        )
    )


def structured(
    schema: Type[BaseModel],
    messages: List[BaseMessage],
    node: str = "planner",
    temperature: Optional[float] = None,
) -> BaseModel:
    llm = get_llm(node, temperature)
    contract = _json_contract(schema)

    try:
        return llm.with_structured_output(schema).invoke(messages, config=call_config(node))
    except Exception:  # noqa: BLE001 - deliberate fallback chain
        try:
            return llm.with_structured_output(schema, method="json_mode").invoke(
                list(messages) + [contract], config=call_config(node)
            )
        except Exception as json_error:  # noqa: BLE001
            raw = chat(list(messages) + [contract], node=node)
            try:
                data = _parse_json(raw)
            except Exception:
                raise json_error from None
            return schema.model_validate(data)
