"""Zero-dependency agent framework adapters for LangChain, LlamaIndex, CrewAI, and PydanticAI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .client import TinplateClient, TinplateError, _validate_input_guardrail_pipeline


def _raise_if_unsafe(data: Any, code: str, message: str) -> Dict[str, Any]:
    if not isinstance(data, dict) or data.get("safe") is False or data.get("verdict") == "block":
        raise TinplateError(403, code, message)
    return data


@dataclass
class TinplateToolSpec:
    """Framework-agnostic tool wrapper compatible with LangChain, LlamaIndex, CrewAI, and PydanticAI."""

    name: str
    description: str
    func: Callable[..., Dict[str, Any]]

    def __call__(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return self.func(*args, **kwargs)


def _build_core_tools(client: TinplateClient) -> List[TinplateToolSpec]:
    return [
        TinplateToolSpec(
            name="tinplate_prompt_guard",
            description="Detect prompt injection, jailbreaks, and system-prompt extraction attempts.",
            func=lambda text, sensitivity="medium": client.prompt_guard(
                text=text, sensitivity=sensitivity
            ),
        ),
        TinplateToolSpec(
            name="tinplate_redact_pii",
            description="Redact PII (emails, phones, IBANs, SSNs, EU VAT, and national tax IDs) with reversible tokens.",
            func=lambda text, locales=None: client.redact_pii(
                text=text, locales=locales or ["GLOBAL"]
            ),
        ),
        TinplateToolSpec(
            name="tinplate_heal_json",
            description="Repair malformed LLM JSON output deterministically.",
            func=lambda raw: client.heal_json(raw=raw),
        ),
        TinplateToolSpec(
            name="tinplate_guard_llm_output",
            description="Audit LLM output for leaked secrets, PII, or unsafe content.",
            func=lambda output: client.guard_llm_output(output=output),
        ),
        TinplateToolSpec(
            name="tinplate_scan_secrets",
            description="Scan text or code diffs for 28+ credential and API key patterns.",
            func=lambda text: client.scan_secrets(text=text),
        ),
        TinplateToolSpec(
            name="tinplate_ssrf_firewall",
            description="Validate an external URL against SSRF, private IPs, and metadata endpoints.",
            func=lambda url: client.ssrf_firewall(url=url),
        ),
    ]


class TinplateLangChainCallbackHandler:
    """LangChain-compatible callback handler for prompt injection, PII, and output guardrails."""

    def __init__(
        self,
        client: TinplateClient,
        *,
        sensitivity: str = "medium",
        block_on_injection: bool = True,
        guard_tools: bool = True,
    ) -> None:
        self.client = client
        self.sensitivity = sensitivity
        self.block_on_injection = block_on_injection
        self.guard_tools = guard_tools
        self.events: List[Dict[str, Any]] = []

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        for prompt in prompts:
            res = self.client.prompt_guard(text=prompt, sensitivity=self.sensitivity)
            data = res.get("data", {})
            self.events.append({"stage": "llm_start", "data": data})
            if self.block_on_injection and data.get("verdict") == "block":
                raise TinplateError(403, "prompt_blocked", "Tinplate blocked prompt injection in LangChain on_llm_start")

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        text = ""
        generations = getattr(response, "generations", None)
        if isinstance(generations, list) and generations:
            first = generations[0]
            if isinstance(first, list) and first:
                text = getattr(first[0], "text", "") or ""
        elif isinstance(response, str):
            text = response
        if text:
            res = self.client.guard_llm_output(output=text)
            data = res.get("data", {})
            self.events.append({"stage": "llm_end", "data": data})
            _raise_if_unsafe(
                data,
                "output_blocked",
                "Tinplate blocked unsafe LLM output in LangChain on_llm_end",
            )

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        if not self.guard_tools:
            return
        res = self.client.guard_command_sql(input=input_str)
        data = res.get("data", {})
        self.events.append({"stage": "tool_start", "data": data})
        _raise_if_unsafe(
            data,
            "tool_blocked",
            "Tinplate blocked unsafe tool input in LangChain on_tool_start",
        )


def as_langchain_tools(client: TinplateClient) -> List[Any]:
    """Return Tinplate tools wrapped as LangChain Tool objects if langchain_core is installed, else TinplateToolSpec."""
    specs = _build_core_tools(client)
    try:
        from langchain_core.tools import Tool  # type: ignore

        return [Tool(name=s.name, description=s.description, func=s.func) for s in specs]
    except ImportError:
        return specs


def _guard_text_pipeline(
    client: TinplateClient,
    text: str,
    *,
    sensitivity: str = "medium",
    locales: Optional[List[str]] = None,
    framework: str,
) -> str:
    """Run prompt-guard + pii-redactor pipeline and return redacted text or raise TinplateError."""
    res = client.pipeline([
        {"id": "pg", "endpoint": "/v1/prompt-guard", "body": {"text": text, "sensitivity": sensitivity}},
        {"id": "pii", "endpoint": "/v1/pii-redactor", "body": {"text": text, "locales": locales or ["GLOBAL"], "mode": "token"}},
    ])
    blocked, _verdict, redacted_text = _validate_input_guardrail_pipeline(
        res,
        prompt_id="pg",
        pii_id="pii",
    )
    if blocked:
        raise TinplateError(403, "prompt_blocked", f"Tinplate blocked {framework}")
    return redacted_text


class TinplateLlamaIndexCallback:
    """LlamaIndex-compatible callback and query guardrail."""

    def __init__(self, client: TinplateClient, *, sensitivity: str = "medium") -> None:
        self.client = client
        self.sensitivity = sensitivity
        self.events: List[Dict[str, Any]] = []

    def on_event_start(
        self, event_type: str, payload: Optional[Dict[str, Any]] = None, **kwargs: Any
    ) -> str:
        text = ""
        if isinstance(payload, dict):
            text = str(payload.get("query_str") or payload.get("prompt") or "")
        if text:
            res = self.client.prompt_guard(text=text, sensitivity=self.sensitivity)
            data = res.get("data", {})
            self.events.append({"event": event_type, "stage": "start", "data": data})
            if data.get("verdict") == "block":
                raise TinplateError(403, "prompt_blocked", f"Tinplate blocked LlamaIndex {event_type}")
        return f"tinplate-{event_type}"

    def on_event_end(
        self, event_type: str, payload: Optional[Dict[str, Any]] = None, **kwargs: Any
    ) -> None:
        text = ""
        if isinstance(payload, dict):
            text = str(payload.get("response") or "")
        if text:
            res = self.client.guard_llm_output(output=text)
            data = res.get("data", {})
            self.events.append({"event": event_type, "stage": "end", "data": data})
            _raise_if_unsafe(
                data,
                "output_blocked",
                f"Tinplate blocked unsafe LLM output in LlamaIndex {event_type}",
            )

    def guard_query(self, query_str: str, *, locales: Optional[List[str]] = None) -> str:
        return _guard_text_pipeline(
            self.client,
            query_str,
            sensitivity=self.sensitivity,
            locales=locales,
            framework="LlamaIndex query",
        )


def as_llamaindex_tools(client: TinplateClient) -> List[Any]:
    """Return Tinplate tools wrapped as LlamaIndex FunctionTool if llama_index is installed, else TinplateToolSpec."""
    specs = _build_core_tools(client)
    try:
        from llama_index.core.tools import FunctionTool  # type: ignore

        return [
            FunctionTool.from_defaults(fn=s.func, name=s.name, description=s.description)
            for s in specs
        ]
    except ImportError:
        return specs


class TinplateCrewAIGuardrail:
    """CrewAI task input/output guardrail helper."""

    def __init__(self, client: TinplateClient, *, sensitivity: str = "medium") -> None:
        self.client = client
        self.sensitivity = sensitivity

    def guard_task_input(self, description: str, *, locales: Optional[List[str]] = None) -> str:
        return _guard_text_pipeline(
            self.client,
            description,
            sensitivity=self.sensitivity,
            locales=locales,
            framework="CrewAI task input",
        )

    def guard_task_output(self, output: str) -> Dict[str, Any]:
        return self.client.guard_llm_output(output=output)


def as_crewai_tools(client: TinplateClient) -> List[TinplateToolSpec]:
    """Return Tinplate tool specs ready for CrewAI agents."""
    return _build_core_tools(client)


def guard_pydantic_ai_prompt(
    client: TinplateClient,
    prompt: str,
    *,
    locales: Optional[List[str]] = None,
    sensitivity: str = "medium",
) -> str:
    """Validate and redact a prompt before passing it to a PydanticAI Agent.run()."""
    return _guard_text_pipeline(
        client,
        prompt,
        sensitivity=sensitivity,
        locales=locales,
        framework="PydanticAI prompt",
    )


def as_pydantic_ai_tools(client: TinplateClient) -> List[Callable[..., Dict[str, Any]]]:
    """Return typed plain-function tools ready for `Agent(..., tools=as_pydantic_ai_tools(client))`."""
    tools: List[Callable[..., Dict[str, Any]]] = []
    for spec in _build_core_tools(client):
        fn = spec.func
        fn.__name__ = spec.name
        fn.__doc__ = spec.description
        tools.append(fn)
    return tools
