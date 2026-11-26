"""Zero-dependency Python SDK for the Tinplate 26-API Offline AI Security Edge Gateway."""

from .adapters import (
    TinplateCrewAIGuardrail,
    TinplateLangChainCallbackHandler,
    TinplateLlamaIndexCallback,
    TinplateToolSpec,
    as_crewai_tools,
    as_langchain_tools,
    as_llamaindex_tools,
    as_pydantic_ai_tools,
    guard_pydantic_ai_prompt,
)
from .client import TinplateClient, TinplateError

__all__ = [
    "TinplateClient",
    "TinplateError",
    "TinplateToolSpec",
    "TinplateLangChainCallbackHandler",
    "TinplateLlamaIndexCallback",
    "TinplateCrewAIGuardrail",
    "as_langchain_tools",
    "as_llamaindex_tools",
    "as_crewai_tools",
    "as_pydantic_ai_tools",
    "guard_pydantic_ai_prompt",
]
__version__ = "2.0.0"
