"""
Brain package — multi-agent architecture for ARGUS.

Components:
    - LLMClient: Unified API wrapper (OpenAI, with future Anthropic support)
    - DiscoveryAgent: Multimodal page analysis (GPT-4o)
    - Orchestrator: Central agent loop coordinator (pure Python)
    - StrategyStub: Placeholder for Strategy Agent (teammates implement)
    - AnalyzerStub: Placeholder for Analyzer Agent (teammates implement)
"""

from src.brain.llm_client import LLMClient, MODEL_DISCOVERY, MODEL_STRATEGY, MODEL_ANALYZER
from src.brain.discovery import DiscoveryAgent, DiscoveryResult, UIElement
from src.brain.orchestrator import Orchestrator, OrchestratorConfig, PageState, AgentAction

__all__ = [
    "LLMClient",
    "MODEL_DISCOVERY",
    "MODEL_STRATEGY",
    "MODEL_ANALYZER",
    "DiscoveryAgent",
    "DiscoveryResult",
    "UIElement",
    "Orchestrator",
    "OrchestratorConfig",
    "PageState",
    "AgentAction",
]