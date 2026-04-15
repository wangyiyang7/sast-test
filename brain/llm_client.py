"""
LLM API client wrapper for OpenAI models.
Supports multimodal (vision) and text-only calls with retry logic and caching.

Current model assignments:
    - Discovery Agent: gpt-4o         (multimodal — vision + text)
    - Strategy Agent:  gpt-4.1        (text-only — use gpt-5.1 when available)
    - Analyzer Agent:  gpt-4.1-mini   (text-only)

Designed for easy provider switching to Anthropic when API keys are available.
"""

import base64
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import re
from openai import OpenAI, RateLimitError, APIStatusError, APIConnectionError
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL

logger = logging.getLogger(__name__)

# ── Model identifiers ──────────────────────────────────────────────
# OpenRouter model names: "provider/model-name"       
MODEL_DISCOVERY ="openai/gpt-4o-mini"        # multimodal — vision + text
MODEL_STRATEGY  = "qwen/qwen3.6-plus"  # text-only strategy decisions
#MODEL_STRATEGY  = "openai/gpt-5-mini"         
#MODEL_STRATEGY  = "anthropic/claude-haiku-4.5" 
MODEL_ANALYZER  = "openai/gpt-4.1-mini"    # text-only vulnerability evaluation

# ── Retry settings ─────────────────────────────────────────────────
MAX_RETRIES = 3
RETRY_BACKOFF = 2.0  # seconds, doubles each retry

if MODEL_STRATEGY  == "qwen/qwen3.6-plus:free":
    RETRY_BACKOFF = 30


class LLMClient:
    """
    Unified client for all LLM calls in Argus.
    Wraps the OpenAI SDK with retry logic, usage tracking,
    and optional response caching for text-only calls.
    """

    def __init__(self, cache_enabled: bool = True, cache_ttl: int = 300):
        """
        Args:
            cache_enabled: Cache identical text-only requests to save cost.
            cache_ttl: Cache entry lifetime in seconds.
        """
        if not OPENROUTER_API_KEY:
            raise ValueError("OPENROUTER_API_KEY not set in environment")

        # OpenRouter uses the OpenAI SDK format but with a different base_url and key.
        # Models are referenced as "openai/gpt-4o", "openai/gpt-4.1", etc.
        self._client = OpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
        )
        self._cache_enabled = cache_enabled
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, Dict[str, Any]] = {}

        # Cumulative usage tracking
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_calls = 0

    # ── Public API ──────────────────────────────────────────────────

    def call_discovery(
        self,
        screenshot_path: Path,
        dom_summary: str,
        url: str,
        system_prompt: str,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        """
        Multimodal call for the Discovery Agent (screenshot + text).

        Args:
            screenshot_path: Path to page screenshot (PNG).
            dom_summary: Text from Vision.summarize_for_llm().
            url: Current page URL.
            system_prompt: Discovery Agent system prompt.
            max_tokens: Max response tokens.

        Returns:
            Parsed JSON dict of discovered UI elements.
        """
        img_b64 = self._encode_image(screenshot_path)

        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{img_b64}",
                            "detail": "high",
                        },
                    },
                    {
                        "type": "text",
                        "text": (
                            f"Current URL: {url}\n\n"
                            f"DOM Summary:\n{dom_summary}\n\n"
                            "Analyze the screenshot and DOM above. "
                            "Return your response as valid JSON only."
                        ),
                    },
                ],
            },
        ]

        raw = self._call(
            model=MODEL_DISCOVERY,
            messages=messages,
            max_tokens=max_tokens,
        )
        return self._parse_json_response(raw)

    def call_text(
        self,
        model: str,
        system_prompt: str,
        user_message: str,
        max_tokens: int = 1024,
    ) -> Dict[str, Any]:
        """
        Text-only call (used by Strategy and Analyzer agents).

        Args:
            model: Model identifier (MODEL_STRATEGY or MODEL_ANALYZER).
            system_prompt: Agent system prompt.
            user_message: Formatted context string.
            max_tokens: Max response tokens.

        Returns:
            Parsed JSON dict from the LLM response.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        raw = self._call(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
        )
        return self._parse_json_response(raw)

    def get_usage_stats(self) -> Dict[str, Any]:
        """Return cumulative token usage statistics."""
        return {
            "total_calls": self.total_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "cache_size": len(self._cache),
        }

    # ── Core call with retries ──────────────────────────────────────

    def _call(
        self,
        model: str,
        messages: List[Dict],
        max_tokens: int,
    ) -> str:
        """
        Execute an API call with retry logic and optional caching.

        Returns:
            Raw text content from the LLM response.
        """
        # Check cache (skip for multimodal — images bloat cache keys)
        cache_key = None
        if self._cache_enabled and not self._has_image(messages):
            cache_key = self._make_cache_key(model, messages)
            cached = self._get_cached(cache_key)
            if cached is not None:
                logger.debug("Cache hit for %s call", model)
                return cached

        last_error = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                logger.info("LLM call [%s] attempt %d/%d", model, attempt, MAX_RETRIES)

                # gpt-5.1 and newer models use max_completion_tokens
                # Older models (gpt-4o, gpt-4.1, etc.) use max_tokens
                response = self._client.chat.completions.create(
                        model=model,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=0.2,
                    )

                # Track usage
                self.total_calls += 1
                usage = response.usage
                if usage:
                    self.total_input_tokens += usage.prompt_tokens
                    self.total_output_tokens += usage.completion_tokens
                    logger.info(
                        "LLM response: %d input, %d output tokens",
                        usage.prompt_tokens, usage.completion_tokens,
                    )

                text = response.choices[0].message.content or ""

                # Cache text-only results
                if cache_key is not None:
                    self._set_cached(cache_key, text)

                return text

            except RateLimitError as e:
                last_error = e
                wait = RETRY_BACKOFF * (2 ** (attempt - 1))
                logger.warning("Rate limited. Retrying in %.1fs ...", wait)
                time.sleep(wait)

            except APIStatusError as e:
                last_error = e
                if e.status_code >= 500:
                    wait = RETRY_BACKOFF * (2 ** (attempt - 1))
                    logger.warning("Server error %d. Retrying in %.1fs ...", e.status_code, wait)
                    time.sleep(wait)
                else:
                    raise  # 4xx not retryable

            except APIConnectionError as e:
                last_error = e
                wait = RETRY_BACKOFF * (2 ** (attempt - 1))
                logger.warning("Connection error. Retrying in %.1fs ...", wait)
                time.sleep(wait)

        raise RuntimeError(f"LLM call failed after {MAX_RETRIES} attempts: {last_error}")

    # ── Helpers ──────────────────────────────────────────────────────

    def _encode_image(self, path: Path) -> str:
        """Read image file and return base64 string."""
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

    def _has_image(self, messages: List[Dict]) -> bool:
        """Check if any message contains an image block."""
        for msg in messages:
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "image_url":
                        return True
        return False

    def _parse_json_response(self, raw: str) -> Dict[str, Any]:
        text = raw.strip()

        # Strip ```json ... ``` wrappers (even if not at the start)
        if "```" in text:
            # Find the JSON block between fences
            match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
            if match:
                text = match.group(1).strip()

        # If text still doesn't start with {, try to find the JSON object
        if not text.startswith("{"):
            start = text.find("{")
            if start != -1:
                # Find the matching closing brace
                depth = 0
                for i, c in enumerate(text[start:], start):
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            text = text[start:i+1]
                            break

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse LLM JSON: %s", e)
            logger.debug("Raw response:\n%s", raw[:500])
            return {"raw_response": raw, "parse_error": str(e)}

    def _make_cache_key(self, model: str, messages: List[Dict]) -> str:
        """Generate hash key for caching text-only requests."""
        payload = json.dumps({"model": model, "messages": messages}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[str]:
        """Retrieve cached response if it exists and hasn't expired."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.time() - entry["timestamp"] > self._cache_ttl:
            del self._cache[key]
            return None
        return entry["response"]

    def _set_cached(self, key: str, response: str) -> None:
        """Store a response in the cache."""
        self._cache[key] = {"response": response, "timestamp": time.time()}
