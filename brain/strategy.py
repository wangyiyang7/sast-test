"""
Strategy Agent — the "brain" of ARGUS.

Receives structured Discovery output, the current access map, action history,
and network traffic to decide the single best next action to advance
security testing coverage.

Focuses on: IDOR, RBAC bypass, broken auth, and privilege escalation.

Deliberately stateless — all context is passed in per call.
The Orchestrator owns state (access_map, history, current_role).
"""

import re
import logging
from collections import Counter
from typing import Any, Dict, List, Optional
import json
from pathlib import Path
from datetime import datetime
from src.brain.llm_client import LLMClient, MODEL_STRATEGY
from src.rag.retriever import Retriever

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────

VALID_ACTION_TYPES = {
    "click",
    "type",
    "navigate",
    "submit",
    "switch_role",
    "test_access",
    "scroll",
}

_FALLBACK_ACTION: Dict[str, Any] = {
    "action_type": "scroll",
    "selector": "",
    "value": "",
    "role": "",
    "rationale": "[STRATEGY FALLBACK] LLM response was malformed — scrolling to surface more content.",
    "_parse_failed": True,
}

# How many times a pattern can repeat before we tell the LLM to stop
_EXHAUSTION_THRESHOLD = 2


# ── Exhausted pattern detection ──────────────────────────────────────

def _detect_exhausted_patterns(action_history: List[Dict[str, Any]]) -> List[str]:
    """
    Find URL patterns tried 2+ times with different params/IDs.

    Normalizes both path IDs and query parameter values so that:
      /rest/basket/1, /rest/basket/2, /rest/basket/3
        → all become /rest/basket/{id}  (counted 3 times)
      /rest/products/search?q=1, /rest/products/search?q=2
        → all become /rest/products/search?q={val}  (counted 2 times)
      /rest/admin/application-configuration (hit 5 times)
        → counted 5 times as-is (no normalization needed)

    Returns a list of exhausted pattern strings.
    """
    pattern_counter: Counter = Counter()

    for entry in action_history:
        url = entry.get("url_after", "")
        if not url:
            continue
        # Normalize path IDs: /basket/3 → /basket/{id}
        normalized = re.sub(r'/\d+(?=/|$|\?)', '/{id}', url)
        # Normalize query param values: ?q=5 → ?q={val}
        normalized = re.sub(r'([?&]\w+=)[^&]*', r'\1{val}', normalized)
        pattern_counter[normalized] += 1

    return [
        pattern for pattern, count in pattern_counter.items()
        if count >= _EXHAUSTION_THRESHOLD
    ]


# ── System prompt ────────────────────────────────────────────────────

STRATEGY_SYSTEM_PROMPT = """You are the Strategy Agent in ARGUS, an autonomous web application penetration testing system.

Your job: decide the SINGLE BEST next action to find IDOR vulnerabilities.

=== WHAT IS IDOR ===
Insecure Direct Object Reference: user A accesses user B's resources by
changing a numeric ID in an API endpoint. Example: userX calls GET /backend/resource/7
and receives userY's data instead of a 401/403.

=== AVAILABLE ACTION TYPEs ===
- test_access: Make an AUTHENTICATED API call to a /backend/ endpoint.
  Use this for all IDOR probes. Requires value (the full URL).
  This sends the current user's auth token automatically.
- click: Click an element from PAGE DISCOVERY. Use for navigating the app.
  Requires selector from Discovery output.
- navigate: Go to a URL in the browser. ONLY use for client-side SPA routes when
  no clickable element exists. NEVER use for /backend/ URLs —
  use test_access instead (navigate does not send auth tokens).
- switch_role: Switch to a different user. Requires role.
- scroll: Scroll to reveal more content.
- type: Enter text into an input. Requires selector and value.
- submit: Submit a form. Requires selector.

=== CRITICAL RULES ===
1. If the ACCESS MAP already contains endpoints with {id} that were accessed
by a DIFFERENT role, you MUST test_access those endpoints FIRST before
doing any further discovery. Do not click navigation links or explore
new pages when there are untested IDOR targets sitting in the ACCESS MAP.
2. Use navigate and test_access carefully — navigate does not send auth tokens.
3. Only use selectors and URLs from PAGE DISCOVERY, ACCESS MAP, or
   NETWORK TRAFFIC. Do not guess or invent URLs.
4. If a click fails (success=false in history), do not retry the same
   selector. Try a different approach.
5. Do not test the same endpoint+ID+role combination twice.


=== OUTPUT FORMAT ===
Return ONLY a single valid JSON object:

{
    "action_type": "click | test_access | navigate | switch_role | scroll | type | submit",
    "selector": "CSS selector (empty string if not needed)",
    "value": "URL for test_access/navigate, or text for type (empty string if not needed)",
    "role": "target role for switch_role only (empty string otherwise)",
    "rationale": "One sentence: what IDOR hypothesis this tests"
}"""

# ── User message builder ─────────────────────────────────────────────

def _build_user_message(
    discovery_summary: str,
    access_map: str,
    action_history: List[Dict[str, Any]],
    current_role: str,
    network_summary: str,
    rag_context: str = "",
    available_roles: List[str] = None,
    dead_selectors: List[str] = None,
) -> str:
    """
    Assemble all context into a single user message for the LLM.
    """
    recent_history = action_history[-10:] if len(action_history) > 10 else action_history

    # Format action history
    if recent_history:
        history_lines = []
        for i, a in enumerate(recent_history, 1):
            line = (
                f"  {i}. [{a.get('action', '?')}] "
                f"selector={a.get('selector', '') or '—'} "
                f"url_before={a.get('url_before', '?')} "
                f"→ url_after={a.get('url_after', '?')} "
                f"success={a.get('success', '?')}"
            )
            history_lines.append(line)
        history_str = "\n".join(history_lines)
    else:
        history_str = "  (none — this is the first action)"

    access_str = access_map if access_map else "  (empty — no access data collected yet)"
    network_str = network_summary.strip() if network_summary else "  (no network traffic captured)"
    rag_section = f"\n{rag_context}" if rag_context else ""

    # ── Exhausted patterns — tell the LLM what to stop trying ──
    exhausted = _detect_exhausted_patterns(action_history)
    if exhausted:
        exhausted_section = (
            "\n=== EXHAUSTED ENDPOINTS (DO NOT RETRY) ===\n"
            "These URL patterns have been tried 2+ times already.\n"
            "Do NOT try them again with different IDs or parameter values.\n"
            "Move on to a completely different endpoint or switch roles.\n"
            + "\n".join(f"  {p}" for p in exhausted)
        )
    else:
        exhausted_section = ""
    # Available roles for switch_role
    if available_roles:
        roles_str = ", ".join(available_roles)
    else:
        roles_str = "(unknown — only current role available)"

    dead_section = ""
    if dead_selectors:
        dead_section = (
            "\n=== DEAD SELECTORS — DO NOT USE ===\n"
            "These selectors have timed out or are not visible. Never use them.\n"
            + "\n".join(f"  ✗ {s}" for s in dead_selectors)
            + "\n"
        )

    return f"""=== CURRENT ROLE ===
{current_role}

=== AVAILABLE ROLES FOR TESTING ===
{roles_str}
IMPORTANT: When using switch_role, the "role" field MUST be one of these exact names.
Do NOT use generic names like "customer", "user", or "regular" — only these specific roles exist.

=== PAGE DISCOVERY ===
{discovery_summary}

=== ACCESS MAP (permissions observed across all roles so far) ===
{access_str}

=== RECENT ACTION HISTORY (last {len(recent_history)} actions) ===
{history_str}
{exhausted_section}
{dead_section}

=== NETWORK TRAFFIC SUMMARY ===
{network_str}
{rag_section}
=== YOUR TASK ===
Based on all of the above, decide the single best next action to find IDOR vulnerabilities.
If the ACCESS MAP shows IDOR TARGETS, you MUST test_access them immediately.
If an endpoint pattern appears in EXHAUSTED ENDPOINTS, do NOT try it again — move on entirely.
Return ONLY the JSON action object."""


# ── Output parser ────────────────────────────────────────────────────

def _parse_strategy_response(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalise the LLM's parsed JSON response.
    """
    if "parse_error" in raw:
        logger.warning(
            "Strategy Agent received unparseable LLM output: %s",
            raw.get("parse_error"),
        )
        return dict(_FALLBACK_ACTION)

    action_type = raw.get("action_type", "").strip().lower()
    if action_type not in VALID_ACTION_TYPES:
        logger.warning(
            "Strategy Agent returned unknown action_type %r — falling back. Raw: %s",
            action_type, raw,
        )
        return dict(_FALLBACK_ACTION)

    action = {
        "action_type": action_type,
        "selector": str(raw.get("selector") or "").strip(),
        "value":    str(raw.get("value")    or "").strip(),
        "role":     str(raw.get("role")     or "").strip(),
        "rationale":str(raw.get("rationale")or "").strip(),
    }

    if action_type in ("click", "type", "submit") and not action["selector"]:
        logger.warning(
            "Strategy chose action_type=%r but provided no selector. "
            "Hands will likely fail. Rationale: %s",
            action_type, action["rationale"],
        )

    if action_type in ("navigate", "test_access") and not action["value"]:
        logger.warning(
            "Strategy chose action_type=%r but provided no URL value. "
            "Falling back. Rationale: %s",
            action_type, action["rationale"],
        )
        return dict(_FALLBACK_ACTION)

    if action_type == "switch_role" and not action["role"]:
        logger.warning("Strategy chose switch_role but provided no role. Falling back.")
        return dict(_FALLBACK_ACTION)

    if action_type == "type" and not action["value"]:
        logger.warning(
            "Strategy chose action_type=type but provided no value to type. Selector: %s",
            action["selector"],
        )

    # Auto-promote navigate → test_access for API endpoints
    if action["action_type"] == "navigate" and action["value"]:
        v = action["value"]
        if "/api/" in v or "/rest/" in v:
            if "/#/" not in v:  # Don't promote hash routes
                logger.info("Auto-promoting navigate → test_access for API URL: %s", v)
                action["action_type"] = "test_access"

    logger.info(
        "Strategy decision: action_type=%s selector=%r value=%r rationale=%s",
        action["action_type"], action["selector"],
        action["value"], action["rationale"],
    )
    return action


# ── Strategy Agent class ─────────────────────────────────────────────

class StrategyAgent:
    """
    Decides the next browser action to take during a penetration test.
    """

    def __init__(self, llm_client: LLMClient, retriever: Optional[Retriever] = None):
        self._llm = llm_client
        self._retriever = retriever

    def decide(
        self,
        discovery_summary: str,
        access_map: str,
        action_history: List[Dict[str, Any]],
        current_role: str,
        network_summary: str = "",
        available_roles: List[str] = None,
        dead_selectors: List[str] = None,
    ) -> Dict[str, Any]:
        """Choose the next action."""
        # Build RAG context if retriever is available
        rag_context = ""
        if self._retriever is not None:
            try:
                recent = action_history[-3:] if action_history else []
                history_summary = "; ".join(
                    f"{a.get('action','?')} on {a.get('url_before','?')}"
                    for a in recent
                )
                first_line = discovery_summary.split("\n")[0] if discovery_summary else ""
                url_line = next(
                    (l for l in discovery_summary.split("\n") if l.startswith("URL:")),
                    ""
                )
                current_url = url_line.replace("URL:", "").strip()

                rag_context = self._retriever.format_context(
                    page_description=first_line,
                    current_url=current_url,
                    current_role=current_role,
                    action_history_summary=history_summary,
                )
                if rag_context:
                    logger.info("RAG returned context (%d chars)", len(rag_context))
            except Exception as e:
                logger.warning("RAG retrieval failed (non-fatal): %s", e)
                rag_context = ""

        user_message = _build_user_message(
            discovery_summary=discovery_summary,
            access_map=access_map,
            action_history=action_history,
            current_role=current_role,
            network_summary=network_summary,
            rag_context=rag_context,
            available_roles=available_roles,
            dead_selectors=dead_selectors,
        )

        logger.info("Strategy Agent deciding next action for role=%s", current_role)

        raw = self._llm.call_text(
            model=MODEL_STRATEGY,
            system_prompt=STRATEGY_SYSTEM_PROMPT,
            user_message=user_message,
        )

        self._save_raw(raw, current_role, user_message)

        return _parse_strategy_response(raw)

    def _save_raw(self, raw: Dict[str, Any], role: str, user_message: str = "") -> None:
        try: 
            out_dir = Path("reports/strategy")
            out_dir.mkdir(parents=True, exist_ok=True)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = out_dir / f"strategy_raw_{ts}_{role}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "raw_response": raw,
                    "user_message": user_message,
                }, f, indent=2, default=str)
        except Exception as e:
            logger.warning("Failed to save strategy raw output: %s", e)
