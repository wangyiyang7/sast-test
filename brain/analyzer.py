"""
Analyzer Agent — the "judge" of ARGUS.

Receives a before/after PageState pair, the action that was taken, the current
role, and raw network traffic, then uses an LLM to determine whether a security
vulnerability was exposed.

Vulnerability classes it detects:
  - IDOR (Insecure Direct Object Reference)
  - RBAC bypass (role-based access control violation)
  - Broken Authentication / Privilege Escalation
  - Tenant Isolation failure (one user accessing another user's data)

Deliberately stateless — all context is passed in per call.
The Orchestrator owns state and calls this agent after every action.
"""

import logging
from typing import Any, Dict, List, Optional
import json as _json
from src.brain.llm_client import LLMClient, MODEL_ANALYZER

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────

VULNERABILITY_TYPES = {
    "IDOR",
    "RBAC",
    "Broken Authentication",
    "Privilege Escalation",
    "Tenant Isolation",
    "Information Disclosure",
}

SEVERITY_LEVELS = {"Critical", "High", "Medium", "Low", "Info"}

# Returned when the LLM output is malformed — signals "no finding, but degraded"
_FALLBACK_FINDING: Dict[str, Any] = {
    "is_vulnerability": False,
    "vulnerability_type": None,
    "severity": None,
    "description": "[ANALYZER FALLBACK] LLM response was malformed — no analysis available.",
    "evidence": "",
    "reproduction_steps": [],
    "confidence": 0.0,
    "_parse_failed": True,
}


# ── System prompt ────────────────────────────────────────────────────

ANALYZER_SYSTEM_PROMPT = """You are the Analyzer Agent in ARGUS, an autonomous web application penetration testing system.

Your job: Given a browser action, the page state BEFORE and AFTER the action, the role that performed it, and captured network traffic, determine whether a security vulnerability was exposed.

=== VULNERABILITY CLASSES YOU DETECT ===

1. IDOR (Insecure Direct Object Reference)
   - A user accessed a resource (order, basket, address, profile) belonging to ANOTHER user by manipulating an ID.
   - Key signals: numeric ID in URL changed → response returns data; response body contains another user's email/id/name.
   - Example: GET /api/BasketItems/1 as user with basket ID 2 → returns items.

2. RBAC (Role-Based Access Control Bypass)
   - A lower-privilege user (customer, accountant) accessed a route or performed an action reserved for admins.
   - Key signals: URL contains /admin/ or /api/Users (all users); HTTP 200 for a route that should return 401/403 for this role.
   - Example: customer navigates to /#/administration and gets 200.

3. Broken Authentication / Privilege Escalation
   - An action succeeded that should have required higher privileges or re-authentication.
   - Key signals: sensitive operation (password change, role update, delete) completed as wrong role.

4. Tenant Isolation
   - A user viewed or modified data belonging to a different user/tenant.
   - Overlaps with IDOR but emphasises cross-user data leakage at the application level.

5. Information Disclosure
   - Sensitive data (tokens, passwords, PII, internal paths) exposed in a response that should be sanitised.
   - Key signals: response body contains plaintext passwords, JWT secrets, or other users' PII.

=== HOW TO ANALYZE ===

Step 1 — Check HTTP status codes in network traffic:
  - 200/201 for a route that should be 401/403 for this role = likely RBAC or broken auth.
  - 200 with another user's data = likely IDOR or tenant isolation.

Step 2 — Compare URLs before and after:
  - Did the URL change to a privileged path (/#/administration, /api/Users)?
  - Were IDs in the URL manipulated between before and after states?

Step 3 — Examine response bodies in network traffic:
  - Does any response contain data that shouldn't be visible to this role?
  - Are there other users' emails, IDs, basket contents, addresses?

Step 4 — Assess severity:
  - Critical: admin takeover, all-user data exposure, authentication bypass.
  - High: another user's order/basket/profile data accessed.
  - Medium: limited info disclosure, partial RBAC bypass.
  - Low: minor info leakage, no direct data access.
  - Info: interesting behaviour worth noting, no clear vulnerability.

=== CONFIDENCE SCORING ===
  - 0.9–1.0: Clear HTTP evidence (wrong-role 200, another user's data in body).
  - 0.6–0.89: Strong circumstantial evidence (URL change to admin route, suspicious response).
  - 0.3–0.59: Uncertain — could be a false positive.
  - 0.0–0.29: No meaningful evidence — return is_vulnerability: false.

=== IMPORTANT: AVOID FALSE POSITIVES ===
  - Admin users accessing admin routes is NOT a vulnerability.
  - 401/403 responses to unauthorized access are the system WORKING CORRECTLY.
  - Only flag is_vulnerability: true when you have concrete evidence of unauthorized access.

=== OUTPUT FORMAT ===
Return ONLY a single valid JSON object. No markdown, no explanation, no preamble:

{
    "is_vulnerability": true or false,
    "vulnerability_type": "IDOR" | "RBAC" | "Broken Authentication" | "Privilege Escalation" | "Tenant Isolation" | "Information Disclosure" | null,
    "severity": "Critical" | "High" | "Medium" | "Low" | "Info" | null,
    "description": "One or two sentences describing what happened and why it is (or is not) a vulnerability.",
    "evidence": "Specific HTTP request/response details, URL changes, or response body excerpts that support your conclusion.",
    "reproduction_steps": [
        "Step 1: Log in as <role>",
        "Step 2: Navigate to <url>",
        "Step 3: ..."
    ],
    "confidence": 0.0
}"""


# ── User message builder ─────────────────────────────────────────────

def _build_user_message(
    action: Dict[str, Any],
    state_before: Dict[str, Any],
    state_after: Dict[str, Any],
    current_role: str,
    network_traffic: List[Dict[str, Any]],
) -> str:
    """
    Assemble all context into a single structured user message for the LLM.

    Keeps each section clearly labelled. Network traffic is trimmed to
    API calls only and capped at 15 entries to stay within token budget.
    """

    # ── Action summary ──────────────────────────────────────────────
    action_str = (
        f"  Type:      {action.get('action_type', '?')}\n"
        f"  Selector:  {action.get('selector') or '—'}\n"
        f"  Value:     {action.get('value') or '—'}\n"
        f"  Rationale: {action.get('rationale') or '—'}"
    )

    # ── Page state summary ──────────────────────────────────────────
    def _fmt_state(state: Dict, label: str) -> str:
        return (
            f"=== PAGE STATE {label} ===\n"
            f"  URL:   {state.get('url', '?')}\n"
            f"  Title: {state.get('title', state.get('dom_summary', '')[:80])}..."
        )

    # ── Network traffic (API calls only, capped at 15) ──────────────
    api_calls = [
        r for r in network_traffic
        if "/api/" in r.get("url", "") or "/rest/" in r.get("url", "")
    ][:15]

    if api_calls:
        traffic_lines = [f"=== NETWORK TRAFFIC ({len(api_calls)} API calls shown) ==="]
        for r in api_calls:
            status  = r.get("status", "?")
            method  = r.get("method", "?")
            url     = r.get("url", "?")
            body    = r.get("response_body")

            traffic_lines.append(f"  {method} {url}  →  {status}")

            # Include a trimmed response body snippet for the LLM to inspect
            if body:
                try:
                    
                    body_str = _json.dumps(body)[:300]
                    traffic_lines.append(f"    Response (truncated): {body_str}")
                except Exception:
                    pass
        traffic_str = "\n".join(traffic_lines)
    else:
        traffic_str = "=== NETWORK TRAFFIC ===\n  No API calls captured for this action."

    # ── Auth tokens (helps identify which user's token was used) ────
    auth_headers = list({
        r.get("header", "")
        for r in network_traffic
        if r.get("header")  # extract_auth_tokens records have "header" key
    })

    # Fallback: scan request_headers directly from raw traffic records
    if not auth_headers:
        for r in network_traffic:
            hdrs = r.get("request_headers", {})
            for h in hdrs:
                if h.lower() in {"authorization", "x-auth-token", "x-access-token"}:
                    auth_headers.append(h)
        auth_headers = list(set(auth_headers))

    auth_str = (
        f"Auth headers present: {auth_headers}"
        if auth_headers
        else "No auth headers detected in captured traffic."
    )

    return f"""=== CURRENT ROLE ===
{current_role}

=== ACTION PERFORMED ===
{action_str}

{_fmt_state(state_before, "BEFORE")}

{_fmt_state(state_after, "AFTER")}

{traffic_str}

=== AUTH CONTEXT ===
{auth_str}

=== YOUR TASK ===
Analyze the above and determine whether a security vulnerability was exposed by this action.
Remember: only flag is_vulnerability: true when you have concrete evidence of unauthorized access.
Return ONLY the JSON finding object."""


# ── Output parser ────────────────────────────────────────────────────

def _parse_analyzer_response(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalise the LLM's parsed JSON response.

    Args:
        raw: Already-parsed dict from LLMClient._parse_json_response().

    Returns:
        A validated finding dict, or the fallback finding if invalid.
    """
    if "parse_error" in raw:
        logger.warning(
            "Analyzer received unparseable LLM output: %s",
            raw.get("parse_error"),
        )
        return dict(_FALLBACK_FINDING)

    is_vuln = bool(raw.get("is_vulnerability", False))

    vuln_type = raw.get("vulnerability_type")
    if vuln_type and vuln_type not in VULNERABILITY_TYPES:
        logger.warning("Analyzer returned unknown vulnerability_type %r — setting to None", vuln_type)
        vuln_type = None

    severity = raw.get("severity")
    if severity and severity not in SEVERITY_LEVELS:
        logger.warning("Analyzer returned unknown severity %r — setting to None", severity)
        severity = None

    # Clamp confidence to [0.0, 1.0]
    try:
        confidence = float(raw.get("confidence", 0.0))
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.0

    # Ensure reproduction_steps is a list of strings
    repro = raw.get("reproduction_steps", [])
    if not isinstance(repro, list):
        repro = [str(repro)]
    repro = [str(s) for s in repro]

    finding = {
        "is_vulnerability": is_vuln,
        "vulnerability_type": vuln_type if is_vuln else None,
        "severity": severity if is_vuln else None,
        "description": str(raw.get("description", "")).strip(),
        "evidence": str(raw.get("evidence", "")).strip(),
        "reproduction_steps": repro,
        "confidence": confidence,
    }

    if is_vuln:
        logger.warning(
            "VULNERABILITY DETECTED: type=%s severity=%s confidence=%.2f | %s",
            finding["vulnerability_type"],
            finding["severity"],
            finding["confidence"],
            finding["description"],
        )
    else:
        logger.info(
            "No vulnerability detected (confidence=%.2f): %s",
            finding["confidence"],
            finding["description"][:100],
        )

    return finding


# ── Analyzer Agent class ─────────────────────────────────────────────

class AnalyzerAgent:
    """
    Evaluates whether a browser action exposed a security vulnerability.

    Wraps a text-only LLM call (MODEL_ANALYZER) with:
      - A security-focused system prompt
      - Structured context assembly from all upstream components
      - Output validation and graceful fallback
    """

    def __init__(self, llm_client: LLMClient):
        self._llm = llm_client

    def evaluate(
        self,
        action: Dict[str, Any],
        state_before: Dict[str, Any],
        state_after: Dict[str, Any],
        current_role: str,
        network_traffic: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Evaluate whether the action exposed a vulnerability.

        Args:
            action:          The action dict from AgentAction.to_dict().
            state_before:    PageState.to_dict() captured before the action.
            state_after:     PageState.to_dict() captured after the action.
            current_role:    The Juice Shop role that performed the action (e.g. "jim").
            network_traffic: Raw traffic list from NetworkInterceptor.get_captured_traffic().

        Returns:
            Finding dict with keys:
                is_vulnerability (bool), vulnerability_type, severity,
                description, evidence, reproduction_steps, confidence.
            Always returns a valid dict — falls back gracefully on LLM errors.
        """
        user_message = _build_user_message(
            action=action,
            state_before=state_before,
            state_after=state_after,
            current_role=current_role,
            network_traffic=network_traffic,
        )

        logger.info(
            "Analyzer evaluating action=%s role=%s url_before=%s url_after=%s",
            action.get("action_type"),
            current_role,
            state_before.get("url"),
            state_after.get("url"),
        )

        raw = self._llm.call_text(
            model=MODEL_ANALYZER,
            system_prompt=ANALYZER_SYSTEM_PROMPT,
            user_message=user_message,
        )

        return _parse_analyzer_response(raw)
