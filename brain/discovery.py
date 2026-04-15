"""
Discovery Agent — the "eyes" of the Brain.

Uses GPT-4o (multimodal) to analyze a screenshot + DOM summary and produce
a structured, semantically enriched list of UI elements on the current page.

The Discovery Agent answers: "What can I see and interact with on this page?"
Its output feeds into the Strategy Agent, which decides what to do next.
"""

import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from src.brain.llm_client import LLMClient

logger = logging.getLogger(__name__)


# ── Data structures ─────────────────────────────────────────────────

@dataclass
class UIElement:
    """A single interactive or informational element on the page."""
    element_id: str            # Unique ID within this page analysis (e.g., "elem_0")
    element_type: str          # Semantic type: "button", "link", "input", "form", "nav_item", "menu", "card", "text", "other"
    label: str                 # Human-readable label (button text, link text, input placeholder, etc.)
    selector: str              # CSS selector to target this element
    action_type: str           # What can be done: "click", "type", "submit", "navigate", "expand", "scroll", "none"
    context: str               # Semantic context: what this element does (e.g., "Opens user profile page")
    is_visible: bool = True    # Whether the element is currently visible
    is_enabled: bool = True    # Whether the element is interactive
    requires_auth: bool = False  # Whether this likely requires authentication
    bounding_box: Optional[Dict[str, float]] = None  # x, y, width, height if available

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveryResult:
    """Complete output of a Discovery Agent analysis."""
    url: str
    page_description: str       # One-line summary of what this page is
    page_type: str              # "login", "dashboard", "product_list", "admin_panel", "form", "profile", "search", "other"
    elements: List[UIElement] = field(default_factory=list)
    navigation_options: List[str] = field(default_factory=list)  # High-level nav paths available
    auth_indicators: List[str] = field(default_factory=list)     # Signs of auth state (e.g., "logged in as admin", "login button visible")
    error_messages: List[str] = field(default_factory=list)      # Any error/warning messages on page

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def get_clickable(self) -> List[UIElement]:
        """Return elements that can be clicked."""
        return [e for e in self.elements if e.action_type in ("click", "navigate", "expand", "submit")]

    def get_inputs(self) -> List[UIElement]:
        """Return elements that accept text input."""
        return [e for e in self.elements if e.action_type == "type"]

    def get_by_type(self, element_type: str) -> List[UIElement]:
        """Filter elements by semantic type."""
        return [e for e in self.elements if e.element_type == element_type]

    def summarize_for_strategy(self) -> str:
        """
        Create a concise text summary for the Strategy Agent.
        This is what Strategy reads to decide the next action.
        """
        lines = [
            f"=== PAGE DISCOVERY ===",
            f"URL: {self.url}",
            f"Page Type: {self.page_type}",
            f"Description: {self.page_description}",
            "",
        ]

        if self.auth_indicators:
            lines.append(f"Auth State: {', '.join(self.auth_indicators)}")
            lines.append("")

        if self.error_messages:
            lines.append(f"Errors/Warnings: {', '.join(self.error_messages)}")
            lines.append("")

        if self.navigation_options:
            lines.append(f"Navigation: {', '.join(self.navigation_options)}")
            lines.append("")

        clickable = self.get_clickable()
        if clickable:
            lines.append(f"=== CLICKABLE ELEMENTS ({len(clickable)}) ===")
            for e in clickable:
                auth_tag = " [AUTH]" if e.requires_auth else ""
                lines.append(f"  [{e.element_id}] {e.label} → {e.action_type} | {e.selector}{auth_tag}")
                lines.append(f"         Context: {e.context}")
            lines.append("")

        inputs = self.get_inputs()
        if inputs:
            lines.append(f"=== INPUT FIELDS ({len(inputs)}) ===")
            for e in inputs:
                lines.append(f"  [{e.element_id}] {e.label} | {e.selector}")
                lines.append(f"         Context: {e.context}")
            lines.append("")

        return "\n".join(lines)


# ── System prompt ───────────────────────────────────────────────────

DISCOVERY_SYSTEM_PROMPT = """You are the Discovery Agent in ARGUS, an autonomous access control security testing system.

Your job: Analyze a web page screenshot and its DOM summary to identify ALL interactive and informational UI elements.

You must return ONLY valid JSON matching this exact schema:

{
    "page_description": "Brief one-line description of what this page is",
    "page_type": "one of: login, dashboard, product_list, product_detail, admin_panel, form, profile, search, cart, checkout, registration, settings, other",
    "elements": [
        {
            "element_id": "elem_0",
            "element_type": "one of: button, link, input, form, nav_item, menu, card, text, other",
            "label": "Human-readable label for this element",
            "selector": "CSS selector to target this element (use the most specific selector available from the DOM)",
            "action_type": "one of: click, type, submit, navigate, expand, scroll, none",
            "context": "What this element does or represents (e.g., 'Navigates to admin panel', 'Search input for products')",
            "is_visible": true,
            "is_enabled": true,
            "requires_auth": false
        }
    ],
    "navigation_options": ["List of high-level navigation paths available, e.g., 'Admin Panel', 'User Profile', 'Product Search'"],
    "auth_indicators": ["Signs of authentication state, e.g., 'Logged in as admin@juice-sh.op', 'Login button visible'"],
    "error_messages": ["Any error or warning messages visible on the page"]
}

IMPORTANT RULES:
1. Use the DOM summary selectors when available — they are the most reliable for automation.
2. If the screenshot shows elements NOT in the DOM (dynamically rendered), describe them and give your best selector guess.
3. Prioritize interactive elements (buttons, links, inputs, forms) over static text.
4. For EACH element, provide clear context about what it does — the Strategy Agent depends on this.
5. Mark elements as requires_auth=true if they appear to need login to function.
6. Be thorough but focused — skip decorative elements, icons without function, and CSS framework artifacts.
7. Return ONLY the JSON object — no markdown, no explanation, no preamble.
8. IMPORTANT: Pay special attention to navigation elements that lead to OTHER PAGES of the application — sidebar menus, navigation bars, account menus, footer links,
   and any links to user-specific pages (orders, addresses, basket, profile, settings). These are critical for the Strategy Agent to discover new attack surface.
   Mark their context clearly, e.g., "Navigates to order history page".

"""


# ── Discovery Agent class ──────────────────────────────────────────

class DiscoveryAgent:
    """
    Analyzes a page using GPT-4o multimodal to produce a structured
    list of UI elements with semantic understanding.
    """

    def __init__(self, llm_client: LLMClient):
        self._llm = llm_client

    def analyze(
        self,
        screenshot_path: Path,
        dom_summary: str,
        url: str,
        network_summary: str = "",
    ) -> DiscoveryResult:
        """
        Run Discovery Agent on a page.

        Args:
            screenshot_path: Path to the page screenshot.
            dom_summary: Text from Vision.summarize_for_llm().
            url: Current page URL.
            network_summary: Optional network traffic summary for extra context.

        Returns:
            DiscoveryResult with all identified elements.
        """
        # Append network context to DOM summary if available
        full_context = dom_summary
        if network_summary:
            full_context += f"\n\n{network_summary}"

        logger.info("Discovery Agent analyzing: %s", url)

        # Call the LLM
        response = self._llm.call_discovery(
            screenshot_path=screenshot_path,
            dom_summary=full_context,
            url=url,
            system_prompt=DISCOVERY_SYSTEM_PROMPT,
        )

        # Parse into structured result
        return self._parse_response(response, url)

    def _parse_response(self, response: Dict[str, Any], url: str) -> DiscoveryResult:
        """
        Convert LLM JSON response into a DiscoveryResult.
        Handles malformed responses gracefully.
        """
        # Check for parse errors from LLMClient
        if "parse_error" in response:
            logger.warning("Discovery got unparseable response, returning empty result")
            return DiscoveryResult(
                url=url,
                page_description="Failed to analyze page",
                page_type="other",
                error_messages=[f"LLM parse error: {response['parse_error']}"],
            )

        # Build UIElement list
        elements = []
        raw_elements = response.get("elements", [])

        for i, raw in enumerate(raw_elements):
            try:
                elem = UIElement(
                    element_id=raw.get("element_id", f"elem_{i}"),
                    element_type=raw.get("element_type", "other"),
                    label=raw.get("label", "Unknown"),
                    selector=raw.get("selector", ""),
                    action_type=raw.get("action_type", "none"),
                    context=raw.get("context", ""),
                    is_visible=raw.get("is_visible", True),
                    is_enabled=raw.get("is_enabled", True),
                    requires_auth=raw.get("requires_auth", False),
                    bounding_box=raw.get("bounding_box"),
                )
                elements.append(elem)
            except Exception as e:
                logger.warning("Skipping malformed element %d: %s", i, e)
                continue

        result = DiscoveryResult(
            url=url,
            page_description=response.get("page_description", "Unknown page"),
            page_type=response.get("page_type", "other"),
            elements=elements,
            navigation_options=response.get("navigation_options", []),
            auth_indicators=response.get("auth_indicators", []),
            error_messages=response.get("error_messages", []),
        )

        logger.info(
            "Discovery found %d elements (%d clickable, %d inputs) on %s page",
            len(result.elements),
            len(result.get_clickable()),
            len(result.get_inputs()),
            result.page_type,
        )

        return result