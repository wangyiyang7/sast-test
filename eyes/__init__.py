"""
Eyes component — combines Vision (screenshot + DOM) and NetworkInterceptor
into a single PageState snapshot that the LLM agent can reason over.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from playwright.sync_api import Page

from src.eyes.vision import Vision
from src.eyes.network import NetworkInterceptor


@dataclass
class PageState:
    """
    Complete snapshot of a page at one point in time.
    Passed directly to the LLM reasoning module.
    """
    timestamp: str
    url: str
    title: str

    # From Vision (Week 5)
    screenshot_path: Optional[Path]
    dom_data: Dict[str, Any]
    dom_summary: str            # Pre-formatted text for LLM

    # From NetworkInterceptor (Week 6)
    network_traffic: List[Dict[str, Any]]
    resource_ids: List[Dict[str, Any]]
    auth_tokens: List[Dict[str, Any]]
    network_summary: str        # Pre-formatted text for LLM

    def to_llm_prompt(self) -> str:
        """
        Combine DOM and network summaries into one text block
        ready to be inserted into an LLM prompt.
        """
        return "\n\n".join([
            self.dom_summary,
            self.network_summary,
        ])

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (e.g. for saving as JSON)."""
        return {
            "timestamp": self.timestamp,
            "url": self.url,
            "title": self.title,
            "screenshot_path": str(self.screenshot_path) if self.screenshot_path else None,
            "dom_data": self.dom_data,
            "dom_summary": self.dom_summary,
            "network_traffic": self.network_traffic,
            "resource_ids": self.resource_ids,
            "auth_tokens": self.auth_tokens,
            "network_summary": self.network_summary,
        }


class Eyes:
    """
    Main interface for the agent to observe the browser.

    Usage:
        eyes = Eyes(page, screenshots_dir)
        eyes.start()                    # begin capturing network traffic

        # ... Playwright navigates / clicks ...

        state = eyes.capture()          # take a full snapshot right now
        print(state.to_llm_prompt())    # feed to LLM
    """

    def __init__(self, page: Page, screenshots_dir: Path):
        self.page = page
        self.vision = Vision(page, screenshots_dir)
        self.network = NetworkInterceptor(page)

    def start(self):
        """Start network capture. Call once before the agent begins browsing."""
        self.network.start_capture()

    def stop(self):
        """Stop network capture."""
        self.network.stop_capture()

    def capture(self, label: str = None) -> PageState:
        """
        Take a full snapshot of current page state:
          - screenshot
          - DOM extraction + LLM summary
          - all network traffic captured so far + LLM summary

        Args:
            label: optional name used for screenshot/DOM filenames

        Returns:
            PageState dataclass ready to hand to the LLM
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = label or timestamp

        # --- Visual + DOM (Vision, Week 5) ---
        screenshot_path = self.vision.capture_full_page(filename=f"screen_{filename}")
        dom_data = self.vision.extract_dom()
        dom_summary = self.vision.summarize_for_llm(dom_data)

        # --- Network (Week 6) ---
        traffic = self.network.get_captured_traffic()
        resource_ids = self.network.extract_resource_ids()
        auth_tokens = self.network.extract_auth_tokens()
        network_summary = self.network.summarize_for_llm()

        return PageState(
            timestamp=datetime.now().isoformat(),
            url=self.page.url,
            title=self.page.title(),
            screenshot_path=screenshot_path,
            dom_data=dom_data,
            dom_summary=dom_summary,
            network_traffic=traffic,
            resource_ids=resource_ids,
            auth_tokens=auth_tokens,
            network_summary=network_summary,
        )