"""
Orchestrator — the central coordinator of the ARGUS agent loop.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import re as _re

from src.eyes.vision import Vision
from src.eyes.network import NetworkInterceptor
from src.brain.llm_client import LLMClient
from src.brain.discovery import DiscoveryAgent, DiscoveryResult
from src.brain.strategy import StrategyAgent
from src.brain.analyzer import AnalyzerAgent
from src.rag import KnowledgeBase, Retriever
from src.hands.browser import BrowserManager
from src.hands.auth import AuthManager, JUICE_SHOP_USERS
from config import SCREENSHOTS_DIR, JUICE_SHOP_URL
from src.access_map.mapper import AccessMap

logger = logging.getLogger(__name__)


# ── Data structures ─────────────────────────────────────────────────

@dataclass
class PageState:
    url: str
    timestamp: str
    screenshot_path: Optional[Path] = None
    dom_summary: str = ""
    network_summary: str = ""
    discovery: Optional[DiscoveryResult] = None
    raw_dom: Optional[Dict[str, Any]] = None
    raw_network: Optional[List[Dict]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "timestamp": self.timestamp,
            "screenshot_path": str(self.screenshot_path) if self.screenshot_path else None,
            "dom_summary": self.dom_summary,
            "network_summary": self.network_summary,
            "discovery": self.discovery.to_dict() if self.discovery else None,
        }


@dataclass
class AgentAction:
    action_type: str
    selector: str = ""
    value: str = ""
    role: str = ""
    rationale: str = ""
    element_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActionRecord:
    action: AgentAction
    state_before: PageState
    state_after: PageState
    role: str
    iteration: int
    timestamp: str
    finding: Optional[Dict] = None
    success: bool = True
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "state_before_url": self.state_before.url,
            "state_after_url": self.state_after.url,
            "role": self.role,
            "iteration": self.iteration,
            "timestamp": self.timestamp,
            "finding": self.finding,
            "success": self.success,
            "error": self.error,
        }


@dataclass
class OrchestratorConfig:
    max_iterations: int = 10
    max_actions_per_role: int = 20
    exploration_first: bool = True
    start_role: str = "admin"
    roles_to_test: List[str] = field(default_factory=lambda: ["admin", "jim"])
    screenshots_dir: Path = Path(SCREENSHOTS_DIR)
    stop_on_idor: bool = True        # stop as soon as any IDOR is confirmed
    min_idor_findings: int = 1       # how many unique IDORs before stopping


# ── Orchestrator ────────────────────────────────────────────────────

class Orchestrator:

    def __init__(self, config: OrchestratorConfig = None, strategy=None, analyzer=None):
        self.config = config or OrchestratorConfig()

        self._browser: Optional[BrowserManager] = None
        self._auth: Optional[AuthManager] = None
        self._vision: Optional[Vision] = None
        self._network: Optional[NetworkInterceptor] = None
        self._llm: Optional[LLMClient] = None
        self._discovery: Optional[DiscoveryAgent] = None
        self._strategy = strategy
        self._analyzer = analyzer

        self.access_map = AccessMap()
        self.history: List[ActionRecord] = []
        self.findings: List[Dict[str, Any]] = []
        self.current_role: str = ""
        self.iteration: int = 0
        self.visited_urls: set = set()
        self._is_running: bool = False

        # Selectors that have failed — Strategy will be told to avoid these
        self._dead_selectors: set = {"button[aria-label='Open Sidenav']",
                                     }

    # ── Lifecycle ───────────────────────────────────────────────────

    def setup(self) -> None:
        logger.info("Orchestrator setup starting...")

        self._browser = BrowserManager()
        self._browser.launch()
        logger.info("Browser launched")

        self._auth = AuthManager(self._browser)
        self._vision = Vision(self._browser.page, self.config.screenshots_dir)
        self._network = NetworkInterceptor(self._browser.page)
        self._llm = LLMClient()
        self._discovery = DiscoveryAgent(self._llm)

        self._kb = KnowledgeBase()
        self._kb.setup()
        self._retriever = Retriever(self._kb)
        logger.info("RAG ready -- %d static docs, %d past findings",
                    self._kb.get_static_count(), self._kb.get_findings_count())

        if self._strategy is None:
            self._strategy = StrategyAgent(self._llm, retriever=self._retriever)
        if self._analyzer is None:
            self._analyzer = AnalyzerAgent(self._llm)

        self._browser.navigate(JUICE_SHOP_URL)
        self._dismiss_welcome()

        self._auth.login(self.config.start_role)
        self.current_role = self.config.start_role
        logger.info("Logged in as: %s", self.current_role)
        logger.info("Orchestrator setup complete")

    def teardown(self) -> None:
        logger.info("Orchestrator teardown...")
        if self._network and self._network._is_capturing:
            self._network.stop_capture()
        if self._browser:
            self._browser.close()
        logger.info("Teardown complete")

    # ── Main loop ───────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        self._is_running = True
        logger.info("=" * 60)
        logger.info("ARGUS agent loop starting (max %d iterations)", self.config.max_iterations)
        logger.info("=" * 60)

        try:
            while self._is_running and not self._should_stop():
                self.iteration += 1
                logger.info("-- Iteration %d --", self.iteration)
                try:
                    self._run_single_iteration()
                except Exception as e:
                    logger.error("Error in iteration %d: %s", self.iteration, e, exc_info=True)
                    if self.iteration >= self.config.max_iterations:
                        break
                    continue
        except KeyboardInterrupt:
            logger.info("Agent loop interrupted by user")
        finally:
            self._is_running = False

        summary = self._build_summary()
        self._save_access_map()
        self._save_report(summary)
        return summary

    def _run_single_iteration(self) -> None:
        # Step 1: Eyes
        logger.info("Step 1: Eyes capturing page state...")
        state_before = self._capture_page_state(f"iter{self.iteration}_before")

        # Recover if stuck on a raw API response page
        if state_before.url and "/#/" not in state_before.url and state_before.url != JUICE_SHOP_URL:
            logger.warning("Stuck on raw API page %s -- navigating back to app", state_before.url)
            self._browser.navigate(JUICE_SHOP_URL)
            self._browser.page.wait_for_timeout(500)
            state_before = self._capture_page_state(f"iter{self.iteration}_before_recovered")

        # Step 2: Discovery
        logger.info("Step 2: Discovery analyzing page...")
        discovery_result = self._run_discovery(state_before)
        state_before.discovery = discovery_result
        self._save_discovery(discovery_result, self.iteration)
        self.visited_urls.add(state_before.url)

        # Step 3: Strategy
        logger.info("Step 3: Strategy deciding next action...")
        action = self._get_strategy_action(discovery_result, state_before)

        # Block consecutive role switches
        if action.action_type == "switch_role":
            if self.history and self.history[-1].action.action_type == "switch_role":
                logger.warning("Blocking consecutive switch_role -- forcing navigate instead.")
                action = AgentAction(
                    action_type="navigate",
                    value=JUICE_SHOP_URL + "/#/basket",
                    rationale="[AUTO] Consecutive role switch blocked -- navigating to basket.",
                )

        # Step 4: Handle role switch
        if action.action_type == "switch_role":
            self._handle_role_switch(action.role)
            return

        # Step 5: Execute
        logger.info("Step 5: Hands executing: %s %s", action.action_type,
                    action.selector or action.value)
        self._network.start_capture()
        exec_success, exec_error = self._execute_action(action)
        self._browser.page.wait_for_timeout(500)

        # Step 6: Eyes after
        logger.info("Step 6: Eyes capturing after state...")
        state_after = self._capture_page_state(f"iter{self.iteration}_after")
        self._network.stop_capture()

        # Feed traffic into AccessMap
        if state_after.raw_network:
            self.access_map.record_traffic(
                traffic=state_after.raw_network,
                role=self.current_role,
                iteration=self.iteration,
                base_url=JUICE_SHOP_URL,
            )
        self.access_map.record_page_navigation(
            url=state_after.url,
            status_code=200,
            role=self.current_role,
            iteration=self.iteration,
        )
        logger.info("AccessMap now has %d endpoints", len(self.access_map))
        logger.info("AccessMap: %d endpoints, roles=%s, pending_idor=%d",
            len(self.access_map),
            self.access_map.known_roles,
            len(self.access_map.get_pending_idor_targets(self.current_role, JUICE_SHOP_URL)),
        )

        # Step 7: Analyzer
        logger.info("Step 7: Analyzer evaluating...")
        finding = self._run_analyzer(action, state_before, state_after)

        # Step 8: Record
        record = ActionRecord(
            action=action,
            state_before=state_before,
            state_after=state_after,
            role=self.current_role,
            iteration=self.iteration,
            timestamp=datetime.now().isoformat(),
            finding=finding,
            success=exec_success,
            error=exec_error,
        )
        self.history.append(record)

        if action.action_type == "test_access" and action.value:
            self.access_map.mark_idor_tested(
                role=self.current_role,
                method="GET",
                url=action.value,
            )

        self._kb.save_finding(
            finding=finding,
            role=self.current_role,
            url_before=state_before.url,
            url_after=state_after.url,
            action_type=action.action_type,
            iteration=self.iteration,
        )

        if finding and finding.get("is_vulnerability"):
            self.findings.append(finding)
            logger.warning("VULNERABILITY FOUND: %s (%s) -- %s",
                finding.get("vulnerability_type"),
                finding.get("severity"),
                finding.get("description"),
            )

        logger.info("Iteration %d complete. %s -> %s",
                    self.iteration, state_before.url, state_after.url)

    # ── Component wrappers ──────────────────────────────────────────

    def _capture_page_state(self, label: str) -> PageState:
        screenshot_path = self._vision.capture_full_page(filename=label)
        dom_data = self._vision.extract_dom()
        dom_summary = self._vision.summarize_for_llm(dom_data)
        net_summary = ""
        raw_network = []
        if self._network._is_capturing:
            net_summary = self._network.summarize_for_llm()
            raw_network = self._network.get_captured_traffic()
        return PageState(
            url=self._browser.get_url(),
            timestamp=datetime.now().isoformat(),
            screenshot_path=screenshot_path,
            dom_summary=dom_summary,
            network_summary=net_summary,
            raw_dom=dom_data,
            raw_network=raw_network,
        )

    def _run_discovery(self, state: PageState) -> DiscoveryResult:
        return self._discovery.analyze(
            screenshot_path=state.screenshot_path,
            dom_summary=state.dom_summary,
            url=state.url,
            network_summary=state.network_summary,
        )

    def _get_strategy_action(self, discovery: DiscoveryResult, state: PageState) -> AgentAction:
        history_summary = [
            {
                "iteration": r.iteration,
                "action": r.action.action_type,
                "selector": r.action.selector,
                "url_before": r.state_before.url,
                "url_after": r.state_after.url,
                "success": r.success,
            }
            for r in self.history[-10:]
        ]

        raw = self._strategy.decide(
            discovery_summary=discovery.summarize_for_strategy(),
            access_map=self.access_map.summarise_for_strategy(
                current_role=self.current_role, base_url=JUICE_SHOP_URL),
            action_history=history_summary,
            current_role=self.current_role,
            network_summary=state.network_summary,
            available_roles=self.config.roles_to_test,
            dead_selectors=list(self._dead_selectors),
        )

        return AgentAction(
            action_type=raw.get("action_type", "navigate"),
            selector=raw.get("selector", ""),
            value=raw.get("value", ""),
            role=raw.get("role", ""),
            rationale=raw.get("rationale", ""),
            element_id=raw.get("element_id", ""),
        )

    def _execute_action(self, action: AgentAction) -> tuple:
        """Execute action. On any failure, mark selector dead and return False."""
        try:
            if action.action_type == "click":
                sel = action.selector
                if sel in self._dead_selectors:
                    logger.warning("Skipping dead selector: %s", sel)
                    return False, "dead selector -- skipped"
                try:
                    self._browser.click(sel)
                except Exception as e:
                    logger.warning("Click failed, marking dead: %s -- %s", sel, e)
                    self._dead_selectors.add(sel)
                    try:
                        self._browser.page.keyboard.press("Escape")
                        self._browser.page.wait_for_timeout(300)
                    except Exception:
                        pass
                    return False, str(e)

            elif action.action_type == "type":
                sel = action.selector
                if sel in self._dead_selectors:
                    logger.warning("Skipping dead selector: %s", sel)
                    return False, "dead selector -- skipped"
                try:
                    self._browser.fill(sel, action.value)
                except Exception as e:
                    
                    logger.warning("Fill failed, marking dead: %s -- %s", sel, e)
                    self._dead_selectors.add(sel)
                    try:
                        self._browser.page.keyboard.press("Escape")
                        self._browser.page.wait_for_timeout(300)
                    except Exception:
                        pass
                    return False, str(e)

            elif action.action_type == "submit":
                sel = action.selector
                if sel in self._dead_selectors:
                    return False, "dead selector -- skipped"
                try:
                    self._browser.click(sel)
                except Exception as e:
                    self._dead_selectors.add(sel)
                    return False, str(e)

            elif action.action_type == "scroll":
                self._browser.page.evaluate("window.scrollBy(0, 500)")

            elif action.action_type in ("navigate", "test_access"):
                url = action.value
                if url.startswith("/"):
                    url = JUICE_SHOP_URL.rstrip("/") + url

                if action.action_type == "test_access":
                    result = self._browser.api_call(url)
                    if result.get("error") or result.get("is_html"):
                        self._browser.navigate(url)
                    else:
                        self._network._captured.append({
                            "method": "GET",
                            "url": url,
                            "status": result.get("status"),
                            "response_body": result.get("body"),
                            "request_headers": {"Authorization": "Bearer <present>"},
                            "timestamp": datetime.now().isoformat(),
                        })
                else:
                    self._browser.navigate(url)

            else:
                logger.warning("Unknown action type: %s", action.action_type)
                return False, f"Unknown action type: {action.action_type}"

            self._browser.page.wait_for_timeout(1000)
            return True, ""

        except Exception as e:
            logger.error("Action execution failed: %s", e)
            try:
                self._browser.page.keyboard.press("Escape")
                self._browser.page.wait_for_timeout(300)
            except Exception:
                pass
            return False, str(e)

    def _run_analyzer(self, action: AgentAction, before: PageState, after: PageState) -> Dict:
        return self._analyzer.evaluate(
            action=action.to_dict(),
            state_before=before.to_dict(),
            state_after=after.to_dict(),
            current_role=self.current_role,
            network_traffic=after.raw_network or [],
        )

    # ── Role management ─────────────────────────────────────────────

    def _handle_role_switch(self, target_role: str) -> None:
        if target_role not in JUICE_SHOP_USERS:
            logger.error("Unknown role: %s", target_role)
            return
        logger.info("Switching role: %s -> %s", self.current_role, target_role)
        logger.info("Access map before switch:\n%s",
            self.access_map.dump_human_readable(
                current_role=self.current_role, base_url=JUICE_SHOP_URL))
        if self._auth.switch_user(target_role):
            self.current_role = target_role
            logger.info("Now logged in as: %s", self.current_role)
        else:
            logger.error("Failed to switch to role: %s", target_role)

    # ── Termination ─────────────────────────────────────────────────

    def _should_stop(self) -> bool:
        if self.iteration >= self.config.max_iterations:
            logger.info("Reached max iterations (%d)", self.config.max_iterations)
            return True

        if len(self.history) >= 5:
            if all(not r.success for r in self.history[-5:]):
                logger.warning("5 consecutive failures -- stopping")
                return True

        if self.config.stop_on_idor:
            confirmed = [
                f for f in self.findings
                if f.get("vulnerability_type") == "IDOR"
                and f.get("confidence", 0) >= 0.8
            ]
            # Deduplicate by endpoint template so /rest/basket/1 and
            # /rest/basket/2 count as one finding, not two
            unique_endpoints = {
                _extract_endpoint(f.get("evidence", "") + f.get("description", ""))
                for f in confirmed
            }
            if len(unique_endpoints) >= self.config.min_idor_findings:
                logger.info(
                    "Stopping early -- %d unique IDOR endpoint(s) confirmed: %s",
                    len(unique_endpoints), unique_endpoints,
                )
                return True

        return False

    # ── Helpers ─────────────────────────────────────────────────────

    def _dismiss_welcome(self) -> None:
        try:
            self._browser.page.wait_for_selector(
                "button[aria-label='Close Welcome Banner']", timeout=3000)
            self._browser.click("button[aria-label='Close Welcome Banner']")
            self._browser.page.wait_for_timeout(500)
        except Exception:
            logger.debug("No welcome banner to dismiss")
        try:
            self._browser.click("a[aria-label='dismiss cookie message']")
            self._browser.page.wait_for_timeout(500)
        except Exception:
            logger.debug("No cookie banner to dismiss")

    def _build_summary(self) -> Dict[str, Any]:
        return {
            "total_iterations": self.iteration,
            "total_findings": len(self.findings),
            "findings": self.findings,
            "urls_visited": list(self.visited_urls),
            "roles_tested": list({r.role for r in self.history}),
            "llm_usage": self._llm.get_usage_stats() if self._llm else {},
            "actions_taken": len(self.history),
            "success_rate": (
                sum(1 for r in self.history if r.success) / len(self.history)
                if self.history else 0
            ),
            "access_map": self.access_map.to_dict(),
        }

    def _save_report(self, summary: Dict[str, Any]) -> None:
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"argus_report_{timestamp}.json"
        full_report = {**summary, "history": [r.to_dict() for r in self.history]}
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(full_report, f, indent=2, default=str, ensure_ascii=False)
        logger.info("Report saved to: %s", report_path)

    def _save_access_map(self) -> None:
        map_dir = Path("reports")
        map_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = map_dir / f"access_map_{timestamp}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.access_map.dump_human_readable(
                current_role=self.current_role,
                base_url=JUICE_SHOP_URL,
            ))
        logger.info("Access map saved to: %s", path)

    def _save_discovery(self, result: DiscoveryResult, iteration: int) -> None:
        discovery_dir = Path("reports/discovery")
        discovery_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = discovery_dir / f"discovery_iter{iteration}_{self.current_role}_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str, ensure_ascii=False)
        logger.info("Discovery saved to: %s", path)

def _extract_endpoint(text: str) -> str:
    """
    Pull the first /api/ or /rest/ path out of a finding's evidence string
    and normalise numeric IDs so /rest/basket/1 == /rest/basket/2.
    Falls back to the raw text if no path is found.
    """
    match = _re.search(r'(/(?:api|rest)/[^\s"\',]+)', text)
    if not match:
        return text[:80]
    path = match.group(1)
    return _re.sub(r'/\d+', '/{id}', path)