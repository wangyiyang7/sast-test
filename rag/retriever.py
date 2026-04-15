"""
Retriever — high-level RAG interface used by the Strategy Agent.

Abstracts away ChromaDB details. The Strategy Agent calls format_context()
to get a ready-to-insert text block for its LLM prompt.

Combines:
  1. Relevant static knowledge (OWASP patterns, Juice Shop vuln locations)
  2. Similar past findings (what has already been discovered or tested)
"""

import logging
from typing import Any, Dict, List, Optional

from src.rag.knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)

# Similarity distance threshold — results above this are too dissimilar to be useful.
# ChromaDB cosine distance: 0.0 = identical, 2.0 = completely opposite.
# Anything below 0.8 is generally relevant for our use case.
_DISTANCE_THRESHOLD = 0.8


class Retriever:
    """
    High-level RAG retrieval interface for the Strategy Agent.

    Usage:
        retriever = Retriever(knowledge_base)

        context = retriever.format_context(
            page_description="Admin panel showing user list",
            current_url="http://localhost:3000/#/administration",
            current_role="jim",
            action_history_summary="Last action: navigate to /#/",
        )
        # Inject context string into Strategy Agent's LLM prompt
    """

    def __init__(self, kb: KnowledgeBase):
        self._kb = kb

    def format_context(
        self,
        page_description: str,
        current_url: str,
        current_role: str,
        action_history_summary: str = "",
        n_static: int = 3,
        n_findings: int = 2,
    ) -> str:
        """
        Build a RAG context block ready to be inserted into the Strategy Agent prompt.

        Retrieves the most relevant static knowledge docs and past findings,
        filters out low-relevance results, and formats everything as labelled
        sections the LLM can easily parse.

        Args:
            page_description:       One-line description of the current page (from Discovery).
            current_url:            Current browser URL.
            current_role:           Currently active Juice Shop role.
            action_history_summary: Short summary of recent actions (optional, improves retrieval).
            n_static:               Max static knowledge docs to include.
            n_findings:             Max past findings to include.

        Returns:
            Formatted multi-line string for direct injection into LLM prompt.
            Returns an empty string if both queries return no results.
        """
        query_text = self._build_query(
            page_description, current_url, current_role, action_history_summary
        )

        static_docs = self._kb.query_static(query_text, n_results=n_static)
        past_findings = self._kb.query_findings(query_text, n_results=n_findings)

        # Filter by distance threshold
        static_docs = [d for d in static_docs if d["distance"] < _DISTANCE_THRESHOLD]
        past_findings = [d for d in past_findings if d["distance"] < _DISTANCE_THRESHOLD]

        if not static_docs and not past_findings:
            logger.debug("RAG returned no relevant results for query: %s", query_text[:80])
            return ""

        sections = []

        if static_docs:
            sections.append("=== RELEVANT SECURITY KNOWLEDGE (from RAG) ===")
            for i, doc in enumerate(static_docs, 1):
                meta = doc["metadata"]
                vuln_tag = meta.get("vuln_type", "general")
                source = meta.get("source", meta.get("category", ""))
                sections.append(f"[{i}] ({vuln_tag}) {doc['text']}")
                if source:
                    sections.append(f"    Source: {source}")
            sections.append("")

        if past_findings:
            sections.append("=== SIMILAR PAST FINDINGS (from previous runs) ===")
            for i, doc in enumerate(past_findings, 1):
                meta = doc["metadata"]
                is_vuln = meta.get("is_vulnerability", "false") == "true"
                vuln_type = meta.get("vuln_type", "none")
                role = meta.get("role", "?")
                url_after = meta.get("url_after", "?")
                vuln_label = f"VULNERABILITY ({vuln_type})" if is_vuln else "No finding"
                sections.append(
                    f"[{i}] Role={role} → {url_after} | Result: {vuln_label}"
                )
                sections.append(f"    {doc['text'][:200]}...")
            sections.append("")

        return "\n".join(sections)

    def get_known_vulnerable_urls(self) -> List[str]:
        """
        Return a list of URL patterns known to be vulnerable, from past findings.
        Useful for the Strategy Agent to prioritise re-testing under different roles.
        """
        if self._kb.get_findings_count() == 0:
            return []

        # Query for confirmed vulnerabilities
        results = self._kb.query_findings(
            text="vulnerability IDOR RBAC access control",
            n_results=20,
        )

        urls = []
        for doc in results:
            meta = doc["metadata"]
            if meta.get("is_vulnerability") == "true":
                url = meta.get("url_after", "")
                if url and url not in urls:
                    urls.append(url)
        return urls

    def get_untested_juice_shop_routes(self, visited_urls: List[str]) -> List[str]:
        """
        Cross-reference visited URLs against known Juice Shop vulnerability locations
        and return routes that haven't been visited yet.

        Args:
            visited_urls: List of URLs the agent has already visited this run.

        Returns:
            List of unvisited high-priority URL patterns to suggest to Strategy.
        """
        # Pull all Juice Shop-specific docs
        results = self._kb.query_static(
            text="juice shop vulnerable endpoint URL",
            n_results=10,
        )

        priority_routes = []
        for doc in results:
            meta = doc["metadata"]
            if meta.get("category") == "juice_shop":
                url_pattern = meta.get("url_pattern", "")
                if url_pattern:
                    # Check if any visited URL contains this pattern
                    already_visited = any(url_pattern in v for v in visited_urls)
                    if not already_visited:
                        priority_routes.append(url_pattern)

        return priority_routes

    # ── Internal ─────────────────────────────────────────────────────

    def _build_query(
        self,
        page_description: str,
        current_url: str,
        current_role: str,
        action_history_summary: str,
    ) -> str:
        """Combine context signals into a single query string for embedding."""
        parts = [
            f"Current page: {page_description}",
            f"URL: {current_url}",
            f"Role: {current_role}",
        ]
        if action_history_summary:
            parts.append(f"Recent actions: {action_history_summary}")
        return ". ".join(parts)
