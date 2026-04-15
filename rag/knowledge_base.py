"""
Knowledge base — ChromaDB wrapper for ARGUS RAG system.

Manages two collections:
  - "static_knowledge": OWASP docs, Juice Shop vuln locations, testing heuristics.
    Seeded once on first startup; never modified at runtime.
  - "run_findings":  Vulnerability findings saved automatically during agent runs.
    Grows over time; queried to surface similar past findings for the Strategy Agent.

Embeddings are generated via OpenAI text-embedding-3-small (1536 dims, cheap and fast).
ChromaDB persists to disk at CHROMA_DIR so knowledge accumulates across runs.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings
from openai import OpenAI

from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, CHROMA_DIR
from src.rag.documents import ALL_STATIC_DOCUMENTS

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

EMBEDDING_MODEL = "text-embedding-3-small"
STATIC_COLLECTION = "static_knowledge"
FINDINGS_COLLECTION = "run_findings"
_SEED_MARKER = "argus_seed_v1"   # stored in collection metadata to detect already-seeded DBs


class KnowledgeBase:
    """
    ChromaDB-backed vector store for ARGUS.

    Usage:
        kb = KnowledgeBase()
        kb.setup()                          # connect + seed static docs once

        results = kb.query_static(          # retrieve relevant OWASP/heuristic docs
            text="IDOR basket endpoint",
            n_results=3,
        )

        kb.save_finding(finding, role, url) # persist a run finding

        results = kb.query_findings(        # retrieve similar past findings
            text="customer accessing /api/Users",
            n_results=3,
        )
    """

    def __init__(self):
        self._client: Optional[chromadb.PersistentClient] = None
        self._static: Optional[chromadb.Collection] = None
        self._findings: Optional[chromadb.Collection] = None
        # OpenRouter for embeddings — same endpoint format as OpenAI
        self._openai = OpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
        )

    # ── Lifecycle ────────────────────────────────────────────────────

    def setup(self) -> None:
        """
        Connect to ChromaDB and seed static documents if not already done.
        Safe to call multiple times — seeding is idempotent.
        """
        chroma_path = Path(CHROMA_DIR)
        chroma_path.mkdir(parents=True, exist_ok=True)

        self._client = chromadb.PersistentClient(
            path=str(chroma_path),
            settings=Settings(anonymized_telemetry=False),
        )

        # Get or create both collections (chromadb creates if missing)
        self._static = self._client.get_or_create_collection(
            name=STATIC_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )
        self._findings = self._client.get_or_create_collection(
            name=FINDINGS_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )

        # Seed static docs only if not already done
        self._seed_static_if_needed()
        logger.info(
            "KnowledgeBase ready — static=%d docs, findings=%d docs",
            self._static.count(),
            self._findings.count(),
        )

    # ── Public query API ─────────────────────────────────────────────

    def query_static(
        self,
        text: str,
        n_results: int = 4,
        vuln_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve the most relevant static knowledge documents.

        Args:
            text:      Query text (e.g. current page description + URL).
            n_results: Max documents to return.
            vuln_type: Optional filter — only return docs of this vuln type.

        Returns:
            List of dicts with keys: id, text, metadata, distance.
        """
        return self._query(self._static, text, n_results, vuln_type)

    def query_findings(
        self,
        text: str,
        n_results: int = 3,
        vuln_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve similar past run findings.

        Args:
            text:      Query text (e.g. current URL + role + action description).
            n_results: Max documents to return.
            vuln_type: Optional filter — only return findings of this type.

        Returns:
            List of dicts with keys: id, text, metadata, distance.
        """
        if self._findings.count() == 0:
            return []
        return self._query(self._findings, text, n_results, vuln_type)

    def save_finding(
        self,
        finding: Dict[str, Any],
        role: str,
        url_before: str,
        url_after: str,
        action_type: str,
        iteration: int,
    ) -> None:
        """
        Persist a run finding to the findings collection.
        All findings are saved (not just confirmed vulnerabilities) so the
        Strategy Agent can learn what has already been tested.

        Args:
            finding:     The full finding dict from AnalyzerAgent.evaluate().
            role:        The role that performed the action.
            url_before:  Page URL before the action.
            url_after:   Page URL after the action.
            action_type: The action type performed (click, navigate, etc.).
            iteration:   Orchestrator iteration number.
        """
        # Build a human-readable text representation for embedding
        is_vuln = finding.get("is_vulnerability", False)
        vuln_type = finding.get("vulnerability_type") or "none"
        severity = finding.get("severity") or "none"
        description = finding.get("description", "")
        evidence = finding.get("evidence", "")

        text = (
            f"Role: {role}. "
            f"Action: {action_type}. "
            f"URL before: {url_before}. "
            f"URL after: {url_after}. "
            f"Vulnerability found: {is_vuln}. "
            f"Type: {vuln_type}. "
            f"Severity: {severity}. "
            f"Description: {description}. "
            f"Evidence: {evidence}."
        )

        # Stable ID based on content hash (prevents exact duplicates)
        doc_id = "finding_" + hashlib.sha256(text.encode()).hexdigest()[:16]

        metadata = {
            "role": role,
            "url_before": url_before[:200],     # ChromaDB metadata values must be str/int/float
            "url_after": url_after[:200],
            "action_type": action_type,
            "is_vulnerability": str(is_vuln),   # must be str for ChromaDB
            "vuln_type": vuln_type,
            "severity": severity,
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            embedding = self._embed(text)
            self._findings.upsert(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[text],
                metadatas=[metadata],
            )
            logger.info(
                "Saved finding to RAG: is_vuln=%s type=%s role=%s",
                is_vuln, vuln_type, role,
            )
        except Exception as e:
            # Never crash the agent loop because of a RAG write failure
            logger.warning("Failed to save finding to RAG: %s", e)

    def get_findings_count(self) -> int:
        """Return number of findings stored."""
        return self._findings.count() if self._findings else 0

    def get_static_count(self) -> int:
        """Return number of static docs stored."""
        return self._static.count() if self._static else 0

    # ── Internal helpers ─────────────────────────────────────────────

    def _seed_static_if_needed(self) -> None:
        """
        Insert all static documents into the static collection.
        Uses upsert so it's safe to call on every startup — existing docs
        are overwritten (not duplicated) because IDs are stable.
        """
        logger.info("Seeding static knowledge base (%d documents)...", len(ALL_STATIC_DOCUMENTS))

        ids = [doc["id"] for doc in ALL_STATIC_DOCUMENTS]
        texts = [doc["text"] for doc in ALL_STATIC_DOCUMENTS]
        metadatas = [doc["metadata"] for doc in ALL_STATIC_DOCUMENTS]

        # Batch embed all static docs in one API call
        try:
            embeddings = self._embed_batch(texts)
        except Exception as e:
            logger.error("Failed to embed static documents: %s", e)
            raise

        self._static.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=texts,
            metadatas=metadatas,
        )
        logger.info("Static knowledge base seeded with %d documents.", len(ids))

    def _query(
        self,
        collection: chromadb.Collection,
        text: str,
        n_results: int,
        vuln_type: Optional[str],
    ) -> List[Dict[str, Any]]:
        """
        Run a similarity query against a collection.

        Returns:
            List of result dicts sorted by relevance (closest first).
        """
        try:
            embedding = self._embed(text)

            # Build optional metadata filter
            where = {"vuln_type": vuln_type} if vuln_type else None

            # Clamp n_results to collection size to avoid ChromaDB errors
            count = collection.count()
            if count == 0:
                return []
            n = min(n_results, count)

            kwargs: Dict[str, Any] = {
                "query_embeddings": [embedding],
                "n_results": n,
                "include": ["documents", "metadatas", "distances"],
            }
            if where:
                kwargs["where"] = where

            response = collection.query(**kwargs)

            results = []
            for doc, meta, dist in zip(
                response["documents"][0],
                response["metadatas"][0],
                response["distances"][0],
            ):
                results.append({
                    "text": doc,
                    "metadata": meta,
                    "distance": dist,
                })
            return results

        except Exception as e:
            logger.warning("RAG query failed: %s", e)
            return []

    def _embed(self, text: str) -> List[float]:
        """Embed a single text string using OpenAI."""
        response = self._openai.embeddings.create(
            model=EMBEDDING_MODEL,
            input=text,
        )
        return response.data[0].embedding

    def _embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed a list of texts in a single OpenAI API call."""
        response = self._openai.embeddings.create(
            model=EMBEDDING_MODEL,
            input=texts,
        )
        # OpenAI returns embeddings in the same order as inputs
        return [item.embedding for item in response.data]
