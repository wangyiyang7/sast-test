"""
RAG package for ARGUS.

Provides retrieval-augmented generation for the Strategy Agent,
grounding its decisions in OWASP knowledge and past run findings.

Quick start:
    from src.rag import KnowledgeBase, Retriever

    kb = KnowledgeBase()
    kb.setup()                    # connect to ChromaDB + seed static docs

    retriever = Retriever(kb)
    context = retriever.format_context(
        page_description="Product list page",
        current_url="http://localhost:3000/#/",
        current_role="jim",
    )
"""

from src.rag.knowledge_base import KnowledgeBase
from src.rag.retriever import Retriever

__all__ = ["KnowledgeBase", "Retriever"]
