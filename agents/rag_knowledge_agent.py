"""
rag_knowledge_agent.py
------------------------
Agent 3 of 5 in the pipeline.

Responsibility: for each security finding, retrieve the most relevant
best-practice document(s) from the local Chroma vector store. This is
the RAG step that grounds the Remediation Agent's explanations in real
benchmark text rather than letting the LLM invent justifications from
parametric memory — directly addressing the hallucination risk that
makes raw LLM-only security advice unreliable.
"""

import os
from typing import List
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

from agents.state import AgentState, EnrichedFinding

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
CHROMA_DB_DIR = os.getenv("CHROMA_DB_DIR", "./knowledge_base/chroma_db")
TOP_K_RESULTS = 2  # retrieve top 2 most relevant knowledge snippets per finding


def _get_vector_store() -> Chroma:
    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
    return Chroma(
        embedding_function=embeddings,
        persist_directory=CHROMA_DB_DIR,
        collection_name="devsecops_security_knowledge",
    )


def rag_knowledge_agent(state: AgentState) -> dict:
    """LangGraph node entry point."""
    errors: List[str] = []
    enriched_findings: List[EnrichedFinding] = []

    findings = state["all_findings"]
    if not findings:
        return {
            "enriched_findings": [],
            "errors": [],
            "current_step": "rag_knowledge_agent_complete",
        }

    try:
        vector_store = _get_vector_store()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"[rag_knowledge_agent] Failed to load vector store: {exc}")
        # Degrade gracefully: pass findings through with no retrieved context
        # rather than killing the whole pipeline.
        for finding in findings:
            enriched_findings.append(
                EnrichedFinding(finding=finding, retrieved_context=[], citation="")
            )
        return {
            "enriched_findings": enriched_findings,
            "errors": errors,
            "current_step": "rag_knowledge_agent_complete",
        }

    for finding in findings:
        # Build a retrieval query from the finding's description + resource type —
        # this is the part that benefits most from good prompt/query engineering.
        query = f"{finding['resource_type']} {finding['description']}"

        try:
            results = vector_store.similarity_search(query, k=TOP_K_RESULTS)
            retrieved_context = [doc.page_content for doc in results]
            citation = results[0].metadata.get("title", "") if results else ""
        except Exception as exc:  # noqa: BLE001
            errors.append(f"[rag_knowledge_agent] Retrieval failed for {finding['finding_id']}: {exc}")
            retrieved_context = []
            citation = ""

        enriched_findings.append(
            EnrichedFinding(
                finding=finding,
                retrieved_context=retrieved_context,
                citation=citation,
            )
        )

    return {
        "enriched_findings": enriched_findings,
        "errors": errors,
        "current_step": "rag_knowledge_agent_complete",
    }
