"""
build_knowledge_base.py
-------------------------
One-time (or re-run-when-knowledge-changes) script that ingests
knowledge_base/security_knowledge.json into a local Chroma vector store.

Uses HuggingFace's sentence-transformers running LOCALLY — no API calls,
no cost, no rate limits. This is the free alternative to OpenAI embeddings
and is exactly the kind of cost-conscious engineering decision worth
mentioning in an interview ("how would you reduce embedding costs at scale?").

Run this once before starting the Streamlit app:
    python knowledge_base/build_knowledge_base.py
"""

import json
import os
from pathlib import Path

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document

KB_DIR = Path(__file__).parent
KNOWLEDGE_JSON = KB_DIR / "security_knowledge.json"
CHROMA_DB_DIR = os.getenv("CHROMA_DB_DIR", str(KB_DIR / "chroma_db"))

# all-MiniLM-L6-v2: small, fast, free, runs on CPU, good enough quality
# for this corpus size. Swapping to a larger model is a one-line change
# if recall quality needs improving later.
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def load_knowledge_documents() -> list[Document]:
    with open(KNOWLEDGE_JSON, "r", encoding="utf-8") as f:
        entries = json.load(f)

    documents = []
    for entry in entries:
        documents.append(
            Document(
                page_content=entry["content"],
                metadata={
                    "id": entry["id"],
                    "title": entry["title"],
                    "category": entry["category"],
                },
            )
        )
    return documents


def build_vector_store() -> Chroma:
    documents = load_knowledge_documents()
    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)

    vector_store = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        persist_directory=CHROMA_DB_DIR,
        collection_name="devsecops_security_knowledge",
    )
    return vector_store


if __name__ == "__main__":
    print(f"Loading knowledge documents from {KNOWLEDGE_JSON}...")
    docs = load_knowledge_documents()
    print(f"Loaded {len(docs)} documents.")

    print(f"Building Chroma vector store at {CHROMA_DB_DIR} (this runs locally, no API calls)...")
    build_vector_store()
    print("Done. Vector store is ready for the RAG knowledge agent.")
