"""
state.py
---------
Defines the shared state object that flows through the LangGraph pipeline.
Every agent node receives this state, reads what it needs, and returns a
partial update that LangGraph merges back in. This is the single contract
that keeps five independently-written agents working together.
"""

from typing import TypedDict, List, Dict, Optional
from typing_extensions import Annotated
import operator


class ParsedResource(TypedDict):
    """A single infrastructure resource extracted from a config file."""
    resource_type: str       # e.g. "aws_s3_bucket", "Deployment", "Pod"
    resource_name: str       # e.g. "my_app_bucket"
    file_path: str           # source file this came from
    line_number: int         # approximate line in source file
    raw_block: str           # the raw HCL/YAML block, for LLM context


class SecurityFinding(TypedDict):
    """A single security issue identified by the scanner agent."""
    finding_id: str          # e.g. "CKV_AWS_18" or "LLM-001"
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    resource_name: str
    resource_type: str
    file_path: str
    description: str
    source: str               # "checkov" or "llm_reasoning"


class EnrichedFinding(TypedDict):
    """A finding enriched with retrieved knowledge-base context (RAG step)."""
    finding: SecurityFinding
    retrieved_context: List[str]   # CIS benchmark / best-practice snippets
    citation: str                   # which rule/benchmark this maps to


class Remediation(TypedDict):
    """A proposed fix for a single finding."""
    finding_id: str
    resource_name: str
    explanation: str         # why this is a problem, grounded in retrieved_context
    fixed_code_snippet: str  # corrected HCL/YAML
    citation: str


class AgentState(TypedDict):
    """
    The full pipeline state. Fields use Annotated + operator.add where
    multiple agents might append to a list across graph steps, so
    LangGraph knows how to merge concurrent updates safely.
    """
    # --- input ---
    raw_files: Dict[str, str]            # {file_path: file_content}
    scan_target: str                     # "terraform" or "kubernetes"

    # --- parser agent output ---
    parsed_resources: List[ParsedResource]

    # --- security scanner agent output ---
    checkov_findings: List[SecurityFinding]
    llm_findings: List[SecurityFinding]
    all_findings: List[SecurityFinding]

    # --- RAG knowledge agent output ---
    enriched_findings: List[EnrichedFinding]

    # --- remediation agent output ---
    remediations: List[Remediation]

    # --- report agent output ---
    final_report_markdown: str

    # --- bookkeeping ---
    errors: Annotated[List[str], operator.add]
    current_step: str
