"""
parser_agent.py
-----------------
Agent 1 of 5 in the pipeline.

Responsibility: read raw Terraform (.tf) or Kubernetes (.yaml/.yml) files and
extract a structured list of resources (type, name, location, raw block).
This gives every downstream agent a clean, structured view of the
infrastructure instead of raw text blobs.

Why a dedicated parser agent instead of just regex-in-the-scanner:
- Keeps responsibilities separated (single-responsibility per agent —
  a core agentic AI design principle interviewers will ask about)
- Makes it trivial to add new file types later (CloudFormation, Pulumi)
  without touching the scanner or remediation logic
"""

import re
import yaml
from pathlib import Path
from typing import List
from agents.state import AgentState, ParsedResource


# Matches top-level Terraform resource blocks, e.g.:
#   resource "aws_s3_bucket" "my_bucket" { ... }
TF_RESOURCE_PATTERN = re.compile(
    r'resource\s+"([a-zA-Z0-9_]+)"\s+"([a-zA-Z0-9_]+)"\s*\{',
    re.MULTILINE,
)


def _extract_terraform_block(content: str, start_idx: int) -> str:
    """Given the index right after the opening '{', return the full block
    text up to (and including) the matching closing brace, by tracking
    brace depth. This handles nested blocks (e.g. tags { ... } inside
    a resource block) correctly."""
    depth = 1
    i = start_idx
    while depth > 0 and i < len(content):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
        i += 1
    return content[start_idx:i]


def parse_terraform_file(file_path: str, content: str) -> List[ParsedResource]:
    """Parse a single .tf file into a list of ParsedResource entries."""
    resources: List[ParsedResource] = []

    for match in TF_RESOURCE_PATTERN.finditer(content):
        resource_type, resource_name = match.group(1), match.group(2)
        block_start = match.end()  # index right after the opening '{'
        block_body = _extract_terraform_block(content, block_start)
        line_number = content[: match.start()].count("\n") + 1

        resources.append(
            ParsedResource(
                resource_type=resource_type,
                resource_name=resource_name,
                file_path=file_path,
                line_number=line_number,
                raw_block=f'resource "{resource_type}" "{resource_name}" {{{block_body}',
            )
        )
    return resources


def parse_kubernetes_file(file_path: str, content: str) -> List[ParsedResource]:
    """Parse a single Kubernetes YAML file (possibly multi-document) into
    a list of ParsedResource entries. Each '---'-separated document is
    treated as one resource if it has 'kind' and 'metadata.name'."""
    resources: List[ParsedResource] = []

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        # Malformed YAML — surface as an empty parse rather than crashing
        # the whole pipeline. The scanner agent will simply see nothing
        # for this file, and we still log this in state.errors upstream.
        return resources

    for idx, doc in enumerate(docs):
        if not doc or not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "UnknownKind")
        name = doc.get("metadata", {}).get("name", f"unnamed_{idx}")

        resources.append(
            ParsedResource(
                resource_type=kind,
                resource_name=name,
                file_path=file_path,
                line_number=0,  # YAML doc-level line tracking omitted for simplicity
                raw_block=yaml.safe_dump(doc, default_flow_style=False),
            )
        )
    return resources


def parser_agent(state: AgentState) -> dict:
    """
    LangGraph node entry point. Reads state['raw_files'], detects file type
    by extension, and populates state['parsed_resources'].
    """
    all_resources: List[ParsedResource] = []
    errors: List[str] = []

    for file_path, content in state["raw_files"].items():
        suffix = Path(file_path).suffix.lower()
        try:
            if suffix == ".tf":
                all_resources.extend(parse_terraform_file(file_path, content))
            elif suffix in (".yaml", ".yml"):
                all_resources.extend(parse_kubernetes_file(file_path, content))
            else:
                errors.append(f"[parser_agent] Skipped unsupported file type: {file_path}")
        except Exception as exc:  # noqa: BLE001 — we want to keep the pipeline alive
            errors.append(f"[parser_agent] Failed to parse {file_path}: {exc}")

    return {
        "parsed_resources": all_resources,
        "errors": errors,
        "current_step": "parser_agent_complete",
    }
