"""
report_agent.py
------------------
Agent 5 of 5 in the pipeline.

Responsibility: take everything the previous four agents produced and
compile it into a single, polished markdown report — the kind of artifact
a developer or security reviewer would actually want to read, with a
summary at the top, findings grouped by severity, and grounded fixes
with citations.

This is deliberately a non-LLM agent (pure templating/aggregation). Not
every node in an agentic pipeline needs to call an LLM — knowing when
NOT to use the model (deterministic formatting) is itself a design
decision worth being able to defend in an interview.
"""

from datetime import datetime, timezone
from collections import Counter
from typing import List

from agents.state import AgentState

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_EMOJI_FREE_LABEL = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
}


def _build_summary_section(state: AgentState) -> str:
    findings = state["all_findings"]
    severity_counts = Counter(f["severity"] for f in findings)
    source_counts = Counter(f["source"] for f in findings)

    lines = [
        "## Summary",
        "",
        f"- **Total findings:** {len(findings)}",
        f"- **From Checkov (static rules):** {source_counts.get('checkov', 0)}",
        f"- **From LLM contextual reasoning:** {source_counts.get('llm_reasoning', 0)}",
        "",
        "**By severity:**",
        "",
    ]
    for severity in SEVERITY_ORDER:
        count = severity_counts.get(severity, 0)
        if count:
            lines.append(f"- {SEVERITY_EMOJI_FREE_LABEL[severity]} {count}")
    lines.append("")
    return "\n".join(lines)


def _build_findings_section(state: AgentState) -> str:
    remediation_by_finding_id = {
        r["finding_id"]: r for r in state.get("remediations", [])
    }

    findings_sorted = sorted(
        state["all_findings"],
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99,
    )

    lines = ["## Findings & Remediation", ""]

    for finding in findings_sorted:
        remediation = remediation_by_finding_id.get(finding["finding_id"])

        lines.append(
            f"### {SEVERITY_EMOJI_FREE_LABEL.get(finding['severity'], '')} "
            f"{finding['resource_type']} `{finding['resource_name']}`"
        )
        lines.append("")
        lines.append(f"- **Finding ID:** `{finding['finding_id']}`")
        lines.append(f"- **Source:** {finding['source']}")
        lines.append(f"- **File:** `{finding['file_path']}`" if finding["file_path"] else "")
        lines.append(f"- **Issue:** {finding['description']}")
        lines.append("")

        if remediation:
            if remediation.get("citation"):
                lines.append(f"**Why this matters** _(grounded in: {remediation['citation']})_:")
            else:
                lines.append("**Why this matters:**")
            lines.append("")
            lines.append(remediation.get("explanation", "No explanation generated."))
            lines.append("")

            if remediation.get("fixed_code_snippet"):
                # Guess a reasonable fence language from the resource type
                fence_lang = "hcl" if "aws_" in finding["resource_type"] else "yaml"
                lines.append("**Suggested fix:**")
                lines.append("")
                lines.append(f"```{fence_lang}")
                lines.append(remediation["fixed_code_snippet"])
                lines.append("```")
                lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(line for line in lines if line is not None)


def report_agent(state: AgentState) -> dict:
    """LangGraph node entry point."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scan_target = state.get("scan_target", "infrastructure")

    header = (
        f"# DevSecOps AI Agent — Security Scan Report\n\n"
        f"**Scan target:** {scan_target}  \n"
        f"**Generated:** {timestamp}  \n"
        f"**Files scanned:** {len(state.get('raw_files', {}))}  \n"
        f"**Resources parsed:** {len(state.get('parsed_resources', []))}\n\n"
        f"---\n\n"
    )

    summary = _build_summary_section(state)
    findings_section = _build_findings_section(state)

    error_section = ""
    if state.get("errors"):
        error_section = (
            "\n## Pipeline notes\n\n"
            + "\n".join(f"- {e}" for e in state["errors"])
            + "\n"
        )

    full_report = header + summary + "\n---\n\n" + findings_section + error_section

    return {
        "final_report_markdown": full_report,
        "current_step": "report_agent_complete",
    }
