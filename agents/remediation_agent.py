"""
remediation_agent.py
-----------------------
Agent 4 of 5 in the pipeline.

Responsibility: for each enriched finding (finding + retrieved best-practice
context), generate a concrete fix: a corrected code snippet plus a plain-
English explanation that CITES the retrieved context rather than relying
purely on the LLM's own judgment. This is the agent where RAG grounding
actually pays off — the explanation is constrained to reference real
benchmark text, which is the entire point of doing RAG instead of a bare
LLM call.
"""

import os
from typing import List
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from agents.state import AgentState, Remediation

REMEDIATION_SYSTEM_PROMPT = """You are a senior cloud security engineer writing \
remediation guidance for a developer who just received a security finding.

You will be given:
1. The security finding (what's wrong)
2. Retrieved best-practice context from a security knowledge base (ground truth)
3. The original code snippet

Your job:
- Write a SHORT explanation (2-3 sentences) of why this is a risk, grounded in \
  the retrieved context. Do not invent justifications not supported by the \
  retrieved context — if the context doesn't fully explain the risk, say what \
  the context DOES say and keep your own addition minimal.
- Write a corrected version of the code snippet that fixes the specific issue.
- Keep the corrected snippet in the same language/format as the input (HCL for \
  Terraform, YAML for Kubernetes).

Respond ONLY with a JSON object (no prose, no markdown fences):
{
  "explanation": "<grounded explanation>",
  "fixed_code_snippet": "<corrected code>"
}"""


def remediation_agent(state: AgentState) -> dict:
    """LangGraph node entry point."""
    errors: List[str] = []
    remediations: List[Remediation] = []

    enriched_findings = state["enriched_findings"]
    if not enriched_findings:
        return {
            "remediations": [],
            "errors": [],
            "current_step": "remediation_agent_complete",
        }

    llm = ChatGroq(
        model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        temperature=0.1,  # low but nonzero — slight room for natural phrasing
        api_key=os.getenv("GROQ_API_KEY"),
    )

    # Find the original raw code for each finding's resource, if available,
    # by matching against parsed_resources. Falls back to empty string.
    resource_lookup = {
        r["resource_name"]: r["raw_block"] for r in state.get("parsed_resources", [])
    }

    for enriched in enriched_findings:
        finding = enriched["finding"]
        original_code = resource_lookup.get(finding["resource_name"], "// original code not available")
        context_block = "\n\n".join(enriched["retrieved_context"]) or "No additional context retrieved."

        user_content = (
            f"FINDING:\n"
            f"Resource: {finding['resource_type']} \"{finding['resource_name']}\"\n"
            f"Severity: {finding['severity']}\n"
            f"Description: {finding['description']}\n\n"
            f"RETRIEVED CONTEXT:\n{context_block}\n\n"
            f"ORIGINAL CODE:\n{original_code}"
        )

        messages = [
            SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
            HumanMessage(content=user_content),
        ]

        try:
            response = llm.invoke(messages)
            content = response.content.strip()

            if content.startswith("```"):
                content = content.strip("`")
                if content.startswith("json"):
                    content = content[4:]

            import json
            parsed = json.loads(content)

            remediations.append(
                Remediation(
                    finding_id=finding["finding_id"],
                    resource_name=finding["resource_name"],
                    explanation=parsed.get("explanation", ""),
                    fixed_code_snippet=parsed.get("fixed_code_snippet", ""),
                    citation=enriched["citation"],
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(
                f"[remediation_agent] Failed to generate remediation for "
                f"{finding['finding_id']}: {exc}"
            )
            # Still produce a placeholder so the report agent has something
            # to show rather than silently dropping the finding.
            remediations.append(
                Remediation(
                    finding_id=finding["finding_id"],
                    resource_name=finding["resource_name"],
                    explanation="Automatic remediation generation failed for this finding. "
                                 "Manual review recommended.",
                    fixed_code_snippet="",
                    citation=enriched["citation"],
                )
            )

    return {
        "remediations": remediations,
        "errors": errors,
        "current_step": "remediation_agent_complete",
    }
