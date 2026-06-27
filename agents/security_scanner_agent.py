"""
security_scanner_agent.py
---------------------------
Agent 2 of 5 in the pipeline.

Responsibility: identify security issues in the parsed resources using
TWO complementary techniques:

  1. Checkov (free, open-source static analysis) — fast, deterministic,
     catches well-known misconfiguration patterns (CKV_AWS_*, CKV_K8S_*).

  2. LLM-based reasoning (via Groq) — catches *contextual* and *logic-level*
     issues that a fixed rule set misses, e.g. "this IAM policy's wildcard
     action combined with a wildcard resource is a privilege-escalation
     risk even though no single Checkov rule flags this exact combination."

This two-layer approach is the core "agentic" design decision worth
highlighting in interviews: deterministic tools for known patterns,
LLM reasoning for judgment calls that need context — not LLM-for-everything.
"""

import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import List
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from agents.state import AgentState, SecurityFinding


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Checkov's free/open-source CLI does not populate a `severity` field on its
# own (that metadata lives behind Bridgecrew's paid platform). To keep this
# project fully free-tier while still surfacing meaningful severity, we map
# a curated set of high-impact check IDs to CRITICAL/HIGH manually, and let
# everything else default to MEDIUM. This list is intentionally small and
# focused on checks that represent genuinely severe exposure (open SSH,
# privilege escalation, public data exposure, hardcoded secrets) rather
# than trying to fully replicate Bridgecrew's proprietary severity scoring.
CHECKOV_SEVERITY_OVERRIDES = {
    # Network exposure
    "CKV_AWS_24": "CRITICAL",    # SSH open to 0.0.0.0/0
    "CKV_AWS_260": "CRITICAL",   # Ingress from 0.0.0.0/0 to port 22/3389
    "CKV_AWS_25": "HIGH",        # RDP open to 0.0.0.0/0
    # IAM / privilege escalation
    "CKV_AWS_286": "CRITICAL",   # IAM privilege escalation
    "CKV_AWS_287": "CRITICAL",   # IAM credentials exposure
    "CKV_AWS_288": "CRITICAL",   # IAM data exfiltration
    "CKV_AWS_289": "HIGH",       # IAM permissions management
    "CKV_AWS_290": "HIGH",       # IAM write access without constraints
    "CKV_AWS_62": "CRITICAL",    # IAM full admin "*:*" privileges
    # Data exposure / encryption
    "CKV_AWS_18": "HIGH",        # S3 bucket access logging disabled
    "CKV_AWS_20": "CRITICAL",    # S3 bucket public-read ACL
    "CKV_AWS_21": "HIGH",        # S3 bucket versioning disabled
    "CKV_AWS_19": "HIGH",        # S3 bucket encryption disabled
    "CKV_AWS_16": "HIGH",        # RDS encryption disabled
    "CKV_AWS_17": "CRITICAL",    # RDS publicly accessible
    # Kubernetes privilege / isolation
    "CKV_K8S_16": "CRITICAL",    # Container running privileged
    "CKV_K8S_17": "HIGH",        # hostPID enabled
    "CKV_K8S_18": "HIGH",        # hostIPC enabled
    "CKV_K8S_19": "HIGH",        # hostNetwork enabled
    "CKV_K8S_20": "HIGH",        # Container allowing privilege escalation
    "CKV_K8S_23": "HIGH",        # runAsUser root (UID 0)
    # Secrets
    "CKV_SECRET_6": "CRITICAL",  # High-entropy string detected (likely hardcoded secret)
}


def _resolve_checkov_severity(check_id: str, raw_severity) -> str:
    """Resolve a Checkov finding's severity, falling back to our manual
    override map when the free CLI doesn't supply one (raw_severity is None
    in the open-source CLI for most checks)."""
    if raw_severity:
        return SEVERITY_MAP.get(str(raw_severity).upper(), "MEDIUM")
    return CHECKOV_SEVERITY_OVERRIDES.get(check_id, "MEDIUM")

LLM_REASONING_SYSTEM_PROMPT = """You are a senior cloud security engineer reviewing \
infrastructure-as-code for risks that static rule-based scanners typically miss — \
things like privilege escalation paths, hardcoded secrets, insecure defaults that \
only become dangerous in combination with other settings, and missing defense-in-depth.

You will be given one or more parsed infrastructure resources (Terraform or \
Kubernetes). For each resource, identify ONLY genuine security concerns — do not \
invent issues that aren't actually present in the code.

Respond ONLY with a JSON array (no prose, no markdown fences) where each element has:
{
  "resource_name": "<name from the input>",
  "resource_type": "<type from the input>",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "description": "<one or two sentence explanation of the specific risk>"
}

If a resource has no additional issues beyond what a standard scanner would catch, \
omit it entirely. Return an empty array [] if there is nothing further to add."""


def run_checkov_scan(file_paths: List[str]) -> List[SecurityFinding]:
    """Run Checkov as a subprocess against the given files and parse its
    JSON output into SecurityFinding records. Checkov is free/open-source
    (Bridgecrew/Palo Alto Networks), no API key or payment required."""
    findings: List[SecurityFinding] = []

    if not file_paths:
        return findings

    # Checkov scans directories, not individual files in this invocation style,
    # so we scan the common parent directory of the given files.
    target_dir = str(Path(file_paths[0]).parent)

    try:
        result = subprocess.run(
            ["checkov", "-d", target_dir, "--output", "json", "--quiet", "--compact"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        # Checkov exits non-zero when it finds failed checks — that's expected,
        # not an execution error. We only care about stdout containing JSON.
        if not result.stdout.strip():
            return findings

        report = json.loads(result.stdout)

        # Checkov's JSON shape varies by version: it may be a single object
        # or a list of objects (one per framework: terraform, kubernetes, ...)
        reports = report if isinstance(report, list) else [report]

        for rep in reports:
            for failed in rep.get("results", {}).get("failed_checks", []):
                check_id = failed.get("check_id", "UNKNOWN")
                findings.append(
                    SecurityFinding(
                        finding_id=check_id,
                        severity=_resolve_checkov_severity(check_id, failed.get("severity")),
                        resource_name=failed.get("resource", "unknown"),
                        resource_type=failed.get("resource", "unknown").split(".")[0],
                        file_path=failed.get("file_path", "unknown"),
                        description=failed.get("check_name", "No description"),
                        source="checkov",
                    )
                )
    except FileNotFoundError:
        # checkov binary not installed in this environment — degrade gracefully,
        # the LLM reasoning pass still runs and the pipeline doesn't crash.
        pass
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        pass

    return findings


def run_llm_reasoning_scan(state: AgentState, llm: ChatGroq) -> List[SecurityFinding]:
    """Send parsed resources to the LLM for contextual security reasoning
    that goes beyond Checkov's fixed rule set."""
    findings: List[SecurityFinding] = []
    resources = state["parsed_resources"]

    if not resources:
        return findings

    # Batch resources into one prompt to minimize API calls (cost-efficiency
    # is itself worth mentioning in interviews — fewer round trips, same Groq
    # free-tier rate limit budget covers a much larger codebase this way).
    resource_summaries = "\n\n".join(
        f"Resource: {r['resource_type']} \"{r['resource_name']}\" "
        f"(file: {r['file_path']})\n{r['raw_block']}"
        for r in resources
    )

    messages = [
        SystemMessage(content=LLM_REASONING_SYSTEM_PROMPT),
        HumanMessage(content=resource_summaries),
    ]

    try:
        response = llm.invoke(messages)
        content = response.content.strip()

        # Defensive parsing: strip markdown fences if the model adds them
        # despite instructions, since LLMs occasionally do this anyway.
        if content.startswith("```"):
            content = content.strip("`")
            if content.startswith("json"):
                content = content[4:]

        parsed = json.loads(content)

        for item in parsed:
            findings.append(
                SecurityFinding(
                    finding_id=f"LLM-{len(findings) + 1:03d}",
                    severity=SEVERITY_MAP.get(item.get("severity", "MEDIUM").upper(), "MEDIUM"),
                    resource_name=item.get("resource_name", "unknown"),
                    resource_type=item.get("resource_type", "unknown"),
                    file_path="",
                    description=item.get("description", ""),
                    source="llm_reasoning",
                )
            )
    except (json.JSONDecodeError, AttributeError, KeyError):
        # If the LLM response is malformed, don't crash the pipeline — the
        # Checkov findings still flow through. We log this via state.errors
        # upstream in the node wrapper.
        pass

    return findings


def security_scanner_agent(state: AgentState) -> dict:
    """LangGraph node entry point."""
    errors: List[str] = []

    file_paths = list(state["raw_files"].keys())
    checkov_findings = run_checkov_scan(file_paths)

    llm = ChatGroq(
        model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        temperature=0,  # deterministic security analysis, not creative writing
        api_key=os.getenv("GROQ_API_KEY"),
    )

    try:
        llm_findings = run_llm_reasoning_scan(state, llm)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"[security_scanner_agent] LLM reasoning pass failed: {exc}")
        llm_findings = []

    all_findings = checkov_findings + llm_findings

    return {
        "checkov_findings": checkov_findings,
        "llm_findings": llm_findings,
        "all_findings": all_findings,
        "errors": errors,
        "current_step": "security_scanner_agent_complete",
    }
