"""
app.py
--------
Streamlit UI for the DevSecOps AI Agent.

Lets a user upload Terraform/Kubernetes files (or pick one of the bundled
sample vulnerable configs), runs the 5-agent LangGraph pipeline, and
displays the resulting security report with severity breakdown and
grounded remediations.

Run with:  streamlit run app.py
"""

import os
import sys
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

# Make the agents package importable when run via `streamlit run app.py`
sys.path.insert(0, str(Path(__file__).parent))

load_dotenv()

from agents.graph import run_pipeline  # noqa: E402

st.set_page_config(page_title="DevSecOps AI Agent", page_icon=None, layout="wide")

st.title("DevSecOps AI Agent")
st.caption(
    "Multi-agent system that audits Terraform & Kubernetes configs for security "
    "issues using Checkov, LLM reasoning, and RAG-grounded remediation — built with "
    "LangGraph, LangChain, Groq, and ChromaDB, entirely on free tiers."
)

if not os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API_KEY") == "your_groq_api_key_here":
    st.warning(
        "No GROQ_API_KEY found. Copy `.env.example` to `.env` and add a free key "
        "from https://console.groq.com/keys before running a scan."
    )

st.divider()

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("1. Choose input")
    source_choice = st.radio(
        "Scan target",
        ["Use bundled vulnerable sample (Terraform)", "Use bundled vulnerable sample (Kubernetes)", "Upload my own files"],
        index=0,
    )

    raw_files = {}
    scan_target = "terraform"

    if source_choice == "Use bundled vulnerable sample (Terraform)":
        sample_path = Path(__file__).parent / "test_configs" / "vulnerable" / "main.tf"
        raw_files = {str(sample_path): sample_path.read_text()}
        scan_target = "terraform"
        st.code(sample_path.read_text(), language="hcl", line_numbers=True)

    elif source_choice == "Use bundled vulnerable sample (Kubernetes)":
        sample_path = Path(__file__).parent / "test_configs" / "vulnerable" / "deployment.yaml"
        raw_files = {str(sample_path): sample_path.read_text()}
        scan_target = "kubernetes"
        st.code(sample_path.read_text(), language="yaml", line_numbers=True)

    else:
        uploaded_files = st.file_uploader(
            "Upload .tf or .yaml/.yml files",
            type=["tf", "yaml", "yml"],
            accept_multiple_files=True,
        )
        if uploaded_files:
            for uf in uploaded_files:
                raw_files[uf.name] = uf.read().decode("utf-8")
            scan_target = "kubernetes" if any(f.endswith((".yaml", ".yml")) for f in raw_files) else "terraform"

with col2:
    st.subheader("2. Run the agent pipeline")
    st.write(
        "Pipeline: parser agent -> security scanner agent (Checkov + LLM) -> "
        "RAG knowledge agent -> remediation agent -> report agent"
    )

    run_disabled = not raw_files
    if st.button("Run security scan", type="primary", disabled=run_disabled, use_container_width=True):
        with st.spinner("Running multi-agent pipeline... (parsing, scanning, retrieving, remediating, reporting)"):
            try:
                result = run_pipeline(raw_files, scan_target=scan_target)
                st.session_state["result"] = result
            except Exception as exc:  # noqa: BLE001
                st.error(f"Pipeline failed: {exc}")

st.divider()

if "result" in st.session_state:
    result = st.session_state["result"]

    findings = result.get("all_findings", [])
    st.subheader("3. Results")

    metric_cols = st.columns(4)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    metric_cols[0].metric("Critical", severity_counts["CRITICAL"])
    metric_cols[1].metric("High", severity_counts["HIGH"])
    metric_cols[2].metric("Medium", severity_counts["MEDIUM"])
    metric_cols[3].metric("Low", severity_counts["LOW"])

    tab1, tab2 = st.tabs(["Full report", "Raw pipeline state (debug)"])

    with tab1:
        st.markdown(result.get("final_report_markdown", "No report generated."))
        st.download_button(
            "Download report as markdown",
            data=result.get("final_report_markdown", ""),
            file_name="devsecops_scan_report.md",
            mime="text/markdown",
        )

    with tab2:
        st.write("Current step:", result.get("current_step"))
        st.write("Errors:", result.get("errors", []))
        st.json(
            {
                "parsed_resources_count": len(result.get("parsed_resources", [])),
                "checkov_findings_count": len(result.get("checkov_findings", [])),
                "llm_findings_count": len(result.get("llm_findings", [])),
                "remediations_count": len(result.get("remediations", [])),
            }
        )
