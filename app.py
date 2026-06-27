import os
import sys
from pathlib import Path
from datetime import datetime

import requests
import streamlit as st
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))

load_dotenv()

from agents.graph import run_pipeline


def parse_github_repo(repo_value):
    repo_value = (repo_value or "").strip()
    repo_value = repo_value.replace("https://github.com/", "").replace("http://github.com/", "")
    repo_value = repo_value.strip("/")

    parts = repo_value.split("/")
    if len(parts) < 2:
        return None, None

    return parts[0], parts[1]


@st.cache_data(ttl=60)
def fetch_github_actions_runs(repo_value, token=None, limit=10):
    owner, repo = parse_github_repo(repo_value)

    if not owner or not repo:
        return {"error": "Enter repo like phani4129/devsecops-ai-agent"}

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"

    try:
        response = requests.get(url, headers=headers, params={"per_page": limit}, timeout=20)
    except requests.RequestException as exc:
        return {"error": f"Could not connect to GitHub API: {exc}"}

    if response.status_code == 401:
        return {"error": "GitHub token is wrong or expired."}

    if response.status_code == 403:
        return {"error": "GitHub permission issue. Token needs Actions read access."}

    if response.status_code == 404:
        return {"error": "Repository not found. For private repo, add GITHUB_TOKEN."}

    if not response.ok:
        return {"error": f"GitHub API error {response.status_code}: {response.text[:200]}"}

    return response.json()


def status_text(status, conclusion):
    if status != "completed":
        return "IN PROGRESS"

    if conclusion == "success":
        return "SUCCESS"

    if conclusion == "failure":
        return "FAILED"

    if conclusion == "cancelled":
        return "CANCELLED"

    if status:
        return status.upper()

    return "UNKNOWN"


def render_cicd_dashboard():
    st.subheader("GitHub Actions CI/CD Dashboard")

    groq_key = os.getenv("GROQ_API_KEY", "")
    github_repo = os.getenv("GITHUB_REPO", "phani4129/devsecops-ai-agent")
    github_token = os.getenv("GITHUB_TOKEN", "")

    if groq_key:
        st.success("GROQ API Key Configured")
    else:
        st.error("GROQ API Key Missing")

    repo_value = st.text_input("GitHub Repository", value=github_repo)
    token_value = st.text_input("GitHub Token Optional", value=github_token, type="password")
    limit = st.number_input("Number of workflow runs", min_value=1, max_value=30, value=10)

    if st.button("Refresh CI/CD Status"):
        st.cache_data.clear()

    data = fetch_github_actions_runs(repo_value, token_value, int(limit))

    if data.get("error"):
        st.warning(data["error"])
        return

    runs = data.get("workflow_runs", [])

    if not runs:
        st.info("No workflow runs found.")
        return

    latest = runs[0]

    st.metric(
        "Latest CI/CD Status",
        status_text(latest.get("status"), latest.get("conclusion")),
    )

    rows = []

    for run in runs:
        created = run.get("created_at", "")
        updated = run.get("updated_at", "")
        duration = "-"

        try:
            start = datetime.fromisoformat(created.replace("Z", "+00:00"))
            end = datetime.fromisoformat(updated.replace("Z", "+00:00"))
            seconds = int((end - start).total_seconds())
            duration = f"{seconds // 60}m {seconds % 60}s"
        except Exception:
            pass

        rows.append(
            {
                "Status": status_text(run.get("status"), run.get("conclusion")),
                "Workflow": run.get("name"),
                "Branch": run.get("head_branch"),
                "Commit": (run.get("head_sha") or "")[:7],
                "Event": run.get("event"),
                "Duration": duration,
                "URL": run.get("html_url"),
            }
        )

    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.link_button("Open latest workflow in GitHub", latest.get("html_url"))


st.set_page_config(page_title="DevSecOps AI Agent", layout="wide")

st.title("DevSecOps AI Agent")

st.caption(
    "A Generative AI-powered DevSecOps platform that performs Infrastructure as Code "
    "security scanning, AI-assisted vulnerability remediation, GitHub Actions CI/CD "
    "monitoring, and automated security reporting."
)

tab1, tab2 = st.tabs(["Security Scanner", "CI/CD Dashboard"])

with tab2:
    render_cicd_dashboard()

with tab1:
    if not os.getenv("GROQ_API_KEY"):
        st.warning("No GROQ_API_KEY found. Add it in .env file.")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("1. Choose input")

        source_choice = st.radio(
            "Scan target",
            [
                "Use bundled vulnerable sample (Terraform)",
                "Use bundled vulnerable sample (Kubernetes)",
                "Upload my own files",
            ],
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
                for file in uploaded_files:
                    raw_files[file.name] = file.read().decode("utf-8")

                scan_target = "kubernetes" if any(
                    f.endswith((".yaml", ".yml")) for f in raw_files
                ) else "terraform"

    with col2:
        st.subheader("2. Run the Agent Pipeline")

        st.write(
            "**Pipeline:** Parser Agent -> Security Scanner Agent (Checkov + Groq LLM) -> "
            "RAG Knowledge Agent -> Remediation Agent -> Report Agent"
        )

        if st.button("Run security scan", type="primary", disabled=not raw_files):
            with st.spinner("Running DevSecOps AI pipeline... Please wait."):
                try:
                    result = run_pipeline(raw_files, scan_target=scan_target)
                    st.session_state["result"] = result

                    st.success(
                        "Scan is complete. Please scroll down and check the report below."
                    )

                except Exception as exc:
                    st.error(f"Pipeline failed: {exc}")

    if "result" in st.session_state:
        result = st.session_state["result"]
        findings = result.get("all_findings", [])

        st.subheader("3. Results")

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for finding in findings:
            severity = finding.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Critical", severity_counts["CRITICAL"])
        c2.metric("High", severity_counts["HIGH"])
        c3.metric("Medium", severity_counts["MEDIUM"])
        c4.metric("Low", severity_counts["LOW"])

        report_tab, debug_tab = st.tabs(["Full Report", "Debug"])

        with report_tab:
            st.markdown(result.get("final_report_markdown", "No report generated."))
            st.download_button(
                "Download Report",
                data=result.get("final_report_markdown", ""),
                file_name="devsecops_scan_report.md",
                mime="text/markdown",
            )

        with debug_tab:
            st.json(
                {
                    "current_step": result.get("current_step"),
                    "errors": result.get("errors", []),
                    "parsed_resources_count": len(result.get("parsed_resources", [])),
                    "checkov_findings_count": len(result.get("checkov_findings", [])),
                    "llm_findings_count": len(result.get("llm_findings", [])),
                    "remediations_count": len(result.get("remediations", [])),
                }
            )