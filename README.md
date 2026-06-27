# DevSecOps AI Agent

A multi-agent AI system that automatically audits Terraform and Kubernetes
infrastructure-as-code for security misconfigurations, grounds its findings
in real security benchmarks via RAG, and generates fix suggestions with
citations — built entirely on free-tier tools, no paid API keys required.

## Why this project exists

Most "AI agent" portfolio projects are RAG chatbots over a PDF. This one
solves an actual engineering problem — catching security misconfigurations
in IaC before they reach production — by combining a deterministic static
analyzer (Checkov) with LLM-based contextual reasoning and RAG-grounded
remediation, orchestrated as a five-node LangGraph pipeline.

## Architecture

```
GitHub Push / Pull Request
        |
        v
GitHub Actions CI/CD Pipeline
        |
        |-- Python syntax check
        |-- Bandit security scan
        |-- Checkov IaC scan
        |-- Trivy filesystem scan
        |-- Upload security reports
        |
        v
CI/CD Dashboard in Streamlit


n8n Webhook / Streamlit UI / CLI Scan
        |
        v
parser_agent
reads Terraform/Kubernetes files and extracts IaC resources
        |
        v
security_scanner_agent
runs Checkov static rules and Groq LLM contextual reasoning
        |
        v
rag_knowledge_agent
retrieves relevant CIS Benchmark-style snippets from ChromaDB
        |
        v
remediation_agent
generates grounded fixes with explanation
        |
        v
report_agent
compiles findings, remediations, and evidence into one markdown report
        |
        v
Streamlit UI / CLI output / n8n response
```

Each agent is a LangGraph node that reads and writes to one shared state
object (`agents/state.py`). Agents are intentionally single-responsibility —
the parser doesn't scan, the scanner doesn't write fixes, the report agent
doesn't call an LLM at all. That separation is also what makes each agent
independently testable.

## Why a two-layer scanner (Checkov + LLM) instead of LLM-only

Checkov catches well-known, well-defined misconfiguration patterns fast and
deterministically — zero hallucination risk, but it can't reason about
*combinations* of settings or unusual context. The LLM reasoning pass catches
issues that need judgment (e.g. "this specific combination of settings adds
up to a privilege-escalation path even though no single rule flags it").
Using both, instead of replacing static analysis with an LLM, is the
deliberate design decision worth defending in an interview.

## Why RAG instead of asking the LLM directly

Without retrieval, an LLM asked "why is this insecure?" answers from its own
parametric memory — which drifts, can be wrong about specific benchmark
numbers, and can't be audited. Every remediation in this project cites a
specific knowledge-base entry (`knowledge_base/security_knowledge.json`,
modeled on CIS Benchmark controls) it was grounded in, so the explanation is
checkable against a real source instead of trusted blindly.

## Tech stack (100% free tier, no credit card needed anywhere)

| Component | Tool | Why free |
|---|---|---|
| Agent orchestration | LangGraph | Open-source |
| LLM calls | Groq API (Llama 3.3 70B) | Free tier, no card required |
| RAG retrieval chain | LangChain | Open-source |
| Vector store | ChromaDB | Local, open-source, no signup |
| Embeddings | HuggingFace `all-MiniLM-L6-v2` | Runs locally, no API calls |
| Static analysis | Checkov | Open-source (Bridgecrew/PANW) |
| UI | Streamlit | Free tier on Streamlit Community Cloud |
| Automation | n8n | Free self-hosted forever |

## Project structure

```
devsecops-ai-agent/
├── .github/
│   └── workflows/
│       └── devsecops-ci.yml              GitHub Actions CI/CD pipeline
├── agents/
│   ├── state.py                          shared LangGraph state schema
│   ├── parser_agent.py                   agent 1: extracts resources from IaC
│   ├── security_scanner_agent.py         agent 2: Checkov + LLM scanning
│   ├── rag_knowledge_agent.py            agent 3: retrieves grounding context
│   ├── remediation_agent.py              agent 4: generates grounded fixes
│   ├── report_agent.py                   agent 5: compiles the final report
│   └── graph.py                          wires all 5 agents into the LangGraph pipeline
├── utils/
│   └── github_actions.py                 GitHub API helper for CI/CD dashboard
├── knowledge_base/
│   ├── security_knowledge.json           CIS-Benchmark-style knowledge corpus
│   └── build_knowledge_base.py           one-time script to build the Chroma index
├── test_configs/
│   ├── vulnerable/                       sample configs with planted real issues
│   └── safe/                             remediated versions
├── n8n/
│   └── devsecops_scan_workflow.json      importable n8n workflow
├── app.py                                Streamlit UI
├── cli_scan.py                           CLI entry point
├── requirements.txt
├── setup.sh                              one-command local setup
├── .env.example
└── README.md
```

## Running it on your own laptop

### 1. Prerequisites
- Python 3.10+
- ~2GB free disk space (for the embedding model + dependencies)
- A free Groq API key — sign up at https://console.groq.com/keys (no card required)
- Generate Github API token

### 2. Setup (macOS / Linux)

```bash
git clone <your-repo-url>
cd devsecops-ai-agent
chmod +x setup.sh
./setup.sh
```

This creates a virtual environment, installs dependencies, copies
and builds the local Chroma vector store.

After it finishes, open `.env` and paste in your Groq API key and GitHub credentials:

```
GROQ_API_KEY=gsk_your_actual_key_here
GITHUB_REPO=
GITHUB_TOKEN=
```

### 2b. Setup (Windows)

In PowerShell or Git Bash:

```powershell
git clone <your-repo-url>
cd devsecops-ai-agent
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python knowledge_base\build_knowledge_base.py
```

Then edit `.env` and add your Groq API key and GitHub credentials.

### 3. Run the app

```bash
source .venv/bin/activate      # or .venv\Scripts\activate on Windows
streamlit run app.py
```

This opens a browser at `http://localhost:8501`. Pick one of the bundled
vulnerable sample configs (Terraform or Kubernetes), click "Run security
scan," and watch the five agents run in sequence, ending in a full markdown
report with severity breakdown and grounded fixes.

### 4. Or run it from the command line

```bash
python cli_scan.py --path test_configs/vulnerable --fail-on CRITICAL
```

This is the same pipeline, callable as a CI/CD security gate — it exits
with code 1 if any CRITICAL finding is present, which is exactly the pattern
you'd wire into a GitHub Actions step to block a merge.

### 5. Optional: n8n automation

Import `n8n/devsecops_scan_workflow.json` into a free self-hosted n8n
instance (`npx n8n` or Docker) to trigger scans via webhook — e.g. from a
GitHub push event — and route CRITICAL findings to Slack, Jira, or wherever
your team already gets alerts.

## Testing against the bundled sample configs

`test_configs/vulnerable/main.tf` and `deployment.yaml` contain real,
intentionally planted issues: a public S3 bucket, an SSH port open to
`0.0.0.0/0`, a wildcard IAM policy, an unencrypted public RDS instance, a
privileged Kubernetes container with `hostNetwork`/`hostPID` enabled, and
hardcoded secrets in plain env vars. Running Checkov alone against this
sample surfaces 50+ findings; the agent pipeline triages them by real
severity and explains the top issues with grounded citations.

`test_configs/safe/main.tf` is the corrected version, useful for confirming
the pipeline doesn't produce false positives on a properly configured file.

## Possible extensions (good interview talking points)

- Add a LangGraph conditional edge that skips remediation entirely when
  `all_findings` is empty, instead of always running the full chain
- Add a human-in-the-loop interrupt before remediations are written back to
  disk, using LangGraph's interrupt/resume support
- Swap the local Chroma store for a hosted vector DB and add multi-tenant
  knowledge bases per cloud provider (AWS / Azure / GCP specific benchmarks)
- Add an evaluation harness that measures false-positive/false-negative rate
  of the LLM reasoning pass against a labeled set of configs
