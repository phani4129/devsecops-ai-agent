"""
graph.py
----------
Defines the LangGraph pipeline that orchestrates all five agents into a
single stateful, sequential graph:

    n8n webhook (external trigger, not part of this graph)
          |
          v
    parser_agent
          |
          v
    security_scanner_agent
          |
          v
    rag_knowledge_agent
          |
          v
    remediation_agent
          |
          v
    report_agent
          |
          v
    END (final_report_markdown ready)

Why LangGraph instead of a plain Python function chain:
- Explicit, inspectable state object shared across nodes (easier to debug
  and unit-test each agent in isolation)
- Built-in support for adding conditional branches later (e.g. skip
  remediation entirely if all_findings is empty, or add a human-approval
  interrupt before remediation is applied — a natural next iteration to
  mention in interviews as "how would you productionize this further")
- Matches the resume's stated "LangGraph" skill with a real, working
  multi-node graph rather than a single LLM call wrapped in branding
"""

from langgraph.graph import StateGraph, END

from agents.state import AgentState
from agents.parser_agent import parser_agent
from agents.security_scanner_agent import security_scanner_agent
from agents.rag_knowledge_agent import rag_knowledge_agent
from agents.remediation_agent import remediation_agent
from agents.report_agent import report_agent


def build_pipeline():
    """Construct and compile the LangGraph pipeline. Returns a runnable graph."""
    graph = StateGraph(AgentState)

    graph.add_node("parser_agent", parser_agent)
    graph.add_node("security_scanner_agent", security_scanner_agent)
    graph.add_node("rag_knowledge_agent", rag_knowledge_agent)
    graph.add_node("remediation_agent", remediation_agent)
    graph.add_node("report_agent", report_agent)

    graph.set_entry_point("parser_agent")
    graph.add_edge("parser_agent", "security_scanner_agent")
    graph.add_edge("security_scanner_agent", "rag_knowledge_agent")
    graph.add_edge("rag_knowledge_agent", "remediation_agent")
    graph.add_edge("remediation_agent", "report_agent")
    graph.add_edge("report_agent", END)

    return graph.compile()


def run_pipeline(raw_files: dict, scan_target: str = "terraform") -> AgentState:
    """
    Convenience entry point: run the full pipeline on a dict of
    {file_path: file_content} and return the final state.

    Example:
        result = run_pipeline({"main.tf": open("main.tf").read()})
        print(result["final_report_markdown"])
    """
    pipeline = build_pipeline()

    initial_state: AgentState = {
        "raw_files": raw_files,
        "scan_target": scan_target,
        "parsed_resources": [],
        "checkov_findings": [],
        "llm_findings": [],
        "all_findings": [],
        "enriched_findings": [],
        "remediations": [],
        "final_report_markdown": "",
        "errors": [],
        "current_step": "initialized",
    }

    final_state = pipeline.invoke(initial_state)
    return final_state
