"""
OpenAI GPT-4o Autonomous Pentest Orchestrator — Phase 5.

Replaces the Cowork/Claude loop with a fully autonomous
GPT-4o agent-loop that calls V9 MCP tools via the REST API.

Architecture:
  run_full_engagement()
    └─ run_phase(phase)       ← GPT-4o with tool use (gpt-4o)
         └─ call_mcp_tool()   ← posts to :6019/mcp
    └─ generate_poc(finding)  ← Codex o3 PoC synthesis
    └─ XBOWBenchmark          ← efficiency tracking
"""

import json
import pathlib
import sys
import time
import uuid
from typing import Any

import requests

sys.path.insert(0, "C:/users/chirayu/redteamv9")

from agents.xbow_benchmark import XBOWBenchmark

# ── Configuration ─────────────────────────────────────────────────────────────

MCP_BASE = "http://127.0.0.1:6019"
BEARER_FILE = pathlib.Path("C:/Temp/rtv7_bearer.txt")

GPT4O_MODEL = "gpt-4o"
CODEX_MODEL = "o3"                    # Codex o3 for PoC generation
MAX_ITERATIONS_PER_PHASE = 12
PHASES = ["recon", "sqli", "xss", "auth", "idor", "config", "report"]


# ── MCP client helpers ────────────────────────────────────────────────────────

def _bearer() -> str:
    try:
        return BEARER_FILE.read_text().strip()
    except Exception:
        return ""


def _mcp_session() -> tuple[dict, str]:
    """Initialize MCP session, return (headers, session_id)."""
    bearer = _bearer()
    base_headers = {
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    r = requests.post(
        f"{MCP_BASE}/mcp",
        json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "openai-orchestrator", "version": "1.0"},
            },
        },
        headers=base_headers, timeout=10, stream=True,
    )
    session_id = r.headers.get("mcp-session-id", "")
    for line in r.iter_lines():
        if line and line.startswith(b"data: "):
            break  # drain initialize response
    return {**base_headers, "mcp-session-id": session_id}, session_id


def _sse_json(resp) -> dict:
    for line in resp.iter_lines():
        if line and line.startswith(b"data: "):
            try:
                return json.loads(line[6:])
            except Exception:
                pass
    return {}


def call_mcp_tool(headers: dict, tool_name: str,
                  arguments: dict) -> dict:
    """Call one MCP tool and return the parsed result dict."""
    r = requests.post(
        f"{MCP_BASE}/mcp",
        json={
            "jsonrpc": "2.0", "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
        headers=headers, timeout=30, stream=True,
    )
    obj = _sse_json(r)
    content = obj.get("result", {}).get("content", [{}])
    if content and isinstance(content[0], dict):
        raw = content[0].get("text", "{}")
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw}
    return obj.get("result", {})


def get_tool_schemas(headers: dict) -> list[dict]:
    """Fetch all tool schemas from the live MCP server."""
    r = requests.post(
        f"{MCP_BASE}/mcp",
        json={"jsonrpc": "2.0", "id": 2,
              "method": "tools/list", "params": {}},
        headers=headers, timeout=10, stream=True,
    )
    obj = _sse_json(r)
    tools = obj.get("result", {}).get("tools", [])
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("inputSchema",
                                    {"type": "object", "properties": {}}),
            },
        }
        for t in tools
    ]


# ── Phase runner (GPT-4o agentic loop) ───────────────────────────────────────

SYSTEM_PROMPT = """You are RedTeam V9 Executor — an autonomous web application
penetration tester. You operate inside a strictly authorised engagement.

MANDATORY RULES:
1. Call declare_intent() at the start of EVERY phase before any attack tool.
2. After declare_intent(), call only the tools listed in the returned
   tools_authorised list.
3. Call get_intent_incidents() at the end of every phase.
4. Never call shell_exec unless explicitly in tools_authorised.
5. Stay within the declared scope — never touch out-of-scope hosts.

PHASE PROTOCOL:
- recon   → fingerprint_target, crawl_links, enumerate_endpoints, check_headers
- sqli    → declare_intent(sqli_phase) then test_sqli on all injection points
- xss     → declare_intent(xss_phase) then test_xss, verify_xss_browser
- auth    → declare_intent(auth_phase) then test_auth_bypass, test_session_fixation
- idor    → declare_intent(idor_phase) then test_idor
- config  → declare_intent(config_phase) then check_headers, test_csrf, analyse_cookies
- report  → generate_report

When you have confirmed all tools for this phase, stop and return a JSON summary.
"""


def run_phase(session_id: str, phase: str, target_url: str,
              headers: dict, benchmark: XBOWBenchmark,
              openai_client: Any = None) -> dict:
    """
    Run one pentest phase with GPT-4o tool-use loop.
    Returns findings dict for this phase.
    """
    if openai_client is None:
        # Stub for unit tests / offline runs
        return {"phase": phase, "status": "skipped_no_client",
                "findings": [], "tool_calls": 0}

    schemas = get_tool_schemas(headers)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"Session: {session_id}\n"
            f"Target: {target_url}\n"
            f"Current phase: {phase}\n"
            f"Execute all {phase} phase tasks. "
            f"Start with declare_intent() for this phase."
        )},
    ]

    findings = []
    iterations = 0

    while iterations < MAX_ITERATIONS_PER_PHASE:
        iterations += 1
        response = openai_client.chat.completions.create(
            model=GPT4O_MODEL,
            messages=messages,
            tools=schemas,
            tool_choice="auto",
        )
        msg = response.choices[0].message
        benchmark.record_api_call(
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
        )

        if not msg.tool_calls:
            break  # model finished phase

        tool_results = []
        for tc in msg.tool_calls:
            benchmark.record_tool_call()
            tool_name = tc.function.name
            try:
                args = json.loads(tc.function.arguments)
            except Exception:
                args = {}

            result = call_mcp_tool(headers, tool_name, args)

            # Track findings
            if tool_name == "add_finding":
                findings.append(result)
                if len(findings) == 1:
                    benchmark.record_first_finding(
                        severity=args.get("severity", "medium"),
                        title=args.get("title", ""),
                    )

            tool_results.append({
                "tool_call_id": tc.id,
                "role": "tool",
                "content": json.dumps(result),
            })

        messages.append(msg)
        messages.extend(tool_results)

    return {
        "phase": phase,
        "status": "complete",
        "findings": findings,
        "tool_calls": iterations,
    }


# ── PoC generator (Codex o3) ─────────────────────────────────────────────────

POC_SYSTEM = """You are an expert security researcher.
Given a vulnerability finding from an automated pentest,
generate a minimal, self-contained proof-of-concept exploit
in Python (requests library). Include comments explaining
each step. Output ONLY the Python code block."""


def generate_poc(finding: dict, openai_client: Any = None) -> str:
    """Use Codex o3 to generate a PoC for a confirmed finding."""
    if openai_client is None:
        return "# PoC generation skipped (no OpenAI client configured)"

    prompt = (
        f"Vulnerability: {finding.get('title', 'Unknown')}\n"
        f"Endpoint: {finding.get('endpoint', '')}\n"
        f"Evidence: {finding.get('evidence', '')}\n"
        f"CVSS: {finding.get('cvss', '')}\n\n"
        f"Generate a minimal Python PoC using the requests library."
    )

    response = openai_client.chat.completions.create(
        model=CODEX_MODEL,
        messages=[
            {"role": "system", "content": POC_SYSTEM},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content or ""


# ── Full engagement loop ──────────────────────────────────────────────────────

def run_full_engagement(
    target_url: str,
    session_id: str = None,
    phases: list[str] = None,
    openai_api_key: str = None,
    generate_pocs: bool = True,
) -> dict:
    """
    Run a complete autonomous pentest engagement via GPT-4o.

    Parameters
    ----------
    target_url : str
        The target application URL.
    session_id : str, optional
        Session identifier. Auto-generated if not provided.
    phases : list[str], optional
        Phases to run. Defaults to all 7 phases.
    openai_api_key : str, optional
        OpenAI API key. Falls back to OPENAI_API_KEY env var.
    generate_pocs : bool
        Whether to run Codex o3 PoC generation per finding.

    Returns
    -------
    dict
        Engagement summary including findings and benchmark metrics.
    """
    import os
    session_id = session_id or f"v9_{int(time.time())}"
    phases = phases or PHASES

    # Initialize OpenAI client (optional — graceful degradation if absent)
    openai_client = None
    try:
        import openai
        api_key = openai_api_key or os.environ.get("OPENAI_API_KEY", "")
        if api_key:
            openai_client = openai.OpenAI(api_key=api_key)
    except ImportError:
        pass

    # Initialize MCP session
    mcp_headers, mcp_session_id = _mcp_session()

    # Initialize benchmark
    benchmark = XBOWBenchmark(session_id)

    # Create V9 session
    call_mcp_tool(mcp_headers, "create_session", {
        "session_id": session_id,
        "target_url": target_url,
        "goal": "Full autonomous web application security assessment via GPT-4o",
    })

    all_findings = []
    phase_results = []
    pocs = {}

    for phase in phases:
        print(f"[{session_id}] Phase: {phase}")
        result = run_phase(
            session_id=session_id,
            phase=phase,
            target_url=target_url,
            headers=mcp_headers,
            benchmark=benchmark,
            openai_client=openai_client,
        )
        phase_results.append(result)
        all_findings.extend(result.get("findings", []))

    # Generate PoCs for critical/high findings
    if generate_pocs and openai_client:
        for finding in all_findings:
            if finding.get("severity") in ("critical", "high"):
                title = finding.get("title", "unknown")
                print(f"[{session_id}] Generating PoC for: {title}")
                poc_code = generate_poc(finding, openai_client)
                pocs[title] = poc_code

    metrics = benchmark.get_metrics()

    return {
        "session_id": session_id,
        "target_url": target_url,
        "phases_run": phases,
        "total_findings": len(all_findings),
        "findings": all_findings,
        "pocs": pocs,
        "phase_results": phase_results,
        "benchmark": metrics,
        "xbow_passing": all(metrics["passing"].values()),
    }


# ── CLI entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="RedTeam V9 — GPT-4o autonomous pentest orchestrator"
    )
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--session", default=None, help="Session ID")
    parser.add_argument("--phases", default=",".join(PHASES),
                        help="Comma-separated phases to run")
    parser.add_argument("--no-pocs", action="store_true",
                        help="Skip PoC generation")
    args = parser.parse_args()

    result = run_full_engagement(
        target_url=args.target,
        session_id=args.session,
        phases=args.phases.split(","),
        generate_pocs=not args.no_pocs,
    )

    print(f"\nFindings: {result['total_findings']}")
    print(f"xbow passing: {result['xbow_passing']}")
    print(f"Benchmark:\n{json.dumps(result['benchmark'], indent=2)}")
