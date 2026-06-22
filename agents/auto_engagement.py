import json
import sys
import time
import uuid
import requests
import pathlib
import argparse

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

MCP_URL = "http://127.0.0.1:6019/mcp"
BEARER  = open("C:/Temp/rtv7_bearer.txt").read().strip()
BASE_HEADERS = {
    "Authorization": f"Bearer {BEARER}",
    "Content-Type":  "application/json",
    "Accept":        "application/json, text/event-stream",
}

def sse_call(method, params, session_id=None):
    headers = dict(BASE_HEADERS)
    r_init = requests.post(MCP_URL,
        json={"jsonrpc":"2.0","id":1,"method":"initialize",
              "params":{"protocolVersion":"2024-11-05",
                        "capabilities":{},
                        "clientInfo":{"name":"auto_engagement","version":"1.0"}}},
        headers=headers, timeout=15, stream=True)
    mcp_session = r_init.headers.get("mcp-session-id","")
    for line in r_init.iter_lines():
        pass
    if mcp_session:
        headers["mcp-session-id"] = mcp_session
    r = requests.post(MCP_URL,
        json={"jsonrpc":"2.0","id":2,"method":method,"params":params},
        headers=headers, timeout=60, stream=True)
    for line in r.iter_lines():
        if line and line.startswith(b"data: "):
            try:
                obj = json.loads(line[6:])
                return obj.get("result", obj)
            except Exception:
                pass
    return {}

def tool(name, args, session_id=None):
    print(f"  [{name}]", end=" ", flush=True)
    result = sse_call("tools/call",
        {"name": name, "arguments": args},
        session_id)
    content = result.get("content", [])
    if content and isinstance(content, list):
        text = content[0].get("text","") if content else ""
        try:
            data = json.loads(text)
            success = data.get("success", True)
            print("OK" if success else f"WARN: {data.get('error','')}")
            return data
        except Exception:
            print("OK")
            return {"text": text}
    print("OK")
    return result

def run_engagement(target_url, session_id, goal="Full black-box web application security assessment"):
    print(f"\n{'='*60}")
    print(f"AUTO ENGAGEMENT")
    print(f"Target:  {target_url}")
    print(f"Session: {session_id}")
    print(f"{'='*60}\n")

    # Phase 0 — Init
    print("[Phase 0] Initialisation")
    tool("create_session", {"session_id": session_id, "target_url": target_url, "goal": goal})
    tool("get_cross_session_insights", {"tech_stack": "", "attack_type": ""})
    fp = tool("fingerprint_target", {"url": target_url, "session_id": session_id})
    tool("log_reasoning", {"session_id": session_id, "agent": "Orchestrator",
        "step_label": "post_fingerprint",
        "content": json.dumps({"type":"observation","tool":"fingerprint_target","found":str(fp)[:200],"confidence":0.9})})
    branches = tool("score_branches", {"session_id": session_id,
        "candidate_branches": "recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan",
        "top_k": 5})
    tool("crawl_links", {"url": target_url, "session_id": session_id, "depth": 2, "max_pages": 30})

    # Phase 1 — Recon
    print("[Phase 1] Recon")
    tool("declare_intent", {
        "session_id": session_id, "phase": "recon_phase", "intent": "recon",
        "confidence": 0.9,
        "tools_authorised": "crawl_links,enumerate_endpoints,check_headers,http_request,add_injection_point,log_reasoning,distill_knowledge",
        "scope": session_id, "rationale": "Initial recon phase"})
    tool("enumerate_endpoints", {"base_url": target_url, "session_id": session_id, "wordlist_size": "small"})
    tool("check_headers", {"url": target_url, "session_id": session_id})
    tool("distill_knowledge", {"session_id": session_id,
        "insight": "Recon complete. Endpoints, headers and injection points mapped."})

    # Phase 2 — Auth
    print("[Phase 2] Auth testing")
    tool("declare_intent", {
        "session_id": session_id, "phase": "auth_phase", "intent": "auth_bypass",
        "confidence": 0.8,
        "tools_authorised": "test_auth_bypass,test_session_fixation,analyse_cookies,add_finding,log_reasoning,distill_knowledge",
        "scope": session_id, "rationale": "Auth bypass testing"})
    login_url = target_url.rstrip("/") + "/login"
    tool("test_auth_bypass", {"url": target_url, "login_endpoint": login_url,
        "username_field": "username", "password_field": "password",
        "session_id": session_id})
    tool("analyse_cookies", {"url": target_url, "cookies_dict": {}, "session_id": session_id})
    tool("test_session_fixation", {"url": target_url, "session_id": session_id})
    tool("distill_knowledge", {"session_id": session_id, "insight": "Auth phase complete."})

    # Phase 3 — Injection
    print("[Phase 3] Injection testing")
    tool("declare_intent", {
        "session_id": session_id, "phase": "sqli_phase", "intent": "sqli",
        "confidence": 0.85,
        "tools_authorised": "test_sqli,check_sqli_status,get_sqli_results,test_xss,verify_xss_browser,test_command_injection,add_finding,retrieve_knowledge,log_reasoning,distill_knowledge,kill_all_scans",
        "scope": session_id, "rationale": "Injection testing all parameters"})
    tool("retrieve_knowledge", {"query": "SQL injection bypass techniques", "top_k": 5})
    tool("retrieve_knowledge", {"query": "XSS bypass techniques", "top_k": 3})
    search_url = target_url.rstrip("/") + "/search"
    sqli_job = tool("test_sqli", {"url": search_url, "parameter": "query",
        "method": "GET", "data": "", "cookies": {}, "session_id": session_id})
    job_id = (sqli_job.get("result") or sqli_job.get("data") or sqli_job).get("job_id","")
    tool("test_xss", {"url": search_url, "parameter": "query",
        "method": "GET", "data": "", "cookies": {}, "session_id": session_id})
    if job_id:
        for _ in range(6):
            time.sleep(10)
            status = tool("check_sqli_status", {"job_id": job_id})
            s = (status.get("result") or status.get("data") or status).get("status","")
            print(f"    sqli status: {s}")
            if s in ("complete","error"):
                break
        tool("get_sqli_results", {"job_id": job_id, "session_id": session_id})
    tool("kill_all_scans", {})
    tool("distill_knowledge", {"session_id": session_id, "insight": "Injection phase complete."})

    # Phase 4 — Access control
    print("[Phase 4] Access control")
    tool("declare_intent", {
        "session_id": session_id, "phase": "idor_phase", "intent": "idor",
        "confidence": 0.7,
        "tools_authorised": "test_idor,test_csrf,http_request,add_finding,log_reasoning,distill_knowledge",
        "scope": session_id, "rationale": "Access control testing"})
    tool("test_idor", {"base_url": target_url, "endpoint_pattern": "/api/account/{id}",
        "id_param": "id", "cookies": {}, "session_id": session_id})
    tool("test_csrf", {"url": target_url, "form_endpoint": login_url,
        "cookies": {}, "session_id": session_id})
    tool("distill_knowledge", {"session_id": session_id, "insight": "Access control phase complete."})

    # Phase 5 — Config review
    print("[Phase 5] Config review")
    tool("declare_intent", {
        "session_id": session_id, "phase": "config_phase", "intent": "header_misconfiguration",
        "confidence": 0.95,
        "tools_authorised": "check_headers,analyse_cookies,run_nuclei_scan,check_nuclei_status,add_finding,log_reasoning,distill_knowledge,kill_all_scans",
        "scope": session_id, "rationale": "Config and nuclei review"})
    nuclei_job = tool("run_nuclei_scan", {"target_url": target_url,
        "templates": "misconfigurations,cves,exposed-panels,technologies",
        "session_id": session_id})
    nid = (nuclei_job.get("result") or nuclei_job.get("data") or nuclei_job).get("job_id","")
    if nid:
        for _ in range(8):
            time.sleep(10)
            nstatus = tool("check_nuclei_status", {"job_id": nid})
            ns = (nstatus.get("result") or nstatus.get("data") or nstatus).get("status","")
            print(f"    nuclei status: {ns}")
            if ns in ("complete","error"):
                break
    tool("kill_all_scans", {})
    tool("distill_knowledge", {"session_id": session_id, "insight": "Config review complete."})

    # Phase 6 — Report
    print("[Phase 6] Report generation")
    ctx = tool("get_session_context", {"session_id": session_id})
    findings = (ctx.get("data") or ctx).get("confirmed_findings", 0)
    print(f"  Total findings: {findings}")
    tool("log_reasoning", {"session_id": session_id, "agent": "Orchestrator",
        "step_label": "pre_report",
        "content": json.dumps({"type":"decision","action":"generate_report",
            "rationale":f"All phases complete. {findings} findings confirmed."})})
    report = tool("generate_report", {"session_id": session_id})
    tool("log_reasoning", {"session_id": session_id, "agent": "Orchestrator",
        "step_label": "engagement_complete",
        "content": json.dumps({"type":"observation","findings_count":findings,"status":"complete"})})
    print(f"\nEngagement complete: {session_id}")
    print(f"Findings: {findings}")
    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8090/dvwa")
    parser.add_argument("--session", default=None)
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    for i in range(args.count):
        sid = args.session or f"v9_auto_{args.target.split('//')[1].split('/')[0].replace('.','_')}_{int(time.time())}"
        run_engagement(args.target, sid)
        if i < args.count - 1:
            print("\nWaiting 30s before next engagement...")
            time.sleep(30)
