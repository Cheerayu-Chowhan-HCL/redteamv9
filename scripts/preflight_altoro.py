"""
RedTeam V9 — AltoroJ Local Pre-flight Test
Tests actual pentest workflow against local AltoroJ using real MCP tool calls.
"""
import sys, os, json, time, subprocess, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, "C:/users/chirayu/redteamv9")
os.environ["ALLOW_INTERNAL"] = "true"
os.environ["PYTHONIOENCODING"] = "utf-8"

import logging
logging.disable(logging.CRITICAL)

from tools.mcp_service import (
    create_session, fingerprint_target, score_branches, crawl_links,
    check_headers, set_branch, log_reasoning, generate_report, http_request
)
import requests

GRAPH_URL = "http://127.0.0.1:6037"
TARGET    = "http://localhost:8080/altoromutual"
SID       = "v9_altoro_preflight"

results = []

def step(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    results.append((name, ok))
    color = "\033[92m" if ok else "\033[91m"
    reset = "\033[0m"
    print(f"  {color}{status}{reset}  {name:<30}" + (f"  {detail}" if detail else ""))
    return ok

# Clean up any previous preflight session
try:
    subprocess.run(["python", "flush_dbs.py", "--session", SID],
                   capture_output=True, cwd="C:/users/chirayu/redteamv9")
except Exception:
    pass

print(f"\n{'='*60}")
print("  RedTeam V9 — AltoroJ Pre-flight Test")
print(f"  Target: {TARGET}")
print(f"{'='*60}\n")

# Step 1: create_session
r1 = create_session(SID, TARGET, "preflight check against local AltoroJ")
ok1 = r1.get("success", False)
step("create_session", ok1, str(r1.get("result", r1.get("error", "")))[:80])

# Step 2: fingerprint_target
r2 = fingerprint_target(TARGET, SID)
ok2 = r2.get("success", False)
fp = r2.get("result", {})
server  = fp.get("server", "?")
lang    = fp.get("language", "?")
cms     = fp.get("cms", "?")
step("fingerprint_target", ok2, f"server={server} lang={lang} cms={cms}")
if ok2:
    print(f"    Full fingerprint: {json.dumps(fp, indent=None)[:200]}")

# Step 3: score_branches
r3 = score_branches(SID, "recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation", 5)
ok3 = r3.get("success", False)
ranked = r3.get("result", {}).get("ranked_branches", [])
top = ranked[0] if ranked else {}
step("score_branches", ok3, f"top={top.get('attack_type','?')} score={top.get('score',0):.2f} branches={len(ranked)}")
if ranked:
    print("    Top 3 branches:")
    for b in ranked[:3]:
        print(f"      {b['attack_type']:<20} score={b['score']:.3f}  confidence={b['confidence']:.3f}")

# Step 4: crawl_links
r4 = crawl_links(TARGET, SID, 1, 20)
ok4 = r4.get("success", False)
crawl_res = r4.get("result", {})
links = crawl_res.get("links", [])
forms = crawl_res.get("forms", [])
step("crawl_links", ok4, f"links={len(links)} forms={len(forms)} pages={crawl_res.get('pages_crawled',0)}")
if links:
    print(f"    Sample links: {links[:5]}")
if forms:
    print(f"    Forms found: {[f.get('action','?') for f in forms[:3]]}")

# Step 5: check_headers
r5 = check_headers(TARGET, SID)
ok5 = r5.get("success", False)
hdr_res = r5.get("result", {})
missing = hdr_res.get("missing_headers", [])
step("check_headers", ok5, f"missing={len(missing)} headers: {missing[:4]}")

# Step 6: set_branch
r6 = set_branch(SID, "recon", "Initial recon of AltoroJ local instance")
ok6 = r6.get("success", False)
step("set_branch", ok6, str(r6.get("result", r6.get("error", "")))[:80])

# Step 7: log_reasoning
r7 = log_reasoning(SID, "preflight", "recon_complete",
    json.dumps({"type":"observation","attack":"recon","confidence":0.9,
                "rationale":"crawl complete, forms found, headers audited"}))
ok7 = r7.get("success", False)
step("log_reasoning", ok7, f"log_id={r7.get('result',{}).get('log_id','?')}")

# Step 8: verify DAG has data
try:
    dag_r = requests.get(f"{GRAPH_URL}/dag/session_data?session_id={SID}", timeout=10)
    dag_data = dag_r.json()
    attack_nodes = dag_data.get("attack_dag", {}).get("nodes", [])
    think_nodes  = dag_data.get("thinking_dag", {}).get("nodes", [])
    ok8 = (len(attack_nodes) > 0 or len(think_nodes) > 0)
    step("dag_has_nodes", ok8, f"attack_nodes={len(attack_nodes)} thinking_nodes={len(think_nodes)}")
except Exception as e:
    step("dag_has_nodes", False, f"ERROR: {e}")
    ok8 = False

# Step 9: generate_report
r9 = generate_report(SID)
ok9 = r9.get("success", False)
report_path = r9.get("result", {}).get("report_path", "?")
findings_count = r9.get("result", {}).get("findings_count", 0)
step("generate_report", ok9, f"path={report_path}  findings={findings_count}")

# Cleanup
try:
    subprocess.run(["python", "flush_dbs.py", "--session", SID],
                   capture_output=True, cwd="C:/users/chirayu/redteamv9")
    print("\n  Preflight session flushed.")
except Exception:
    pass

# Summary
print(f"\n{'='*60}")
print("  AltoroJ Pre-flight Results")
print(f"{'='*60}")
all_pass = True
for name, ok in results:
    status = "PASS" if ok else "FAIL"
    if not ok:
        all_pass = False
    color = "\033[92m" if ok else "\033[91m"
    reset = "\033[0m"
    print(f"  {color}{name:<30}{reset}  {status}")
passed = sum(1 for _, ok in results if ok)
print(f"{'='*60}")
print(f"  {passed}/{len(results)} checks passed")
if all_pass:
    print("  \033[92mOVERALL: ALL PASS — ready for live engagement\033[0m")
else:
    print("  \033[91mOVERALL: FAILURES — fix before engaging\033[0m")
print(f"{'='*60}\n")
sys.exit(0 if all_pass else 1)
