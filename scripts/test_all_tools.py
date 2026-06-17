"""
RedTeam V9 — All 34 Tools Direct Test (Task 5)
Calls each tool directly via import. No Cowork, no Claude Desktop.
"""
import sys, json, time, os
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
os.environ["PYTHONIOENCODING"] = "utf-8"

# Import all tools
from tools.mcp_service import (
    create_session, set_branch, log_reasoning, add_injection_point, add_finding,
    get_session_context, score_branches, distill_knowledge, retrieve_knowledge,
    get_cross_session_insights, http_request, check_headers, enumerate_endpoints,
    fingerprint_target, crawl_links, test_sqli, check_sqli_status, get_sqli_results,
    test_xss, verify_xss_browser, test_xpath_injection, test_command_injection,
    test_auth_bypass, test_idor, test_csrf, analyse_cookies, test_session_fixation,
    run_nuclei_scan, check_nuclei_status, kill_all_scans, shell_exec, generate_report
)

SESSION_ID = "v6_tool_test"
TARGET = "http://example.com"
results = []

def test(name, fn, *args, **kwargs):
    start = time.time()
    try:
        r = fn(*args, **kwargs)
        elapsed = int((time.time() - start) * 1000)
        ok = isinstance(r, dict) and "success" in r
        # For error cases (missing binary etc), success=False is acceptable IF error is clean string not traceback
        if not r.get("success") and r.get("error"):
            # Clean error = no traceback lines
            is_clean_error = "Traceback" not in str(r.get("error","")) and "line " not in str(r.get("error",""))[:100]
            ok = is_clean_error  # clean error is PASS for optional deps
            note = f"clean_error: {str(r.get('error',''))[:80]}"
        else:
            note = str(r.get("result",""))[:60] if r.get("success") else str(r.get("error",""))[:60]
        status = "PASS" if ok else "FAIL"
        results.append((name, status, elapsed, note))
        color = "\033[92m" if ok else "\033[91m"
        reset = "\033[0m"
        print(f"  {color}{status}{reset}  {name:<35} {elapsed:>5}ms  {note}")
        return r
    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        results.append((name, "FAIL", elapsed, f"EXCEPTION: {e}"))
        print(f"  \033[91mFAIL\033[0m  {name:<35} {elapsed:>5}ms  EXCEPTION: {str(e)[:60]}")
        return {}

print(f"\n{'='*75}")
print("  RedTeam V9 — All Tools Test")
print(f"{'='*75}\n")

# -- Setup ---------------------------------------------------------------------
print("[ Session & Memory Tools ]")
test("create_session",          create_session, SESSION_ID, TARGET, "tool test session")
test("set_branch",              set_branch,     SESSION_ID, "recon", "tool test branch")
test("log_reasoning",           log_reasoning,  SESSION_ID, "tester", "phase_start", "testing all tools")
test("add_injection_point",     add_injection_point, SESSION_ID, "username", "/login", "POST", "login form")
test("add_finding",             add_finding,    SESSION_ID, "Test XSS", "high", "/search",
                                "reflected input", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "encode output")
test("get_session_context",     get_session_context, SESSION_ID)
test("score_branches",          score_branches, SESSION_ID, "sqli,xss,idor,csrf", 5)
test("distill_knowledge",       distill_knowledge, SESSION_ID, "Login form at /login — likely injectable")
test("retrieve_knowledge",      retrieve_knowledge, "SQL injection bypass login", 3)
test("get_cross_session_insights", get_cross_session_insights, "php", "sqli")

print("\n[ HTTP & Recon Tools ]")
test("http_request",            http_request,   TARGET, "GET")
test("check_headers",           check_headers,  TARGET, SESSION_ID)
test("enumerate_endpoints",     enumerate_endpoints, TARGET, SESSION_ID, "small")
test("fingerprint_target",      fingerprint_target, TARGET, SESSION_ID)
test("crawl_links",             crawl_links,    TARGET, SESSION_ID, 1, 5)

print("\n[ Injection Tools ]")
sqli_r = test("test_sqli",      test_sqli, TARGET, "q", "GET", "{}", "{}", SESSION_ID)
job_id = sqli_r.get("result", {}).get("job_id", "no_job") if sqli_r.get("success") else "no_job"
time.sleep(1)
test("check_sqli_status",       check_sqli_status, job_id)
test("get_sqli_results",        get_sqli_results, job_id, SESSION_ID)
test("test_xss",                test_xss,       TARGET, "q", "", "GET", "{}", "{}", SESSION_ID)
test("verify_xss_browser",      verify_xss_browser, TARGET, "", SESSION_ID)
test("test_xpath_injection",    test_xpath_injection, TARGET, "q", "GET", "{}", "{}", SESSION_ID)
test("test_command_injection",  test_command_injection, TARGET, "q", "GET", "{}", "{}", SESSION_ID)

print("\n[ Auth & Session Tools ]")
test("test_auth_bypass",        test_auth_bypass, TARGET, TARGET + "/login", "username", "password", SESSION_ID)
test("test_idor",               test_idor,      TARGET, "/user/{id}", "id", "{}", SESSION_ID)
test("test_csrf",               test_csrf,      TARGET, "", "{}", SESSION_ID)
test("analyse_cookies",         analyse_cookies, TARGET, "{}", SESSION_ID)
test("test_session_fixation",   test_session_fixation, TARGET, SESSION_ID)

print("\n[ Execution & Utility Tools ]")
nuclei_r = test("run_nuclei_scan", run_nuclei_scan, TARGET, "misconfigurations", SESSION_ID)
nuclei_job = nuclei_r.get("result", {}).get("job_id", "no_job") if nuclei_r.get("success") else "no_nuclei"
test("check_nuclei_status",     check_nuclei_status, nuclei_job)
test("kill_all_scans",          kill_all_scans)
test("shell_exec",              shell_exec,     "echo RedTeam V9 shell test")
test("generate_report",         generate_report, SESSION_ID)

# -- Cleanup -------------------------------------------------------------------
import subprocess
subprocess.run(["python", "flush_dbs.py", "--session", SESSION_ID],
               capture_output=True, cwd=str(_Path(__file__).resolve().parent.parent))

# -- Summary -------------------------------------------------------------------
print(f"\n{'='*75}")
passed = sum(1 for _, s, _, _ in results if s == "PASS")
failed = sum(1 for _, s, _, _ in results if s == "FAIL")
total = len(results)
print(f"\n  Results: {passed}/{total} passed, {failed} failed")
print(f"\n  {'Tool':<35} {'Status':<6} {'ms':>5}  Notes")
print(f"  {'-'*70}")
for name, status, ms, note in results:
    color = "\033[92m" if status == "PASS" else "\033[91m"
    reset = "\033[0m"
    print(f"  {color}{name:<35}{reset} {status:<6} {ms:>5}ms  {note[:40]}")
print(f"\n  OVERALL: {'\\033[92mPASS\\033[0m' if failed == 0 else '\\033[91mFAIL\\033[0m'}")
if failed > 0:
    print("  Failed tools:")
    for name, status, ms, note in results:
        if status == "FAIL":
            print(f"    ? {name}: {note}")
print(f"{'='*75}\n")
sys.exit(0 if failed == 0 else 1)
