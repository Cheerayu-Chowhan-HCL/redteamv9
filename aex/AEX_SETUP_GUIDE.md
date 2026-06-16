# RedTeam V9 â€” AEX Gateway Setup Guide

This guide covers every field to update in the AEX SaaS platform to connect
the 4-agent RedTeam V9 engagement system.

---

## 4A. MCP Connector Configuration

Configure one shared MCP connector in AEX. All 4 agents point to it.

| Field | Value |
|-------|-------|
| **Connector name** | `redteam-v9` |
| **Transport** | StreamableHTTP |
| **URL** | `http://127.0.0.1:6019/mcp` |
| **Auth type** | Bearer token |
| **Bearer token** | Read from `C:\Users\chirayu\redteamv9\.tmp\rtv9_bearer.txt` |
| **Protocol version** | `2025-11-25` (LATEST â€” also accepts 2024-11-05, 2025-03-26, 2025-06-18) |
| **Timeout** | 60s (nuclei/sqlmap scans can be slow) |

**How to get the bearer token:**
```powershell
Get-Content C:\Users\chirayu\redteamv9\.tmp\rtv9_bearer.txt
```

**V7 is running when:**
- `http://127.0.0.1:6019/health` returns `{"status":"ok","tools":32}`
- Start with: `cd C:\Users\chirayu\redteamv9 && python scripts\start_mcp.py`

**Note:** The MCP server must be running on the same machine as the AEX gateway.
V7 binds to `127.0.0.1` only â€” not accessible over the network without a tunnel.

---

## 4B. Starter Prompts (paste into AEX "Starter Prompt" field per agent)

### Orchestrator starter prompt
```
Authorised penetration test.
Target: [TARGET_URL]
Session: [SESSION_ID]
Goal: Full black-box web application security assessment.

Begin immediately. Read skill file first, then create_session.
No target knowledge assumed â€” discover everything from scratch.
Generate report when all phases complete.
```

### Planner starter prompt
```
Waiting for handover from Orchestrator.
Session ID and discovered attack surfaces will be provided.
Do not act until Orchestrator handover is received.
```

### Executor starter prompt
```
Waiting for phase assignment from Orchestrator (via Planner).
Session ID and branch_id will be provided in the handover.
Do not call tools until handover received.
```

### Reflector starter prompt
```
Waiting for phase-completion report from Orchestrator.
Session ID and findings summary will be provided.
Do not call tools until handover received.
```

---

## 4C. Tool Whitelist Per Agent

In AEX, each agent has a tool selection list. Configure as follows:

### Orchestrator (10 tools)
```
create_session
get_session_context
score_branches
fingerprint_target
crawl_links
read_skill
generate_report
log_reasoning
distill_knowledge
kill_all_scans
```

### Planner (5 tools)
```
score_branches
set_branch
log_reasoning
read_skill
get_session_context
```

### Executor (ALL 32 tools)
Executor needs full access to run any attack tool.
Enable all tools â€” the system prompt limits what it actually calls.

Key tools Executor uses most:
```
test_sqli, check_sqli_status, get_sqli_results
test_xss, verify_xss_browser
test_auth_bypass, analyse_cookies, test_session_fixation
test_idor, test_csrf, test_xpath_injection, test_command_injection
run_nuclei_scan, check_nuclei_status
check_headers, enumerate_endpoints
add_finding, add_injection_point, log_reasoning
http_request, shell_exec, kill_all_scans
```

### Reflector (4 tools)
```
get_session_context
log_reasoning
distill_knowledge
add_finding
```

---

## 4D. Known AEX Compatibility Issues and Fixes

### Issue 1: String boolean parameters
**Problem:** AEX gateway passes all tool parameters as strings (e.g., `"true"`, `"false"`).
**Status:** FIXED in V7 â€” `_coerce_bool()` converts string booleans automatically.
**Affected tools:** `http_request` (allow_redirects parameter).
**No action needed.**

### Issue 2: branch_id for parallel attribution
**Problem:** Without branch_id, parallel agents race to update a shared branch pointer.
All findings end up on the wrong branch in the knowledge graph.
**Status:** FIXED in V7 â€” `add_finding` accepts optional `branch_id` parameter.
**Required action:** Planner must save `result["branch_node_id"]` from set_branch and
include it in the Executor handover. Executor must pass it to every add_finding call.

### Issue 3: Skill file path
**V4 path (old, broken in V7):** `C:\Temp\rtv4_active_session.json`
**V7 path (correct):** `C:\Users\chirayu\redteamv9\skills\webapp_pt_skill.md`
**Status:** FIXED â€” `read_skill` tool reads from correct V7 path automatically.

### Issue 4: Session file not used in V7
**V4 behaviour:** Active session tracked in `C:\Temp\rtv4_active_session.json`
**V7 behaviour:** No session file. State is in SQLite at
`C:\Users\chirayu\redteamv9\redteamv9.db` and queried via `get_session_context`.

### Issue 5: Port numbers
| Version | MCP Port | Graph Port | RAG Port | DAG Port |
|---------|----------|------------|----------|----------|
| V4      | (various) | (various) | (various) | (various) |
| V6      | 6009     | 6027       | 6045     | 6080     |
| **V7**  | **6019** | **6037**   | **6055** | **6081** |
| V8      | 6029     | 6047       | 6065     | 6082     |

---

## 4E. Manual Checklist â€” Fields to Update in AEX SaaS Platform

Run through this checklist for each of the 4 agents:

### MCP Connector (once, shared by all agents)
- [ ] Set connector URL to `http://127.0.0.1:6019/mcp`
- [ ] Set bearer token from `C:\Users\chirayu\redteamv9\.tmp\rtv9_bearer.txt`
- [ ] Set protocol version: `2025-11-25`
- [ ] Set timeout: 60 seconds
- [ ] Test connection â€” confirm `tools/list` returns 33 tools (32 + read_skill)

### Orchestrator agent
- [ ] System prompt â€” paste from `agent_system_prompts.md` â†’ AGENT 1
- [ ] Starter prompt â€” paste the Orchestrator starter prompt from section 4B
- [ ] Tool whitelist â€” select the 10 Orchestrator tools from section 4C
- [ ] Model â€” **Claude Opus** (recommended; handles multi-step planning)
- [ ] Max tokens â€” 8192
- [ ] Temperature â€” 0.3

### Planner agent
- [ ] System prompt â€” paste from `agent_system_prompts.md` â†’ AGENT 2
- [ ] Starter prompt â€” paste the Planner starter prompt from section 4B
- [ ] Tool whitelist â€” select the 5 Planner tools from section 4C
- [ ] Model â€” **Claude Sonnet** (planning tasks; Opus optional)
- [ ] Max tokens â€” 4096
- [ ] Temperature â€” 0.3

### Executor agent
- [ ] System prompt â€” paste from `agent_system_prompts.md` â†’ AGENT 3
- [ ] Starter prompt â€” paste the Executor starter prompt from section 4B
- [ ] Tool whitelist â€” enable ALL 33 tools
- [ ] Model â€” **Claude Sonnet** (high tool-call volume; Opus for complex targets)
- [ ] Max tokens â€” 8192
- [ ] Temperature â€” 0.1 (low â€” deterministic tool calls)

### Reflector agent
- [ ] System prompt â€” paste from `agent_system_prompts.md` â†’ AGENT 4
- [ ] Starter prompt â€” paste the Reflector starter prompt from section 4B
- [ ] Tool whitelist â€” select the 4 Reflector tools from section 4C
- [ ] Model â€” **Claude Opus** (quality evaluation needs deep reasoning)
- [ ] Max tokens â€” 4096
- [ ] Temperature â€” 0.3

---

## Quick Start Verification

After configuring AEX, verify the integration works:

```python
# Run this from any terminal on the machine:
import requests
TOKEN = open('C:/Users/chirayu/redteamv9/.tmp/rtv9_bearer.txt').read().strip()
H = {'Authorization': f'Bearer {TOKEN}', 'Content-Type': 'application/json',
     'Accept': 'application/json, text/event-stream'}

# 1. Initialize MCP session
r = requests.post('http://127.0.0.1:6019/mcp',
    json={'jsonrpc':'2.0','id':'0','method':'initialize',
          'params':{'protocolVersion':'2025-11-25','capabilities':{},
                    'clientInfo':{'name':'aex-verify','version':'1'}}},
    headers=H, timeout=10)
sid = r.headers.get('Mcp-Session-Id','')
print(f'MCP Session: {sid or "stateless mode"}')

# 2. List tools â€” should return 33
r2 = requests.post('http://127.0.0.1:6019/mcp',
    json={'jsonrpc':'2.0','id':'1','method':'tools/list','params':{}},
    headers={**H, 'Mcp-Session-Id': sid}, timeout=10)
import json
for line in r2.text.splitlines():
    if line.startswith('data:'):
        data = json.loads(line[5:])
        tools = data.get('result',{}).get('tools',[])
        print(f'Tools available: {len(tools)}')
        for t in tools: print(f'  {t[\"name\"]}')
```

Expected output: `Tools available: 33` (32 pentest tools + `read_skill`)
