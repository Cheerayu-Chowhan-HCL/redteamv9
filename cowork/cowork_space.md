# RedTeam V9 Cowork Space

## Space Purpose
Autonomous web application penetration testing workspace.
Uses RedTeam V9 MCP tools for all target interaction.

## Connected Tools
- redteam-v9 MCP connector (34 tools)
- Web search (for CVE lookups and technology research)

## Persistent Context
- All findings stored in: C:\users\chirayu\redteamv9\redteamv9.db
- All reports in: C:\users\chirayu\redteamv9\reports\
- Live DAG: http://localhost:6081/dag_ui.html
- Audit log: C:\users\chirayu\redteamv9\logs\tool_audit.jsonl

## Session Naming Convention
Format: v6_{target_shortname}_{YYYYMMDD}_{sequence}
Example: v6_testfire_20260522_001

## Current Target
AltoroJ local instance: http://localhost:8080/altoromutual
Docker container: altoro (jrociahcl/altoromutualvuln, restart=unless-stopped)
Session: v6_altoro_20260523_001
Trigger file: C:\users\chirayu\redteamv9\cowork\trigger_altoro_local.md

Note: demo.testfire.net is currently down (HCL infra issue).
When it returns, use trigger_testfire.md with session v6_testfire_20260522_001.

## Rules
1. Always confirm authorisation before starting any engagement
2. Never attack targets not explicitly listed in the session goal
3. All HTTP to target must go through http_request MCP tool
4. Payloads stay in MCP layer � never paste exploit code into chat
5. Call kill_all_scans at end of every async scan sequence
