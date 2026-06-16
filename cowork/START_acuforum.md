Authorised penetration test — corpus generation.

Target: http://testasp.vulnweb.com/
Session: v9_ctf_acuforum_001
Tech stack hint: PHP/MySQL (Acunetix test site)
Goal: Full black-box web application security assessment.
This engagement generates SICD training data.

EXTERNAL TARGET — mitmproxy must be running before starting:
  mitmdump --mode regular --listen-port 8888

Read your skill file first using read_skill tool.
Begin with create_session then fingerprint_target.
Use redteam-v9 MCP tools for all actions.
No target knowledge assumed — discover everything from scratch.
Generate report when all phases complete.

Note: This is testasp.vulnweb.com — PHP forum app.
Expected findings: SQLi, XSS, auth bypass, file inclusion.
Expected tech: PHP, MySQL, Apache.
