Authorised penetration test — corpus generation.

Target: http://demo.testfire.net/
Session: v9_ctf_testfire_001
Tech stack hint: Java/.NET (IBM Altoro Mutual public demo)
Goal: Full black-box web application security assessment.
This engagement generates SICD training data.

EXTERNAL TARGET — mitmproxy must be running before starting:
  mitmdump --mode regular --listen-port 8888

Read your skill file first using read_skill tool.
Begin with create_session then fingerprint_target.
Use redteam-v9 MCP tools for all actions.
No target knowledge assumed — discover everything from scratch.
Generate report when all phases complete.

Note: demo.testfire.net is internet-hosted AltoroJ equivalent.
Different network path than local AltoroJ — useful for corpus variety.
