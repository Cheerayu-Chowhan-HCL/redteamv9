# Tool Mapping — Which Agent Calls Which Tool

## Quick reference

| Tool | Orchestrator | Planner | Executor | Reflector |
|------|:---:|:---:|:---:|:---:|
| create_session | ✓ | | | |
| fingerprint_target | ✓ | | | |
| get_session_context | ✓ | | | ✓ |
| get_cross_session_insights | ✓ | | | |
| log_reasoning | ✓ | ✓ | ✓ | ✓ |
| distill_knowledge | ✓ | | ✓ | ✓ |
| generate_report | ✓ | | | |
| kill_all_scans | ✓ | | ✓ | |
| score_branches | | ✓ | | ✓ |
| declare_intent | | ✓ | | |
| select_skills | | ✓ | | |
| retrieve_knowledge | | ✓ | | ✓ |
| set_branch | | ✓ | | |
| crawl_links | | | ✓ | |
| enumerate_endpoints | | | ✓ | |
| check_headers | | | ✓ | |
| http_request | | | ✓ | |
| add_injection_point | | | ✓ | |
| test_sqli | | | ✓ | |
| check_sqli_status | | | ✓ | |
| get_sqli_results | | | ✓ | |
| test_xss | | | ✓ | |
| verify_xss_browser | | | ✓ | |
| test_xpath_injection | | | ✓ | |
| test_command_injection | | | ✓ | |
| test_auth_bypass | | | ✓ | |
| test_session_fixation | | | ✓ | |
| test_idor | | | ✓ | |
| test_csrf | | | ✓ | |
| analyse_cookies | | | ✓ | |
| run_nuclei_scan | | | ✓ | |
| check_nuclei_status | | | ✓ | |
| shell_exec | | | ✓ | |
| add_finding | | | ✓ | ✓ |
| get_intent_incidents | | | | ✓ |

## Key design decisions
- declare_intent() is Planner-only — enforced by agent role
- generate_report is Orchestrator-only — never delegated
- add_finding is shared Executor+Reflector — Reflector fixes gaps
- kill_all_scans is shared Orchestrator+Executor — safety net
