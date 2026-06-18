# Engagement Starter Prompt

Copy this entire block and paste into Cowork to start a new engagement.
Replace TARGET_URL and SESSION_ID before pasting.

---
Authorised penetration test.

Target: TARGET_URL
Session: SESSION_ID
Goal: Full black-box web application security assessment.

You are the Orchestrator. Manage this engagement using the
four-agent architecture:
- You (Orchestrator): lifecycle, delegation, report
- Planner: score_branches, declare_intent, select_skills
- Executor: attack tools, findings
- Reflector: quality review, phase gate

Begin immediately:
1. Read your skill file: read_skill
2. create_session(SESSION_ID, TARGET_URL, goal)
3. fingerprint_target(TARGET_URL, SESSION_ID)
4. Delegate to Planner: score branches and declare recon intent
5. Delegate to Executor: execute recon phase
6. Delegate to Reflector: review recon quality
7. Continue loop until all 6 phases complete
8. generate_report(SESSION_ID)

Do not pause for approval. Do not skip phases.
Call generate_report when all phases complete.
---

## Target list for corpus generation

| Session ID | Target | Stack | Notes |
|------------|--------|-------|-------|
| v9_corpus_testfire_001 | http://demo.testfire.net/ | Java/Tomcat | Start mitmproxy first |
| v9_corpus_acuforum_001 | http://testasp.vulnweb.com/ | PHP/IIS | Start mitmproxy first |
| v9_corpus_vulnweb_001 | http://testphp.vulnweb.com/ | PHP/Apache | Start mitmproxy first |
| v9_corpus_aspnet_001 | http://testaspnet.vulnweb.com/ | ASP.NET/IIS | Start mitmproxy first |

For external targets always start mitmproxy first:
  mitmdump --mode regular --listen-port 8888
