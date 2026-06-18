# RedTeam V9 — Multi-Agent System Prompts

Four-agent architecture for autonomous penetration testing.
One Orchestrator manages three child agents: Planner, Executor, Reflector.

## How to use

1. Start with Orchestrator system prompt + starter prompt
2. Orchestrator delegates to Planner for attack planning
3. Planner returns ranked branches + declares intent
4. Orchestrator hands to Executor with authorised tool list
5. Executor runs attacks, logs findings
6. Orchestrator hands to Reflector for quality review
7. Reflector signals: continue / pivot / complete
8. Loop until all phases done, then generate_report

## Files in this folder

| File | Purpose |
|------|---------|
| orchestrator_system_prompt.md | Orchestrator agent — lifecycle manager |
| planner_system_prompt.md | Planner agent — Bayesian MCTS attack planning |
| executor_system_prompt.md | Executor agent — tool execution |
| reflector_system_prompt.md | Reflector agent — quality control |
| starter_prompt.md | Paste this into Cowork to start an engagement |
| tool_mapping.md | Which tools belong to which agent |
| skill_files_required.md | Which skill files each agent needs |

## MCP connector
All agents connect to: redteam-v9 (http://127.0.0.1:6019/mcp)
Tools: 35 total — see tool_mapping.md for per-agent allocation
