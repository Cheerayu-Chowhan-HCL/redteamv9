# Skill Files — Which Agent Needs Which

## Per-agent skill file assignment

| Agent | Primary skill file | Secondary |
|-------|--------------------|-----------|
| Orchestrator | cowork_orchestrator_skill.md | webapp_pt_skill.md |
| Planner | webapp_pt_skill.md | thinking_pattern_skill.md |
| Executor | webapp_pt_skill.md | thinking_pattern_skill.md |
| Reflector | report_interpretation_skill.md | thinking_pattern_skill.md |

## In Cowork (single-agent mode)
Load all 4 skill files — the agent plays all roles.
Upload order in Cowork skill UI:
1. cowork_orchestrator_skill.md
2. webapp_pt_skill.md
3. thinking_pattern_skill.md
4. report_interpretation_skill.md

## Skill file locations
All skill files: C:\Users\chirayu\redteamv9\cowork\skills\

## Key skill content by agent

Orchestrator reads:
- Engagement loop (phases 0-6)
- Stopping conditions
- Error handling
- Delegation pattern

Planner reads:
- score_branches interpretation table
- declare_intent() parameters and examples
- select_skills() usage
- Branch scoring thresholds (entropy rules)

Executor reads:
- Phase-by-phase tool sequences
- add_finding format requirements
- Async scan pattern (launch -> poll -> results -> kill)
- log_reasoning mandatory pattern

Reflector reads:
- Report quality checklist
- CVSS reference table
- Zero-findings handling
- Signal criteria (CONTINUE/PIVOT/COMPLETE)
