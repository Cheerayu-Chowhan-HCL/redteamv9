# RedTeam V9 — Autonomous AI Penetration Testing Agent

An autonomous AI-powered web application penetration testing agent.
Reasons mathematically about attack paths using Bayesian MCTS.
Monitors its own behaviour using an intent correlation layer (Phase 1 complete).
Training a SICD self-model to detect agent drift (Phase 2 in progress).

## Live proof

Discovered and responsibly disclosed CVSS 7.5 HIGH Broken Access Control
in HPNLU ERP portal (erphpnlu.in). CWE-284, OWASP A01:2021.
Acknowledged by CERT-In: Ref CERTIn-94857726.

## Architecture
Operator → Cowork/Codex → MCP :6019 → Intent middleware

→ Planner (BayesianMCTS) → declare_intent()

→ Executor (34 tools) → Target application

→ Reflector → Transfer learning → next engagement

## Requirements

- Python 3.12+
- Node.js 18+ (for mcp-remote)
- Docker Desktop (for AltoroJ target and Neo4j)
- Claude Desktop (for Cowork connector)
- 20GB+ free disk space

## Quick setup on a new machine

### 1. Clone the repo

```bash
git clone https://github.com/[org]/redteamv9.git
cd redteamv9
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Set up the bearer token

```bash
# Create the token file (generate any secure random string)
echo "YOUR_BEARER_TOKEN_HERE" > C:\Temp\rtv7_bearer.txt
```

### 4. Start Docker containers

```bash
# AltoroJ target
docker run -d -p 8080:8080 --name altoro jrociahcl/altoromutualvuln

# Neo4j graph database
docker run -d -p 7474:7474 -p 7687:7687 --name neo4j-redteam \
  -e NEO4J_AUTH=neo4j/your_password neo4j:5.18
```

### 5. Initialise the database

```bash
python -c "
import sys
sys.path.insert(0, '.')
from core.graph_engine import GraphEngine
GraphEngine()
print('Database initialised')
"
```

### 6. Start the V9 server

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File DEMO_START.ps1
```

### 7. Verify everything is running

```powershell
Invoke-RestMethod http://127.0.0.1:6019/health
# Expected: redteam-v9-mcp, version 9.0.0, tools 34
```

### 8. Configure Claude Desktop connector

Add to `claude_desktop_config.json`:

```json
"redteam-v9": {
  "command": "cmd",
  "args": ["/C", "npx", "-y", "mcp-remote",
    "http://127.0.0.1:6019/mcp",
    "--header",
    "Authorization: Bearer YOUR_BEARER_TOKEN_HERE"
  ]
}
```

### 9. Open Cowork

- Open Claude Desktop → Cowork
- Enable `redteam-v9` connector
- Paste contents of `cowork/PROJECT_INSTRUCTIONS.md`
  into the Instructions panel
- Upload the 4 skill files from `cowork/skills/`
- Open DAG UI: http://localhost:6081/dag_ui.html

## Run your first engagement

In Cowork:
Authorised penetration test.

Target: http://localhost:8080/altoromutual

Session: v9_ctf_altoroj_001

Goal: Full black-box web application security assessment.
Read your skill file first using read_skill tool.

Begin with create_session then fingerprint_target.

Use redteam-v9 MCP tools for all actions.

No target knowledge assumed — discover everything from scratch.

Generate report when all phases complete.

## Phase status

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 0 | Complete | Foundation fixes — DB path, async jobs, RAG retry, Neo4j backoff |
| Phase 1 | Complete | Intent architecture — declare_intent(), MAST taxonomy, middleware |
| Phase 2 | In progress | SICD self-model — transformer encoder, divergence scoring |
| Phase 3 | Planned | SkillDAG + tool isolation across 4 MCP servers |
| Phase 4 | Planned | OpenA2A agent identity registration |
| Phase 5 | Planned | OpenAI GPT-4o migration + hackathon submission |

## Key ports

| Port | Service |
|------|---------|
| 6019 | MCP server (main endpoint) |
| 6037 | Graph memory API |
| 6055 | RAG server |
| 6081 | DAG UI (live attack graph) |
| 7687 | Neo4j Bolt |
| 8080 | AltoroJ target |

## Project structure
tools/mcp_service.py      — 34 MCP tools

core/graph_engine.py      — SQLite + Neo4j dual-write

core/intelligence.py      — BayesianMCTS algorithm

core/rag_engine.py        — ChromaDB semantic retrieval

servers/graph_memory_server.py — DAG UI backend

web/dag_ui.html           — Live attack DAG

cowork/                   — Cowork project files

## Team

HCLTech Cybersecurity AI Initiative
Hackathon: HCLTech-OpenAI Agentic AI Hackathon 2026
