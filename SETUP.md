# RedTeam V9 — New member quick setup

You are joining after Phase 0 and Phase 1 are complete.
The MCP server runs, the intent layer is live, one corpus
engagement has been completed. Your job is to get to the
same state in under 30 minutes.

## What you need installed
- Python 3.12+
- Node.js 18+
- Docker Desktop
- Claude Desktop

## Step 1 — Clone and install (5 minutes)
git clone https://github.com/[org]/redteamv9.git
cd redteamv9
pip install -r requirements.txt --break-system-packages

## Step 2 — Create bearer token file (1 minute)
Ask the team for the bearer token value.
echo "TOKEN_HERE" > C:\Temp\rtv7_bearer.txt

## Step 3 — Start Docker containers (5 minutes)
docker run -d -p 8080:8080 --name altoro jrociahcl/altoromutualvuln
docker run -d -p 7474:7474 -p 7687:7687 --name neo4j-redteam \
  -e NEO4J_AUTH=neo4j/redteamv9 neo4j:5.18

## Step 4 — Initialise database (1 minute)
python -c "
import sys; sys.path.insert(0, '.')
from core.graph_engine import GraphEngine
GraphEngine()
print('DB ready')
"

## Step 5 — Start V9 (2 minutes)
powershell -NoProfile -ExecutionPolicy Bypass -File DEMO_START.ps1

## Step 6 — Verify (1 minute)
Invoke-RestMethod http://127.0.0.1:6019/health
# Must return: redteam-v9-mcp, version 9.0.0, tools 34

## Step 7 — Configure Claude Desktop (5 minutes)
Close Claude Desktop fully.
Open: C:\Users\YOUR_NAME\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json
Add the redteam-v9 connector (ask team for the exact JSON block).
Reopen Claude Desktop.

## Step 8 — Set up Cowork (5 minutes)
- Open Cowork in Claude Desktop
- Enable redteam-v9 connector
- Click pencil icon on Instructions panel
- Paste full contents of cowork/PROJECT_INSTRUCTIONS.md
- Upload 4 files from cowork/skills/ via skill upload UI

## Step 9 — Verify DAG UI
Open http://localhost:6081/dag_ui.html
Should show: RedTeam V9 — Live Attack DAG, No sessions yet

## Step 10 — Run smoke engagement
Use the start prompt in cowork/START_altoro.md
Watch the DAG populate. When generate_report fires, check:
python -c "
import sqlite3
conn = sqlite3.connect('redteamv9.db')
for t in ['sessions','findings','agent_intent_log']:
    print(t, conn.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0])
"
All three should be non-zero.

## What is complete vs in progress

Phase 0 DONE — all foundation bugs fixed
Phase 1 DONE — intent layer live, declare_intent() enforced
Phase 2 IN PROGRESS — need 10+ corpus engagements before SICD training
Phase 3-5 NOT STARTED — see README.md for roadmap

## Key files to read first
1. README.md — full architecture
2. cowork/COWORK_SPACE_CONTEXT.md — how the agent thinks
3. cowork/PROJECT_INSTRUCTIONS.md — what the agent is told
4. tools/mcp_service.py — all 34 tools

## Do not
- Touch anything in redteamv7/
- Run two engagements simultaneously
- Skip declare_intent() — it will corrupt training data
- Edit claude_desktop_config.json while Claude Desktop is running
