import os
import pathlib

def load_env():
    env_file = pathlib.Path(__file__).parent.parent / '.env'
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, value = line.partition('=')
                if not os.environ.get(key.strip()):
                    os.environ[key.strip()] = value.strip()

def get(key, default=''):
    load_env()
    return os.environ.get(key, default)

MCP_BEARER_TOKEN = get('MCP_BEARER_TOKEN')
MCP_URL          = get('MCP_URL', 'http://127.0.0.1:6019/mcp')
NEO4J_URI        = get('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER       = get('NEO4J_USER', 'neo4j')
NEO4J_PASS       = get('NEO4J_PASS', 'redteam123')
OPENAI_API_KEY   = get('OPENAI_API_KEY', '')
