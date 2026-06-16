import json
import pathlib
import sqlite3
import numpy as np
from datetime import datetime
from core.graph_engine import DB_PATH

AUDIT_LOG = pathlib.Path("C:/users/chirayu/redteamv9/logs/tool_audit.jsonl")
MODEL_PATH = pathlib.Path("C:/users/chirayu/redteamv9/models/sicd_encoder.pt")
MODEL_PATH.parent.mkdir(exist_ok=True)

TOOL_VOCAB = [
    "create_session","fingerprint_target","crawl_links","enumerate_endpoints",
    "check_headers","http_request","analyse_cookies","add_injection_point",
    "log_reasoning","score_branches","set_branch","add_finding",
    "distill_knowledge","get_session_context","get_cross_session_insights",
    "declare_intent","get_intent_incidents","test_sqli","check_sqli_status",
    "get_sqli_results","run_nuclei_scan","check_nuclei_status",
    "get_nuclei_results","test_xss","verify_xss_browser","test_auth_bypass",
    "test_session_fixation","test_idor","test_csrf","test_xpath_injection",
    "test_command_injection","test_path_traversal","shell_exec",
    "generate_report","kill_all_scans","retrieve_knowledge","read_skill",
    "UNKNOWN"
]

PHASE_VOCAB = [
    "recon_phase","sqli_phase","xss_phase","auth_phase",
    "idor_phase","config_phase","none","UNKNOWN"
]

EXEMPT = {
    "create_session","declare_intent","get_intent_incidents",
    "log_reasoning","get_session_context","score_branches",
    "distill_knowledge","kill_all_scans","generate_report",
    "read_skill","retrieve_knowledge","get_cross_session_insights"
}

SEQ_LEN = 16
EMBED_DIM = 32


def load_corpus():
    if not AUDIT_LOG.exists():
        return []
    entries = []
    for line in AUDIT_LOG.read_text(errors="ignore").strip().split("\n"):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            pass
    return entries


def entry_to_vector(entry):
    tool = entry.get("tool_name", "UNKNOWN")
    phase = entry.get("session_phase") or "UNKNOWN"
    t_idx = TOOL_VOCAB.index(tool) if tool in TOOL_VOCAB else len(TOOL_VOCAB)-1
    p_idx = PHASE_VOCAB.index(phase) if phase in PHASE_VOCAB else len(PHASE_VOCAB)-1
    is_exempt = 1.0 if tool in EXEMPT else 0.0
    params = entry.get("parameters_summary") or {}
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except Exception:
            params = {}
    param_entropy = min(len(str(params)) / 200.0, 1.0)
    return [
        t_idx / len(TOOL_VOCAB),
        p_idx / len(PHASE_VOCAB),
        is_exempt,
        param_entropy,
    ]


def build_sequences(entries, seq_len=SEQ_LEN):
    by_session = {}
    for e in entries:
        sid = e.get("session_id", "unknown")
        by_session.setdefault(sid, []).append(e)
    sequences = []
    for sid, evts in by_session.items():
        if len(evts) < seq_len:
            continue
        for i in range(len(evts) - seq_len):
            seq = [entry_to_vector(e) for e in evts[i:i+seq_len]]
            sequences.append(np.array(seq, dtype=np.float32))
    return sequences


def compute_divergence_score(recent_entries):
    if not recent_entries:
        return 0.05
    try:
        import torch
        if not MODEL_PATH.exists():
            return _heuristic_score(recent_entries)
        model = SICDEncoder()
        model.load_state_dict(torch.load(MODEL_PATH, weights_only=True))
        model.eval()
        if len(recent_entries) < SEQ_LEN:
            recent_entries = ([recent_entries[0]] *
                              (SEQ_LEN - len(recent_entries)) + recent_entries)
        seq = np.array([entry_to_vector(e)
                        for e in recent_entries[-SEQ_LEN:]], dtype=np.float32)
        x = torch.tensor(seq).unsqueeze(0)
        with torch.no_grad():
            recon = model(x)
        loss = float(((x - recon) ** 2).mean())
        return round(min(loss * 4.0, 0.99), 3)
    except Exception:
        return _heuristic_score(recent_entries)


def _heuristic_score(entries):
    score = 0.05
    tools = [e.get("tool_name","") for e in entries]
    rate = len(entries)
    if rate > 20:
        score += 0.3
    elif rate > 10:
        score += 0.1
    non_exempt = [t for t in tools if t not in EXEMPT]
    if len(set(non_exempt)) > 8:
        score += 0.2
    return round(min(score, 0.99), 3)


try:
    import torch
    import torch.nn as nn

    class SICDEncoder(nn.Module):
        def __init__(self, input_dim=4, seq_len=SEQ_LEN, d_model=EMBED_DIM):
            super().__init__()
            self.input_proj = nn.Linear(input_dim, d_model)
            enc_layer = nn.TransformerEncoderLayer(
                d_model=d_model, nhead=4,
                dim_feedforward=64, dropout=0.1,
                batch_first=True
            )
            self.encoder = nn.TransformerEncoder(enc_layer, num_layers=2)
            self.decoder = nn.Linear(d_model, input_dim)

        def forward(self, x):
            h = self.input_proj(x)
            h = self.encoder(h)
            return self.decoder(h)

    def train_encoder(epochs=40, lr=1e-3):
        print("Loading corpus...")
        entries = load_corpus()
        print(f"Corpus entries: {len(entries)}")
        seqs = build_sequences(entries)
        print(f"Training sequences: {len(seqs)}")
        if len(seqs) < 10:
            print("NOT ENOUGH DATA — need at least 10 sequences.")
            print("Run more corpus engagements first.")
            return
        X = torch.tensor(np.stack(seqs))
        model = SICDEncoder()
        opt = torch.optim.Adam(model.parameters(), lr=lr)
        loss_fn = nn.MSELoss()
        model.train()
        for epoch in range(epochs):
            opt.zero_grad()
            recon = model(X)
            loss = loss_fn(recon, X)
            loss.backward()
            opt.step()
            if (epoch+1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs} loss={loss.item():.5f}")
        torch.save(model.state_dict(), MODEL_PATH)
        print(f"Model saved: {MODEL_PATH}")
        return model

except ImportError:
    class SICDEncoder:
        pass
    def train_encoder(**kwargs):
        print("PyTorch not installed. Run: pip install torch --break-system-packages")


if __name__ == "__main__":
    train_encoder()
