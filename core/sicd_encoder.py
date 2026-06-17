import json
import pathlib
import sqlite3
import numpy as np
from datetime import datetime
from core.graph_engine import DB_PATH

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
AUDIT_LOG = _PROJECT_ROOT / "logs" / "tool_audit.jsonl"
MODEL_PATH = _PROJECT_ROOT / "models" / "sicd_encoder.pt"
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


def download_planb_data() -> list:
    """Download CICIDS2017 sample for Plan B base training.
    Uses the publicly available Friday subset (DoS attacks).
    Returns list of synthetic event sequences for pre-training.
    """
    import urllib.request
    import csv
    import io
    CICIDS_URL = (
        "https://raw.githubusercontent.com/wesad/CICIDS2017-sample/"
        "main/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_sample.csv"
    )
    try:
        print("Downloading CICIDS2017 sample...")
        with urllib.request.urlopen(CICIDS_URL, timeout=30) as resp:
            data = resp.read().decode('utf-8', errors='ignore')
        reader = csv.DictReader(io.StringIO(data))
        sequences = []
        window = []
        for i, row in enumerate(reader):
            try:
                vec = [
                    float(row.get(' Flow Duration', 0)) / 1e8,
                    float(row.get(' Total Fwd Packets', 0)) / 1000,
                    float(row.get(' Total Backward Packets', 0)) / 1000,
                    1.0 if 'BENIGN' in row.get(' Label', '') else 0.0,
                ]
                vec = [max(0.0, min(1.0, v)) for v in vec]
                window.append(vec)
                if len(window) == SEQ_LEN:
                    sequences.append(window[:])
                    window = window[1:]
            except Exception:
                pass
        print(f"Plan B sequences from CICIDS2017: {len(sequences)}")
        return sequences
    except Exception as e:
        print(f"Plan B download failed: {e}")
        print("Falling back to synthetic base data...")
        import random
        sequences = []
        for _ in range(200):
            seq = [[random.gauss(0.3, 0.1) for _ in range(4)]
                   for _ in range(SEQ_LEN)]
            seq = [[max(0, min(1, v)) for v in row] for row in seq]
            sequences.append(seq)
        return sequences


def train_two_stage(planb_epochs: int = 20,
                    plana_epochs: int = 40,
                    lr: float = 1e-3):
    """Two-stage training: Plan B base model then Plan A fine-tune."""
    try:
        import torch
        import torch.nn as nn
        import numpy as np
    except ImportError:
        print("PyTorch required. Run: pip install torch --break-system-packages")
        return

    PLANB_PATH = MODEL_PATH.parent / "sicd_encoder_planb.pt"

    # STAGE 1 — Plan B base model
    print("=== STAGE 1: Plan B base training (CICIDS2017) ===")
    planb_seqs = download_planb_data()
    if len(planb_seqs) < 10:
        print("Plan B data insufficient — skipping to Plan A only")
    else:
        X_b = torch.tensor(
            np.array(planb_seqs, dtype=np.float32)
        )
        model_b = SICDEncoder(input_dim=4)
        opt_b = torch.optim.Adam(model_b.parameters(), lr=lr)
        loss_fn = nn.MSELoss()
        model_b.train()
        for epoch in range(planb_epochs):
            opt_b.zero_grad()
            recon = model_b(X_b)
            loss = loss_fn(recon, X_b)
            loss.backward()
            opt_b.step()
            if (epoch + 1) % 10 == 0:
                print(f"  Plan B epoch {epoch+1}/{planb_epochs} "
                      f"loss={loss.item():.5f}")
        torch.save(model_b.state_dict(), PLANB_PATH)
        print(f"Plan B model saved: {PLANB_PATH}")

    # STAGE 2 — Plan A fine-tune on corpus
    print()
    print("=== STAGE 2: Plan A fine-tune (RedTeam V9 corpus) ===")
    entries = load_corpus()
    seqs = build_sequences(entries)
    print(f"Corpus: {len(entries)} entries -> {len(seqs)} sequences")
    if len(seqs) < 10:
        print("NOT ENOUGH DATA — need 10+ sequences.")
        print("Run more corpus engagements first.")
        return
    X_a = torch.tensor(np.stack(seqs))
    model_a = SICDEncoder(input_dim=4)
    if PLANB_PATH.exists():
        print("Loading Plan B weights for fine-tuning...")
        state = torch.load(PLANB_PATH, weights_only=True)
        try:
            model_a.load_state_dict(state)
            print("Plan B weights loaded successfully")
        except Exception as e:
            print(f"Weight loading failed ({e}) — training from scratch")
    opt_a = torch.optim.Adam(model_a.parameters(), lr=lr * 0.1)
    loss_fn = nn.MSELoss()
    model_a.train()
    for epoch in range(plana_epochs):
        opt_a.zero_grad()
        recon = model_a(X_a)
        loss = loss_fn(recon, X_a)
        loss.backward()
        opt_a.step()
        if (epoch + 1) % 10 == 0:
            print(f"  Plan A epoch {epoch+1}/{plana_epochs} "
                  f"loss={loss.item():.5f}")
    torch.save(model_a.state_dict(), MODEL_PATH)
    print(f"Final model saved: {MODEL_PATH}")
    return model_a


if __name__ == "__main__":
    train_encoder()
