# RedTeam V9 - SICD Encoder Training
# Run after corpus has 200+ labelled entries
# Usage: powershell -File train_sicd.ps1

Write-Host "RedTeam V9 - SICD Encoder Training" -ForegroundColor Cyan
Set-Location "C:\Users\chirayu\redteamv9"

$logFile = "C:\Users\chirayu\redteamv9\logs\tool_audit.jsonl"
if (Test-Path $logFile) {
    $lines = (Get-Content $logFile | Measure-Object -Line).Lines
    Write-Host "Corpus entries: $lines"
    if ($lines -lt 100) {
        Write-Host "WARNING: corpus too small" -ForegroundColor Yellow
    }
} else {
    Write-Host "WARNING: tool_audit.jsonl not found" -ForegroundColor Yellow
}

Write-Host "Checking PyTorch..." -ForegroundColor Gray
python -c "import torch; print('PyTorch', torch.__version__)" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing PyTorch..." -ForegroundColor Yellow
    pip install torch --break-system-packages --index-url https://download.pytorch.org/whl/cpu
}

Write-Host "Starting two-stage training..." -ForegroundColor Green

$trainScript = @'
import sys
sys.path.insert(0, 'C:/users/chirayu/redteamv9')
from core.sicd_encoder import train_two_stage, load_corpus, build_sequences
entries = load_corpus()
seqs = build_sequences(entries)
print(f"Corpus: {len(entries)} entries, {len(seqs)} sequences")
if len(seqs) < 10:
    print("Not enough sequences. Run more engagements first.")
else:
    model = train_two_stage(planb_epochs=20, plana_epochs=40)
    print("Training complete.")
'@
$trainScript | python

$modelPath = "C:\Users\chirayu\redteamv9\models\sicd_encoder.pt"
if (Test-Path $modelPath) {
    $size = (Get-Item $modelPath).Length
    Write-Host "Model saved: $size bytes" -ForegroundColor Green
} else {
    Write-Host "ERROR: model not found after training" -ForegroundColor Red
    exit 1
}

$testScript = @'
import sys
sys.path.insert(0, 'C:/users/chirayu/redteamv9')
from core.sicd_encoder import compute_divergence_score

normal = [
    {"tool_name": "test_sqli", "session_phase": "sqli_phase"},
    {"tool_name": "check_sqli_status", "session_phase": "sqli_phase"},
    {"tool_name": "add_finding", "session_phase": "sqli_phase"},
]
anomalous = [
    {"tool_name": "generate_report", "session_phase": "recon_phase"},
    {"tool_name": "shell_exec", "session_phase": "recon_phase"},
    {"tool_name": "http_request", "session_phase": "sqli_phase"},
] * 5

s1 = compute_divergence_score(normal)
s2 = compute_divergence_score(anomalous)
print(f"Normal:    {s1:.3f}")
print(f"Anomalous: {s2:.3f}")
print(f"Discriminates: {s2 > s1}")
'@
$testScript | python

Write-Host ""
Write-Host "Done. Restart graph_memory_server to use new model." -ForegroundColor Cyan
Write-Host "Run: powershell -File DEMO_START.ps1" -ForegroundColor Gray
