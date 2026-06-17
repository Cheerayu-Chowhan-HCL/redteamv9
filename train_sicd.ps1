# Train SICD encoder — RedTeam V9 Phase 2
# Run after 10+ corpus engagements have been completed.
# Expects: logs/tool_audit.jsonl with >= 200 entries for best results.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File train_sicd.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSCommandPath
$python = "python"

Write-Host ""
Write-Host "  RedTeam V9 — SICD Encoder Training" -ForegroundColor Cyan
Write-Host "  =====================================" -ForegroundColor Cyan
Write-Host ""

# Check corpus size
Write-Host "[1] Checking corpus..." -ForegroundColor Yellow
$audit_log = "$root\logs\tool_audit.jsonl"
if (-not (Test-Path $audit_log)) {
    Write-Host "  ERROR: logs/tool_audit.jsonl not found." -ForegroundColor Red
    Write-Host "  Run at least 10 corpus engagements first." -ForegroundColor Red
    exit 1
}

$lines = (Get-Content $audit_log | Measure-Object -Line).Lines
Write-Host "  Corpus entries: $lines"

if ($lines -lt 200) {
    Write-Host "  WARNING: corpus has $lines entries, recommend >= 200 for quality training." -ForegroundColor Yellow
    Write-Host "  Proceeding anyway (minimum is 10 sequences of 16)..." -ForegroundColor Yellow
}

# Check PyTorch
Write-Host ""
Write-Host "[2] Checking PyTorch..." -ForegroundColor Yellow
$torch_check = & $python -c "import torch; print(torch.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  PyTorch not installed. Installing..." -ForegroundColor Yellow
    & pip install torch --break-system-packages --quiet
}
else {
    Write-Host "  PyTorch: $torch_check"
}

# Run two-stage training (Plan B base + Plan A fine-tune)
Write-Host ""
Write-Host "[3] Running train_two_stage() — Plan B (CICIDS2017) then Plan A (corpus)..." -ForegroundColor Yellow
& $python -c @"
import sys
sys.path.insert(0, '$root')
from core.sicd_encoder import train_two_stage, load_corpus, build_sequences

entries = load_corpus()
seqs = build_sequences(entries)
print(f'Corpus: {len(entries)} entries, {len(seqs)} sequences')
train_two_stage(planb_epochs=20, plana_epochs=40)
print('Two-stage training complete.')
"@

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  Training failed — see output above." -ForegroundColor Red
    exit 1
}

# Verify model file
Write-Host ""
Write-Host "[4] Verifying model..." -ForegroundColor Yellow
$model_path = "$root\models\sicd_encoder.pt"
if (Test-Path $model_path) {
    $size = (Get-Item $model_path).Length
    Write-Host "  models/sicd_encoder.pt: OK ($size bytes)" -ForegroundColor Green
}
else {
    Write-Host "  ERROR: model file not found after training." -ForegroundColor Red
    exit 1
}

# Smoke test divergence score
Write-Host ""
Write-Host "[5] Smoke testing divergence score..." -ForegroundColor Yellow
& $python -c @"
import sys
sys.path.insert(0, '$root')
from core.sicd_encoder import compute_divergence_score, load_corpus

corpus = load_corpus()
if corpus:
    score = compute_divergence_score(corpus[-16:])
    print(f'Divergence score on last 16 entries: {score:.3f}')
    assert 0 <= score <= 1, f'Score out of range: {score}'
    print('Smoke test: PASS')
else:
    print('No corpus entries — skipping smoke test')
"@

Write-Host ""
Write-Host "  SICD training complete." -ForegroundColor Green
Write-Host "  Model: $model_path" -ForegroundColor Green
Write-Host "  Next: restart graph_memory_server to pick up live divergence scoring." -ForegroundColor Cyan
Write-Host ""
