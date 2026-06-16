# RedTeam V9 - Demo Startup Script

Write-Host ""
Write-Host "  RedTeam V9 - Demo Startup" -ForegroundColor Cyan
Write-Host "  =========================" -ForegroundColor Cyan
Write-Host ""

# Step 0 - Verify Docker is running before touching containers
Write-Host "[0] Checking Docker is running..." -ForegroundColor Yellow
$dockerOK = $false
try {
    $null = & docker info 2>&1
    if ($LASTEXITCODE -eq 0) { $dockerOK = $true }
} catch { }
if (-not $dockerOK) {
    Write-Host ""
    Write-Host "  MANUAL ACTION REQUIRED:" -ForegroundColor Red
    Write-Host "  Docker Desktop is not running." -ForegroundColor Red
    Write-Host "  1. Start Docker Desktop from the Start Menu." -ForegroundColor Yellow
    Write-Host "  2. Wait for the Docker icon in the system tray to become stable." -ForegroundColor Yellow
    Write-Host "  3. Re-run this script." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
Write-Host "  Docker: OK" -ForegroundColor Green

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$userPython = "C:\Users\chirayu\AppData\Local\Programs\Python\Python312\python.exe"
if (Test-Path $venvPython) {
    $python = $venvPython
} elseif (Test-Path $userPython) {
    $python = $userPython
} else {
    $python = "python"
}
Write-Host "  Python: $python" -ForegroundColor Gray

$logsDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null
$graphMemoryLog = Join-Path $logsDir "graph_memory.log"
$graphMemoryErrLog = Join-Path $logsDir "graph_memory_err.log"
$graphMemoryProc = $null

function Test-GraphMemoryHealth {
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:6037/health" -TimeoutSec 3 -ErrorAction Stop
        return ($resp.status -eq "ok")
    } catch {
        return $false
    }
}

function Wait-GraphMemoryHealth([int]$Attempts = 15, [int]$DelaySeconds = 2) {
    for ($i = 0; $i -lt $Attempts; $i++) {
        if (Test-GraphMemoryHealth) { return $true }
        Start-Sleep -Seconds $DelaySeconds
    }
    return $false
}

function Write-GraphMemoryFailure {
    Write-Host ""
    Write-Host "  GRAPH MEMORY HEALTH CHECK FAILED" -ForegroundColor Red
    if ($graphMemoryProc) {
        $graphMemoryProc.Refresh()
        $alive = -not $graphMemoryProc.HasExited
        Write-Host ("  PID: {0}" -f $graphMemoryProc.Id) -ForegroundColor Yellow
        Write-Host ("  Alive: {0}" -f $alive) -ForegroundColor Yellow
        if ($graphMemoryProc.HasExited) {
            Write-Host ("  Exit code: {0}" -f $graphMemoryProc.ExitCode) -ForegroundColor Yellow
        }
    } else {
        Write-Host "  PID: unknown" -ForegroundColor Yellow
    }
    Write-Host ("  stderr log: {0}" -f $graphMemoryErrLog) -ForegroundColor Yellow
    if (Test-Path $graphMemoryErrLog) {
        Write-Host "  Last 30 stderr lines:" -ForegroundColor Yellow
        Get-Content $graphMemoryErrLog -Tail 30 | ForEach-Object {
            Write-Host ("    {0}" -f $_) -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "    stderr log not found" -ForegroundColor DarkYellow
    }
    Write-Host ""
}

# Step 1 - Kill any running python processes (admin-free via taskkill)
Write-Host "[1] Stopping existing Python processes..." -ForegroundColor Yellow
taskkill /F /IM python.exe /T 2>$null
taskkill /F /IM pythonw.exe /T 2>$null
Start-Sleep -Seconds 3

# Free port 6019 if anything is still listening
$busy = (netstat -ano | findstr ":6019" | findstr "LISTENING")
if ($busy) {
    $pid6019 = $busy.Trim().Split()[-1]
    Write-Host "  Port 6019 still busy by PID $pid6019 - releasing..." -ForegroundColor Yellow
    taskkill /F /PID $pid6019 2>$null
    Start-Sleep -Seconds 2
}

# Step 2 - Start neo4j-redteam container
Write-Host "[2] Starting neo4j-redteam container..." -ForegroundColor Yellow
$out = & docker start neo4j-redteam 2>&1
Write-Host "    $out" -ForegroundColor DarkGray

# Step 3 - Start altoro container
Write-Host "[3] Starting altoro container..." -ForegroundColor Yellow
$out = & docker start altoro 2>&1
Write-Host "    $out" -ForegroundColor DarkGray

# Step 4 - Wait for containers
Write-Host "[4] Waiting 8s for containers to initialise..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

# Step 5 - Graph Memory Server
Write-Host "[5] Starting Graph Memory Server (port 6037)..." -ForegroundColor Yellow
$graphMemoryProc = Start-Process $python `
    -ArgumentList "servers\graph_memory_server.py" `
    -WorkingDirectory $PSScriptRoot `
    -RedirectStandardOutput $graphMemoryLog `
    -RedirectStandardError $graphMemoryErrLog `
    -PassThru -WindowStyle Hidden
Write-Host ("  Graph Memory PID: {0}" -f $graphMemoryProc.Id) -ForegroundColor Gray

# Step 6 - Sleep 3
if (Wait-GraphMemoryHealth -Attempts 15 -DelaySeconds 2) {
    Write-Host "  Graph Memory /health OK" -ForegroundColor Green
} else {
    Write-GraphMemoryFailure
    exit 1
}

# Step 7 - RAG Server
Write-Host "[7] Starting RAG Server (port 6055)..." -ForegroundColor Yellow
Start-Process $python -ArgumentList "servers\rag_server.py" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden

# Step 8 - Sleep 15 -- ChromaDB needs time to load chunks into memory
Start-Sleep -Seconds 15

# Step 9 - Set ALLOW_INTERNAL
$env:ALLOW_INTERNAL = "true"
Write-Host "[9] ALLOW_INTERNAL=true set for MCP server process." -ForegroundColor Yellow

# Step 10 - MCP Server
Write-Host "[10] Starting MCP Server (port 6019)..." -ForegroundColor Yellow
Start-Process $python -ArgumentList "scripts\start_mcp.py" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden

# Step 11 - Sleep 4
Start-Sleep -Seconds 4

# Step 12 - DAG UI
Write-Host "[12] Starting DAG UI server (port 6081)..." -ForegroundColor Yellow
Start-Process $python -ArgumentList "-m", "http.server", "6081", "--directory", "web" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden

# Step 13 - Sleep 5
Write-Host "      Waiting 5s for all services to bind..." -ForegroundColor DarkGray
Start-Sleep -Seconds 5

# Step 14 - Port health checks
Write-Host ""
Write-Host "[14] Service health check:" -ForegroundColor Yellow
Write-Host ""

$services = @(
    @{ Port = 6037; Label = "Graph Memory  " },
    @{ Port = 6055; Label = "RAG Server    " },
    @{ Port = 6081; Label = "DAG UI        " },
    @{ Port = 7687; Label = "Neo4j         " },
    @{ Port = 8080; Label = "AltoroJ       " }
)

$allOK = $true
foreach ($svc in $services) {
    if ($svc.Port -eq 6037) {
        $ok = Test-GraphMemoryHealth
    } else {
        $ok = Test-NetConnection -ComputerName localhost -Port $svc.Port -InformationLevel Quiet -WarningAction SilentlyContinue
    }
    if ($ok) {
        Write-Host ("  :{0}  {1}  OK" -f $svc.Port, $svc.Label) -ForegroundColor Green
    } else {
        Write-Host ("  :{0}  {1}  FAIL" -f $svc.Port, $svc.Label) -ForegroundColor Red
        $allOK = $false
    }
}

$mcpReady = $false
$mcpAttempts = 0
$mcpMaxAttempts = 30
Write-Host "Waiting for MCP server on :6019..."
while (-not $mcpReady -and $mcpAttempts -lt $mcpMaxAttempts) {
    Start-Sleep -Seconds 2
    $mcpAttempts++
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:6019/mcp" -Method GET -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $mcpReady = $true
            Write-Host "[OK] MCP server ready (GET /mcp = 200) after $($mcpAttempts * 2)s"
        }
    } catch {
        Write-Host "  attempt $mcpAttempts/$mcpMaxAttempts — waiting..."
    }
}
if (-not $mcpReady) {
    Write-Host "[FAIL] MCP server did not respond to GET /mcp after 60 seconds"
    Write-Host "  Check: Invoke-WebRequest http://127.0.0.1:6019/mcp -Method GET"
    exit 1
}

Write-Host ""

# RAG warm-up check
Write-Host "  Waiting for RAG to warm up..."
$ragReady = $false
for ($i = 0; $i -lt 12; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:6055/health" -TimeoutSec 2 -ErrorAction Stop -UseBasicParsing
        if ($r.StatusCode -eq 200) { $ragReady = $true; break }
    } catch { }
    Start-Sleep 3
}
if ($ragReady) {
    Write-Host "  :6055  RAG warm-up   OK (ChromaDB ready)" -ForegroundColor Green
} else {
    Write-Host "  :6055  RAG warm-up   SLOW (ChromaDB still loading)" -ForegroundColor Yellow
}

Write-Host ""

# Step 14b - Nuclei check
$nucleiPath = "C:\tools\nuclei\nuclei.exe"
if (Test-Path $nucleiPath) {
    Write-Host ("  nuclei  {0}  OK" -f $nucleiPath) -ForegroundColor Green
} else {
    $inPath = Get-Command nuclei -ErrorAction SilentlyContinue
    if ($inPath) {
        Write-Host ("  nuclei  in PATH -- {0}  OK" -f $inPath.Source) -ForegroundColor Green
    } else {
        Write-Host "  nuclei  NOT FOUND -- download from github.com/projectdiscovery/nuclei/releases" -ForegroundColor Yellow
    }
}

Write-Host ""

# Step 15 - All systems go
$graphMemoryFinalOK = Test-GraphMemoryHealth
if (-not $graphMemoryFinalOK) {
    Write-GraphMemoryFailure
    Write-Host "  FAIL: Graph Memory is not healthy after MCP/DAG startup." -ForegroundColor Red
    exit 1
}

if ($allOK) {
    Write-Host "  ALL SYSTEMS GO" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Some services not ready - check output above." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  External scan proxy (for sqlmap/nuclei on external targets):" -ForegroundColor Cyan
Write-Host "  Open a NEW PowerShell window and run:" -ForegroundColor Cyan
Write-Host "    mitmdump --mode regular --listen-port 8888" -ForegroundColor Yellow
Write-Host "  Install once if needed: pip install mitmproxy" -ForegroundColor Cyan
Write-Host "  NOT needed for local targets -- proxy auto-bypassed for localhost" -ForegroundColor Cyan
Write-Host ""

# Step 16 - Print starter prompt with timestamp
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Host ""
Write-Host ("  Session ID: v9_{0}" -f $ts) -ForegroundColor Cyan
Write-Host ""
Write-Host "  ---- Paste into AEX to start engagement: -------------" -ForegroundColor Gray
Write-Host "  Authorised penetration test."
Write-Host "  Target: http://localhost:8080/altoromutual"
Write-Host ("  Session: v9_{0}" -f $ts)
Write-Host "  Goal: Full black-box web application security assessment."
Write-Host ""
Write-Host "  Read your skill file first using read_skill tool."
Write-Host "  Begin immediately with create_session then fingerprint_target."
Write-Host "  Use redteam-v9 MCP tools for all actions."
Write-Host "  No target knowledge assumed -- discover everything from scratch."
Write-Host "  Generate report when all phases complete."
Write-Host "  ------------------------------------------------------" -ForegroundColor Gray
Write-Host ""
Write-Host "  AEX connector: http://localhost:6019/mcp (StreamableHTTP, no auth)" -ForegroundColor Cyan
Write-Host ""

# Step 17 - Open DAG UI in browser
Write-Host "[17] Opening DAG UI..." -ForegroundColor Yellow
Start-Process "http://localhost:6081/dag_ui.html"

Write-Host ""
Write-Host "  Done. Demo ready." -ForegroundColor Cyan
Write-Host ""
