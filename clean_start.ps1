# RedTeam V9 — Clean startup script
param([switch]$SkipNeo4j)

Set-Location "C:\users\chirayu\redteamv9"
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "------------------------------------------" -ForegroundColor Cyan
Write-Host "  RedTeam V9 — Starting Services" -ForegroundColor Cyan
Write-Host "------------------------------------------" -ForegroundColor Cyan
Write-Host ""

# -- Step 0: Kill anything on our ports ---------------------------------------
foreach ($port in @(6019, 6037, 6055, 6081)) {
    $pid_found = (netstat -ano 2>$null | Select-String ":$port\s" | ForEach-Object {
        ($_ -split '\s+')[-1]
    } | Select-Object -First 1)
    if ($pid_found) {
        try { Stop-Process -Id $pid_found -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "  Cleared port $port (PID $pid_found)" -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 1

# -- Step 1: Bearer token ------------------------------------------------------
$tokenFile = "C:\Users\chirayu\redteamv9\.tmp\rtv9_bearer.txt"
if (-not (Test-Path $tokenFile)) {
    $token = [System.Web.HttpUtility]::UrlEncode([System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)))
    # Simpler fallback
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $token = [System.Convert]::ToBase64String($bytes) -replace '[/+=]', 'x'
    $token | Out-File -FilePath $tokenFile -Encoding ascii -NoNewline
    Write-Host "  Bearer token generated" -ForegroundColor Green
}
$BEARER = Get-Content $tokenFile

# -- Step 2: Neo4j Docker ------------------------------------------------------
if (-not $SkipNeo4j) {
    Write-Host "[1/5] Starting Neo4j..." -ForegroundColor Yellow

    # Check if Docker is running
    $dockerRunning = $false
    try {
        $dockerStatus = docker info 2>&1
        $dockerRunning = $LASTEXITCODE -eq 0
    } catch {}

    if (-not $dockerRunning) {
        Write-Host "  Docker not running. Attempting to start Docker Desktop..." -ForegroundColor Yellow
        try {
            Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -ErrorAction SilentlyContinue
            $waited = 0
            while (-not $dockerRunning -and $waited -lt 60) {
                Start-Sleep -Seconds 5
                $waited += 5
                try { $s = docker info 2>&1; $dockerRunning = $LASTEXITCODE -eq 0 } catch {}
            }
        } catch {
            Write-Host "  WARNING: Could not start Docker Desktop. Continuing without Neo4j." -ForegroundColor Red
        }
    }

    if ($dockerRunning) {
        $containerRunning = docker ps --filter "name=neo4j-redteam" --format "{{.Names}}" 2>&1
        if ($containerRunning -notmatch "neo4j-redteam") {
            $containerExists = docker ps -a --filter "name=neo4j-redteam" --format "{{.Names}}" 2>&1
            if ($containerExists -match "neo4j-redteam") {
                docker start neo4j-redteam | Out-Null
            } else {
                docker run -d --name neo4j-redteam `
                    -p 7474:7474 -p 7687:7687 `
                    -e NEO4J_AUTH=neo4j/redteam123 `
                    neo4j:5 | Out-Null
            }
        }
        # Wait for Neo4j bolt
        $neo4jReady = $false
        for ($i = 0; $i -lt 12; $i++) {
            try {
                $t = New-Object System.Net.Sockets.TcpClient
                $t.Connect("localhost", 7687)
                $t.Close()
                $neo4jReady = $true
                break
            } catch {}
            Start-Sleep -Seconds 5
        }
        if ($neo4jReady) { Write-Host "  Neo4j ready on :7687" -ForegroundColor Green }
        else { Write-Host "  WARNING: Neo4j not responding on :7687" -ForegroundColor Yellow }
    }
}

# -- Step 3: Activate venv -----------------------------------------------------
$venvPath = "C:\users\chirayu\redteamv9\.venv"
if (Test-Path "$venvPath\Scripts\python.exe") {
    $python = "$venvPath\Scripts\python.exe"
    Write-Host "  Using venv python: $python" -ForegroundColor Gray
} elseif (Test-Path "C:\Users\chirayu\AppData\Local\Programs\Python\Python312\python.exe") {
    $python = "C:\Users\chirayu\AppData\Local\Programs\Python\Python312\python.exe"
    Write-Host "  Using user Python: $python" -ForegroundColor Gray
} else {
    $python = "python"
    Write-Host "  No .venv found, using system python" -ForegroundColor Yellow
}

# -- Ensure logs dir -----------------------------------------------------------
New-Item -ItemType Directory -Force -Path "C:\users\chirayu\redteamv9\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\users\chirayu\redteamv9\reports" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\Users\chirayu\redteamv9\.tmp\rtv9_sandbox" | Out-Null

$pids = @{}
$graphMemoryLog = "C:\users\chirayu\redteamv9\logs\graph_memory.log"
$graphMemoryErrLog = "C:\users\chirayu\redteamv9\logs\graph_memory_err.log"

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
    if ($p1) {
        $p1.Refresh()
        $alive = -not $p1.HasExited
        Write-Host ("  PID: {0}" -f $p1.Id) -ForegroundColor Yellow
        Write-Host ("  Alive: {0}" -f $alive) -ForegroundColor Yellow
        if ($p1.HasExited) {
            Write-Host ("  Exit code: {0}" -f $p1.ExitCode) -ForegroundColor Yellow
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

# -- Step 4: Graph Memory Server -----------------------------------------------
Write-Host "[2/5] Starting Graph Memory Server (:6037)..." -ForegroundColor Yellow
$p1 = Start-Process -FilePath $python `
    -ArgumentList "servers/graph_memory_server.py" `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput $graphMemoryLog `
    -RedirectStandardError $graphMemoryErrLog `
    -PassThru -WindowStyle Hidden
$pids["graph_memory"] = $p1.Id

# Wait for health
$ready = Wait-GraphMemoryHealth -Attempts 15 -DelaySeconds 2
if ($ready) { Write-Host "  Graph Memory Server ready" -ForegroundColor Green }
else {
    Write-GraphMemoryFailure
    exit 1
}

# -- Step 5: RAG Server --------------------------------------------------------
Write-Host "[3/5] Starting RAG Knowledge Server (:6055)..." -ForegroundColor Yellow
$p2 = Start-Process -FilePath $python `
    -ArgumentList "servers/rag_server.py" `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput "logs\rag_server.log" `
    -RedirectStandardError "logs\rag_server_err.log" `
    -PassThru -WindowStyle Hidden
$pids["rag_server"] = $p2.Id

$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 3
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:6055/health" -TimeoutSec 3 -UseBasicParsing 2>$null
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
}
if ($ready) { Write-Host "  RAG Server ready" -ForegroundColor Green }
else { Write-Host "  WARNING: RAG Server health check failed (may still be loading)" -ForegroundColor Yellow }

# -- Step 6: MCP Server --------------------------------------------------------
Write-Host "[4/5] Starting MCP Server (:6019)..." -ForegroundColor Yellow
$p3 = Start-Process -FilePath $python `
    -ArgumentList "scripts/start_mcp.py" `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput "logs\mcp_server.log" `
    -RedirectStandardError "logs\mcp_server_err.log" `
    -PassThru -WindowStyle Hidden
$pids["mcp_server"] = $p3.Id

$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:6019/health" -TimeoutSec 3 -UseBasicParsing 2>$null
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
}
if ($ready) { Write-Host "  MCP Server ready" -ForegroundColor Green }
else { Write-Host "  WARNING: MCP Server health check failed" -ForegroundColor Red }

# -- Step 7: DAG Web UI --------------------------------------------------------
Write-Host "[5/5] Starting DAG Web UI (:6081)..." -ForegroundColor Yellow

# Check ALLOW_EXTERNAL_DAG
$allowExternal = $env:ALLOW_EXTERNAL_DAG -eq "true"
if ($allowExternal) {
    $dagBind = "0.0.0.0"
    Write-Host "  WARNING: DAG UI binding to 0.0.0.0 (ALLOW_EXTERNAL_DAG=true)" -ForegroundColor Yellow
} else {
    $dagBind = "localhost"
}

$p4 = Start-Process -FilePath $python `
    -ArgumentList "-m", "http.server", "6081", "--directory", "web", "--bind", $dagBind `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput "logs\dag_ui.log" `
    -RedirectStandardError "logs\dag_ui_err.log" `
    -PassThru -WindowStyle Hidden
$pids["dag_ui"] = $p4.Id
Start-Sleep -Seconds 2

$dagReady = $false
try {
    $r = Invoke-WebRequest "http://localhost:6081/dag_ui.html" -TimeoutSec 3 -UseBasicParsing 2>$null
    $dagReady = $r.StatusCode -eq 200
} catch {}

# -- Status Table -------------------------------------------------------------
Write-Host ""
Write-Host "--------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  Service              Port   Status   PID" -ForegroundColor White
Write-Host "  ---------------------------------------------------------" -ForegroundColor Gray

function Check-Port([int]$port) {
    try {
        $t = New-Object System.Net.Sockets.TcpClient
        $t.Connect("127.0.0.1", $port)
        $t.Close()
        return "OK"
    } catch { return "FAIL" }
}

$mcpStatus = Check-Port 6019
$gmStatus = if (Test-GraphMemoryHealth) { "OK" } else { "FAIL" }
$ragStatus = Check-Port 6055
$dagStatus = if ($dagReady) { "OK" } else { "FAIL" }

$neo4jStatus = "skip"
if (-not $SkipNeo4j) { $neo4jStatus = Check-Port 7687 }

function StatusColor($s) { if ($s -eq "OK") { return "Green" } else { return "Red" } }

Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "MCP Server", "6019", $mcpStatus, $pids["mcp_server"]) -ForegroundColor (StatusColor $mcpStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "Graph Memory", "6037", $gmStatus, $pids["graph_memory"]) -ForegroundColor (StatusColor $gmStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "RAG Server", "6055", $ragStatus, $pids["rag_server"]) -ForegroundColor (StatusColor $ragStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "DAG Web UI", "6081", $dagStatus, $pids["dag_ui"]) -ForegroundColor (StatusColor $dagStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "Neo4j Bolt", "7687", $neo4jStatus, "(docker)") -ForegroundColor (StatusColor $neo4jStatus)
Write-Host "--------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""

if ($gmStatus -ne "OK") {
    Write-GraphMemoryFailure
    Write-Host "  FAIL: Graph Memory is not healthy after MCP/DAG startup." -ForegroundColor Red
    exit 1
}

Write-Host "  Bearer token: $BEARER" -ForegroundColor Green
Write-Host ""
Write-Host "  DAG UI:       http://localhost:6081/dag_ui.html" -ForegroundColor White
Write-Host "  Neo4j:        http://localhost:7474" -ForegroundColor White
Write-Host ""
Write-Host "  Run MCP inspector: npx @modelcontextprotocol/inspector http://localhost:6019/mcp" -ForegroundColor Yellow
Write-Host "  Trigger example:   POST http://localhost:6019/mcp with Bearer token" -ForegroundColor Yellow
Write-Host ""

