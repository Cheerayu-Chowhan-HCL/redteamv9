# RedTeam V9 - Clean startup script (ASCII-only, no Unicode box chars)
param([switch]$SkipNeo4j)

Set-Location "C:\users\chirayu\redteamv9"
$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RedTeam V9 - Starting Services" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Kill anything on our ports
foreach ($port in @(6019, 6037, 6055, 6081)) {
    $found = netstat -ano 2>$null | Select-String ":$port\s" | ForEach-Object {
        ($_ -split '\s+')[-1]
    } | Select-Object -First 1
    if ($found -and $found -match '^\d+$') {
        try { Stop-Process -Id ([int]$found) -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "  Cleared port $port (PID $found)" -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 1

# Step 1: Bearer token
$tokenFile = "C:\Users\chirayu\redteamv9\.tmp\rtv9_bearer.txt"
if (-not (Test-Path "C:\tmp")) { New-Item -ItemType Directory -Force "C:\tmp" | Out-Null }
if (-not (Test-Path $tokenFile)) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $token = [System.Convert]::ToBase64String($bytes) -replace '[/+=]', 'x'
    $token | Out-File -FilePath $tokenFile -Encoding ascii -NoNewline
    Write-Host "  Bearer token generated" -ForegroundColor Green
}
$BEARER = (Get-Content $tokenFile -Raw).Trim()
Write-Host "  Bearer token loaded" -ForegroundColor Gray

# Step 2: Neo4j Docker
if (-not $SkipNeo4j) {
    Write-Host "[1/5] Starting Neo4j..." -ForegroundColor Yellow
    $dockerRunning = $false
    try {
        docker info 2>&1 | Out-Null
        $dockerRunning = ($LASTEXITCODE -eq 0)
    } catch {}

    if (-not $dockerRunning) {
        Write-Host "  Docker not running - attempting to start Docker Desktop..." -ForegroundColor Yellow
        try {
            Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -ErrorAction SilentlyContinue
            $waited = 0
            while (-not $dockerRunning -and $waited -lt 60) {
                Start-Sleep -Seconds 5
                $waited += 5
                try { docker info 2>&1 | Out-Null; $dockerRunning = ($LASTEXITCODE -eq 0) } catch {}
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
                Write-Host "  neo4j-redteam container started" -ForegroundColor Gray
            } else {
                docker run -d --name neo4j-redteam `
                    -p 7474:7474 -p 7687:7687 `
                    -e NEO4J_AUTH=neo4j/redteam123 `
                    neo4j:5 | Out-Null
                Write-Host "  neo4j-redteam container created and started" -ForegroundColor Gray
            }
        } else {
            Write-Host "  neo4j-redteam already running" -ForegroundColor Gray
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
    } else {
        Write-Host "  Skipping Neo4j (Docker unavailable)" -ForegroundColor Yellow
    }
}

# Resolve python executable
$venvPath = "C:\users\chirayu\redteamv9\.venv"
if (Test-Path "$venvPath\Scripts\python.exe") {
    $python = "$venvPath\Scripts\python.exe"
    Write-Host "  Using venv python: $python" -ForegroundColor Gray
} elseif (Test-Path "C:\Users\chirayu\AppData\Local\Programs\Python\Python312\python.exe") {
    $python = "C:\Users\chirayu\AppData\Local\Programs\Python\Python312\python.exe"
    Write-Host "  Using user Python: $python" -ForegroundColor Gray
} else {
    $python = "python"
    Write-Host "  Using system python" -ForegroundColor Gray
}

# Ensure directories
New-Item -ItemType Directory -Force -Path "C:\users\chirayu\redteamv9\logs"    | Out-Null
New-Item -ItemType Directory -Force -Path "C:\users\chirayu\redteamv9\reports" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\Users\chirayu\redteamv9\.tmp\rtv9_sandbox" | Out-Null

# Pentest environment flags
# ALLOW_INTERNAL=true  -> allows http_request to localhost (needed for AltoroJ :8080)
# TARGET_ALLOWLIST=""  -> empty = allow all public targets; set to restrict scope
if (-not $env:ALLOW_INTERNAL) { $env:ALLOW_INTERNAL = "true" }
if ($null -eq $env:TARGET_ALLOWLIST) { $env:TARGET_ALLOWLIST = "" }
Write-Host "  ALLOW_INTERNAL=$env:ALLOW_INTERNAL  TARGET_ALLOWLIST='$env:TARGET_ALLOWLIST'" -ForegroundColor Gray

$pids = @{}

# Step 3: Graph Memory Server :6037
Write-Host "[2/5] Starting Graph Memory Server (:6037)..." -ForegroundColor Yellow
$p1 = Start-Process -FilePath $python `
    -ArgumentList "servers/graph_memory_server.py" `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput "logs\graph_memory.log" `
    -RedirectStandardError  "logs\graph_memory_err.log" `
    -PassThru -WindowStyle Hidden
$pids["graph_memory"] = $p1.Id

$ready = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:6037/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
}
if ($ready) { Write-Host "  Graph Memory Server ready (PID $($p1.Id))" -ForegroundColor Green }
else { Write-Host "  WARNING: Graph Memory Server health check failed" -ForegroundColor Red }

# Step 4: RAG Server :6055
Write-Host "[3/5] Starting RAG Knowledge Server (:6055)..." -ForegroundColor Yellow
$p2 = Start-Process -FilePath $python `
    -ArgumentList "servers/rag_server.py" `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput "logs\rag_server.log" `
    -RedirectStandardError  "logs\rag_server_err.log" `
    -PassThru -WindowStyle Hidden
$pids["rag_server"] = $p2.Id

$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 3
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:6055/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
}
if ($ready) { Write-Host "  RAG Server ready (PID $($p2.Id))" -ForegroundColor Green }
else { Write-Host "  WARNING: RAG Server health check failed (may still be loading embeddings)" -ForegroundColor Yellow }

# Step 5: MCP Server :6019
Write-Host "[4/5] Starting MCP Server (:6019)..." -ForegroundColor Yellow
$p3 = Start-Process -FilePath $python `
    -ArgumentList "scripts/start_mcp.py" `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput "logs\mcp_server.log" `
    -RedirectStandardError  "logs\mcp_server_err.log" `
    -PassThru -WindowStyle Hidden
$pids["mcp_server"] = $p3.Id

$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:6019/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
}
if ($ready) { Write-Host "  MCP Server ready (PID $($p3.Id))" -ForegroundColor Green }
else { Write-Host "  WARNING: MCP Server health check failed" -ForegroundColor Red }

# Step 6: DAG Web UI :6081
Write-Host "[5/5] Starting DAG Web UI (:6081)..." -ForegroundColor Yellow
$dagBind = "localhost"
if ($env:ALLOW_EXTERNAL_DAG -eq "true") {
    $dagBind = "0.0.0.0"
    Write-Host "  WARNING: DAG UI binding to 0.0.0.0 (ALLOW_EXTERNAL_DAG=true)" -ForegroundColor Yellow
}
$p4 = Start-Process -FilePath $python `
    -ArgumentList "-m", "http.server", "6081", "--directory", "web", "--bind", $dagBind `
    -WorkingDirectory "C:\users\chirayu\redteamv9" `
    -RedirectStandardOutput "logs\dag_ui.log" `
    -RedirectStandardError  "logs\dag_ui_err.log" `
    -PassThru -WindowStyle Hidden
$pids["dag_ui"] = $p4.Id
Start-Sleep -Seconds 2

$dagReady = $false
try {
    $r = Invoke-WebRequest "http://localhost:6081/dag_ui.html" -TimeoutSec 3 -UseBasicParsing -ErrorAction SilentlyContinue
    $dagReady = ($r.StatusCode -eq 200)
} catch {}

# Port check function
function Check-Port([int]$port) {
    try {
        $t = New-Object System.Net.Sockets.TcpClient
        $t.Connect("127.0.0.1", $port)
        $t.Close()
        return "OK"
    } catch { return "FAIL" }
}

$mcpStatus  = Check-Port 6019
$gmStatus   = Check-Port 6037
$ragStatus  = Check-Port 6055
$dagStatus  = if ($dagReady) { "OK" } else { "FAIL" }
$neo4jStatus = if ($SkipNeo4j) { "skip" } else { Check-Port 7687 }

function StatusColor($s) {
    if ($s -eq "OK")   { return "Green" }
    if ($s -eq "skip") { return "Gray" }
    return "Red"
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  RedTeam V9 - Service Status" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "Service", "Port", "Status", "PID") -ForegroundColor White
Write-Host "  --------------------------------------------------" -ForegroundColor Gray
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "MCP Server",    "6019", $mcpStatus,   $pids["mcp_server"])    -ForegroundColor (StatusColor $mcpStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "Graph Memory",  "6037", $gmStatus,    $pids["graph_memory"])  -ForegroundColor (StatusColor $gmStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "RAG Server",    "6055", $ragStatus,   $pids["rag_server"])    -ForegroundColor (StatusColor $ragStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "DAG Web UI",    "6081", $dagStatus,   $pids["dag_ui"])        -ForegroundColor (StatusColor $dagStatus)
Write-Host ("  {0,-20} {1,-6} {2,-8} {3}" -f "Neo4j Bolt",    "7687", $neo4jStatus, "(docker)")             -ForegroundColor (StatusColor $neo4jStatus)
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Bearer token : $BEARER" -ForegroundColor Green
Write-Host ""
Write-Host "  DAG UI       : http://localhost:6081/dag_ui.html" -ForegroundColor White
Write-Host "  Neo4j        : http://localhost:7474" -ForegroundColor White
Write-Host "  MCP endpoint : http://127.0.0.1:6019/mcp" -ForegroundColor White
Write-Host ""
Write-Host "  Logs: C:\users\chirayu\redteamv9\logs\" -ForegroundColor Gray
Write-Host ""
