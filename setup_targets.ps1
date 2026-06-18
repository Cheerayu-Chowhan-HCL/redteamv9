# RedTeam V9 — Training target setup
# Pulls and starts all locally hosted vulnerable web apps.
# Run once to set up. Containers persist across reboots.

Write-Host "=== RedTeam V9 Target Setup ===" -ForegroundColor Cyan
Write-Host "Checking Docker..."
docker info > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker not running. Start Docker Desktop first." -ForegroundColor Red
    exit 1
}

$targets = @(
    @{name="dvwa";      image="vulnerables/web-dvwa";         port="8090:80";   url="http://localhost:8090";  note="PHP/MySQL - login admin/password"},
    @{name="webgoat";   image="webgoat/webgoat";              port="8091:8080"; url="http://localhost:8091/WebGoat"; note="Java/Spring OWASP"},
    @{name="juiceshop"; image="bkimminich/juice-shop";        port="8092:3000"; url="http://localhost:8092";  note="Node.js modern stack"},
    @{name="dvws";      image="tssoftsecurity/dvws";          port="8093:8888"; url="http://localhost:8093";  note="REST/SOAP API security"},
    @{name="modsec";    image="owasp/modsecurity-crs:apache"; port="8094:8080"; url="http://localhost:8094";  note="ModSecurity WAF layer"}
)

foreach ($t in $targets) {
    $exists = docker ps -a --format "{{.Names}}" 2>$null | Where-Object { $_ -eq $t.name }
    if ($exists) {
        Write-Host "  $($t.name): exists — starting..." -ForegroundColor Gray
        docker start $t.name > $null 2>&1
        Write-Host "  $($t.name): running at $($t.url)" -ForegroundColor Green
    } else {
        Write-Host "  Pulling $($t.image)..." -ForegroundColor Yellow
        docker pull $t.image
        if ($LASTEXITCODE -eq 0) {
            docker run -d -p $t.port --name $t.name $t.image > $null
            Write-Host "  $($t.name): started at $($t.url)" -ForegroundColor Green
        } else {
            Write-Host "  $($t.name): pull failed — skipping" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Available targets:" -ForegroundColor Cyan
Write-Host "  http://localhost:8090  DVWA          PHP/MySQL/Apache (no WAF)"
Write-Host "  http://localhost:8091  WebGoat        Java/Spring"
Write-Host "  http://localhost:8092  Juice Shop     Node.js/Express"
Write-Host "  http://localhost:8093  DVWS           REST/SOAP APIs"
Write-Host "  http://localhost:8094  ModSecurity    WAF-protected layer"
Write-Host ""
Write-Host "External targets (start mitmproxy first):"
Write-Host "  http://demo.testfire.net     Java/Tomcat"
Write-Host "  http://testasp.vulnweb.com   PHP/IIS"
Write-Host "  http://testphp.vulnweb.com   PHP/Apache"
Write-Host "  http://testaspnet.vulnweb.com ASP.NET/IIS"
Write-Host ""
Write-Host "mitmproxy command: mitmdump --mode regular --listen-port 8888"
