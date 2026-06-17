Write-Host "Watching AEX debug log... (Ctrl+C to stop)" -ForegroundColor Cyan
$log = "$PSScriptRoot\..\logs\aex_debug.jsonl"
if (-not (Test-Path $log)) {
    New-Item -ItemType File -Path $log -Force | Out-Null
    Write-Host "Log file created (empty)" -ForegroundColor Yellow
}
Get-Content $log -Wait -Tail 20 | ForEach-Object {
    try {
        $j = $_ | ConvertFrom-Json
        if ($j.method) {
            Write-Host "[$($j.timestamp)] $($j.method) $($j.path) from $($j.client)" -ForegroundColor Green
            if ($j.body_preview) {
                Write-Host "  Body: $($j.body_preview.Substring(0, [Math]::Min(200, $j.body_preview.Length)))" -ForegroundColor Gray
            }
            Write-Host "  Headers: $(($j.headers | ConvertTo-Json -Compress))" -ForegroundColor DarkGray
        } elseif ($j.response) {
            $colour = if ($j.response -eq 200) { 'Green' } else { 'Red' }
            Write-Host "  --> Response: $($j.response) ($($j.elapsed_ms)ms)" -ForegroundColor $colour
        }
    } catch {
        Write-Host $_ -ForegroundColor DarkGray
    }
}
