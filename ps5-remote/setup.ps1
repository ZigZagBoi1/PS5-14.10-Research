# PS5 Remote Control — Windows Setup
$ErrorActionPreference = "Stop"

Write-Host "=== PS5 Remote Control Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check for chiaki-ng
$chiakiPaths = @(
    "C:\Program Files\Chiaki\chiaki.exe",
    "C:\Program Files\chiaki-ng\chiaki.exe",
    "C:\Program Files (x86)\Chiaki\chiaki.exe"
)
$found = $false
foreach ($p in $chiakiPaths) {
    if (Test-Path $p) { $found = $true; break }
}
if (-not $found) {
    Write-Host "chiaki-ng not found. Install it:" -ForegroundColor Yellow
    Write-Host "  1. Go to https://github.com/streetpea/chiaki-ng/releases"
    Write-Host "  2. Download the latest Windows installer (.msi or .exe)"
    Write-Host "  3. Install it"
    Write-Host ""

    # Try winget
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Attempting install via winget..."
        winget install streetpea.chiaki-ng 2>$null
    }
}

# Install Python deps
Write-Host "Installing Python dependencies..."
pip install -r "$PSScriptRoot\requirements.txt"

# Create config
$configPath = Join-Path $PSScriptRoot "config.json"
if (-not (Test-Path $configPath)) {
    $ps5Ip = Read-Host "PS5 IP address [10.0.0.50]"
    if (-not $ps5Ip) { $ps5Ip = "10.0.0.50" }
    $ps5Mac = Read-Host "PS5 MAC address (for Wake-on-LAN) [00:00:00:00:00:00]"
    if (-not $ps5Mac) { $ps5Mac = "00:00:00:00:00:00" }

    $config = @{
        ps5_ip = $ps5Ip
        ps5_mac = $ps5Mac
        capture_device = "auto"
        screenshot_interval = 2.0
        api_port = 8888
        api_host = "0.0.0.0"
        game_title_id = ""
        crash_timeout = 30
        freeze_timeout = 15
        probe_port = 9026
        dns_server = "10.0.0.80"
        dualsense_usb = $true
        screenshot_dir = "screenshots"
        log_file = "ps5_remote.log"
    } | ConvertTo-Json
    $config | Set-Content $configPath
    Write-Host "Config saved to $configPath"
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT - One-time Chiaki pairing:" -ForegroundColor Yellow
Write-Host "  1. Open Chiaki-ng"
Write-Host "  2. Your PS5 should appear on the local network"
Write-Host "  3. Go to PS5 Settings > System > Remote Play > Enable Remote Play"
Write-Host "  4. Go to PS5 Settings > System > Remote Play > Link Device"
Write-Host "  5. Note the 8-digit code shown on PS5"
Write-Host "  6. In Chiaki, click your PS5 and enter the code"
Write-Host "  7. Once paired, Chiaki connects directly over LAN (no PSN needed)"
Write-Host ""
Write-Host "  NOTE: Initial pairing needs PSN access. Temporarily change DNS"
Write-Host "  from 10.0.0.80 to automatic, pair, then switch DNS back."
Write-Host "  After pairing, Chiaki works on LAN without PSN servers."
Write-Host ""
Write-Host "To start:" -ForegroundColor Cyan
Write-Host "  python ps5-remote\loop\autonomous.py    # 24/7 loop"
Write-Host "  python ps5-remote\api\server.py         # API server"
