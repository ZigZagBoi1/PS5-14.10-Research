# PS5 Remote Control — Windows Setup
$ErrorActionPreference = "Stop"

Write-Host "=== PS5 Remote Control Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Install Python 3.9+ from python.org" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Python found" -ForegroundColor Green

# Check for chiaki-ng
$chiakiPaths = @(
    "$env:LOCALAPPDATA\Programs\chiaki-ng\chiaki.exe",
    "C:\Program Files\Chiaki\chiaki.exe",
    "C:\Program Files\chiaki-ng\chiaki.exe",
    "C:\Program Files (x86)\Chiaki\chiaki.exe"
)
$chiakiFound = $false
foreach ($p in $chiakiPaths) {
    if (Test-Path $p) {
        Write-Host "[OK] Chiaki found at $p" -ForegroundColor Green
        $chiakiFound = $true
        break
    }
}
if (-not $chiakiFound) {
    Write-Host "[!!] chiaki-ng not found." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Install chiaki-ng:" -ForegroundColor Cyan
    Write-Host "  Option 1: winget install streetpea.chiaki-ng"
    Write-Host "  Option 2: Download from https://github.com/streetpea/chiaki-ng/releases"
    Write-Host ""

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $install = Read-Host "Install via winget now? [Y/n]"
        if ($install -ne "n") {
            winget install streetpea.chiaki-ng
        }
    }
}

# Install Python deps
Write-Host ""
Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
pip install Pillow pyautogui pygetwindow 2>$null
Write-Host "[OK] Dependencies installed" -ForegroundColor Green

# Create config
$configPath = Join-Path $PSScriptRoot "config.json"
if (-not (Test-Path $configPath)) {
    Write-Host ""
    Write-Host "First-time setup:" -ForegroundColor Cyan
    $ps5Ip = Read-Host "PS5 IP address [10.0.0.96]"
    if (-not $ps5Ip) { $ps5Ip = "10.0.0.96" }
    $ps5Mac = Read-Host "PS5 MAC address for Wake-on-LAN [00:00:00:00:00:00]"
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
    $config | Set-Content $configPath -Encoding UTF8
    Write-Host "[OK] Config saved to $configPath" -ForegroundColor Green
} else {
    Write-Host "[OK] Config already exists at $configPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "=== Chiaki Pairing (one-time) ===" -ForegroundColor Yellow
Write-Host "  1. Open Chiaki-ng"
Write-Host "  2. PS5 Settings > System > Remote Play > Enable Remote Play"
Write-Host "  3. PS5 Settings > System > Remote Play > Link Device"
Write-Host "  4. Note the 8-digit code on PS5"
Write-Host "  5. In Chiaki, click your PS5 and enter the code"
Write-Host "  6. After pairing, Chiaki connects over LAN (no PSN needed)"
Write-Host ""
Write-Host "  NOTE: Pairing needs PSN access. Temporarily set DNS to automatic," -ForegroundColor DarkYellow
Write-Host "  pair, then switch back to your DNS blocker." -ForegroundColor DarkYellow
Write-Host ""
Write-Host "=== Running ===" -ForegroundColor Cyan
Write-Host "  Start keeper (keeps game alive):  python ps5-remote\loop\autonomous.py"
Write-Host "  Start API server:                 python ps5-remote\api\server.py"
Write-Host "  Send a probe:                     python tools\send_probe.py --save probes\path\probe.lua"
Write-Host ""
Write-Host "  The keeper only keeps the game running. It does NOT send probes."
Write-Host "  The AI loop decides what probes to write and send."
