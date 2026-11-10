# PS5 13.60 Jailbreak Host - One-time setup
# Run this on your server (10.0.0.80) to download everything needed
# Usage: .\setup.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== PS5 13.60 Jailbreak Host Setup ===" -ForegroundColor Cyan
Write-Host ""

# Create directory structure
$webRoot = Join-Path $root "www"
$relapseDir = Join-Path $webRoot "relapse"
New-Item -ItemType Directory -Force -Path $webRoot | Out-Null
New-Item -ItemType Directory -Force -Path $relapseDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $relapseDir "src") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $relapseDir "src\utils") | Out-Null

# Download Relapse exploit from upstream
Write-Host "[1/3] Downloading Relapse exploit..." -ForegroundColor Yellow
$relapseRepo = "https://raw.githubusercontent.com/ntfargo/Relapse-Exploit/main"
$relapseFiles = @(
    "src/main.js",
    "src/rop.js",
    "src/utils/syscalls.js",
    "src/firmware.js",
    "src/site.js",
    "launch.css",
    "diagnostics.js"
)

foreach ($file in $relapseFiles) {
    $url = "$relapseRepo/$file"
    $dest = Join-Path $relapseDir $file
    $destDir = Split-Path -Parent $dest
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    }
    Write-Host "  Downloading $file..."
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    } catch {
        Write-Host "  WARNING: Could not download $file - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  You may need to download Relapse manually from:" -ForegroundColor Red
        Write-Host "  https://github.com/ntfargo/Relapse-Exploit" -ForegroundColor Red
    }
}

# Download etaHEN
Write-Host "[2/3] Downloading etaHEN..." -ForegroundColor Yellow
$etahenDir = Join-Path $webRoot "etahen"
New-Item -ItemType Directory -Force -Path $etahenDir | Out-Null

# etaHEN is typically served as a binary payload
$etahenUrl = "https://github.com/LightningMods/etaHEN/releases/latest/download/etaHEN.bin"
try {
    Invoke-WebRequest -Uri $etahenUrl -OutFile (Join-Path $etahenDir "etaHEN.bin") -UseBasicParsing
    Write-Host "  etaHEN.bin downloaded" -ForegroundColor Green
} catch {
    Write-Host "  WARNING: Could not download etaHEN.bin" -ForegroundColor Red
    Write-Host "  Download manually from: https://github.com/LightningMods/etaHEN/releases" -ForegroundColor Red
}

# Copy our server and page files
Write-Host "[3/3] Setting up server files..." -ForegroundColor Yellow
Copy-Item (Join-Path $root "index.html") (Join-Path $webRoot "index.html") -Force
Copy-Item (Join-Path $root "server.py") (Join-Path $root "server.py") -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. On your PS5, set DNS to 10.0.0.80 (Settings > Network > Set Up > DNS > Manual)"
Write-Host "     Primary DNS: 10.0.0.80"
Write-Host "     Secondary DNS: 8.8.8.8"
Write-Host ""
Write-Host "  2. Start the server:"
Write-Host "     python server.py"
Write-Host ""
Write-Host "  3. On PS5, open Settings > User's Guide / Helpful Info"
Write-Host "     It will redirect to the jailbreak page automatically"
Write-Host ""
Write-Host "  4. Press the single 'Jailbreak' button. Done."
Write-Host ""
