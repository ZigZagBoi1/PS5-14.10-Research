<#
.SYNOPSIS
    Send a Lua recon probe to the PS5 Lua loader (Native PowerShell implementation).
.DESCRIPTION
    Sends raw Lua payload prefixed with 8-byte LE length to the PS5 Lua loader on TCP 9026.
.EXAMPLE
    .\tools\send_probe.ps1 probes\phase10_untested_theories\43a_kldstat_kaslr.lua -Save
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ProbePath,

    [string]$Ip = "10.0.0.96",
    [int]$Port = 9026,
    [switch]$Save,
    [int]$TimeoutSeconds = 30
)

if (-not (Test-Path $ProbePath)) {
    Write-Error "Probe file not found: $ProbePath"
    exit 1
}

$content = [System.IO.File]::ReadAllText($ProbePath, [System.Text.Encoding]::UTF8)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
$lenBytes = [System.BitConverter]::GetBytes([uint64]$bytes.Length)
if (-not [System.BitConverter]::IsLittleEndian) {
    [Array]::Reverse($lenBytes)
}

Write-Host "[*] Connecting to $Ip`:$Port..."
$client = $null
$stream = $null

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveTimeout = $TimeoutSeconds * 1000
    $client.SendTimeout = $TimeoutSeconds * 1000
    $client.Connect($Ip, $Port)
    $stream = $client.GetStream()

    Write-Host "[*] Connected, sending $($bytes.Length) bytes..."
    $stream.Write($lenBytes, 0, $lenBytes.Length)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()

    Write-Host "[*] Waiting for response..."
    $responseBytes = New-Object System.Collections.Generic.List[byte]
    $buffer = New-Object byte[] 4096

    while ($true) {
        try {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            for ($i = 0; $i -lt $read; $i++) {
                $responseBytes.Add($buffer[$i])
            }
            $chunkText = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
            Write-Host -NoNewline $chunkText
        } catch [System.IO.IOException] {
            Write-Host "`n[*] Read timed out or connection closed"
            break
        }
    }

    Write-Host "`n[*] Received $($responseBytes.Count) bytes total"

    if ($Save -and $responseBytes.Count -gt 0) {
        $parentDir = Split-Path -Parent $ProbePath
        $resultsDir = "results"
        if ($parentDir -and (Test-Path (Join-Path "results" (Split-Path -Leaf $parentDir)))) {
            $resultsDir = Join-Path "results" (Split-Path -Leaf $parentDir)
        }
        if (-not (Test-Path $resultsDir)) {
            New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
        }
        $probeName = [System.IO.Path]::GetFileNameWithoutExtension($ProbePath)
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $outPath = Join-Path $resultsDir "$($probeName)_$($timestamp).txt"
        [System.IO.File]::WriteAllBytes($outPath, $responseBytes.ToArray())
        Write-Host "[*] Saved to $outPath"
    }
} catch {
    Write-Host "[!] Error: $_"
} finally {
    if ($stream) { $stream.Close() }
    if ($client) { $client.Close() }
}
