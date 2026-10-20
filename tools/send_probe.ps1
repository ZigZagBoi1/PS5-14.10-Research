<#
.SYNOPSIS
    Send a Lua recon probe to the PS5 Lua loader (Native PowerShell implementation).
.DESCRIPTION
    Sends raw Lua payload prefixed with 8-byte LE length to the PS5 Lua loader on TCP 9026.
    With -Save, the response bytes are written under results/ as <probe_name>_<timestamp>.txt.
    For a probe inside this checkout's probes/ directory the probe's subdirectories are mirrored
    (probes\phase_x\foo.lua -> results\phase_x\foo_<timestamp>.txt); probes at the root of
    probes\ and probes outside the checkout are saved flat in results\. results\ is relative
    to the current directory.
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
        # Mirror the probe's path below this checkout's probes/ into results/,
        # creating missing directories. External and root-level probes fall
        # back to the results/ root (results/ relative to the current directory).
        # Normalize both values through the same PowerShell provider API. That
        # keeps normal relative and absolute invocation paths comparable.
        $probesRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            (Join-Path (Split-Path -Parent $PSScriptRoot) "probes"))
        $probeFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $ProbePath)
        $runningOnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
        if ($runningOnWindows) {
            # PowerShell can retain an existing file's 8.3 spelling while the
            # checkout root uses long names. GetFullPath does not expand those
            # names, so resolve both existing comparison paths with the native
            # Windows API before applying the lexical containment check below.
            # A checkout without probes/ is still a valid external fallback.
            $probesRootExists = Test-Path -LiteralPath $probesRoot -PathType Container -ErrorAction Stop
            if ($probesRootExists) {
                if (-not ("SendProbePathNative" -as [type])) {
                    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class SendProbePathNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetLongPathNameW(
        string shortPath, StringBuilder longPath, uint bufferLength);

    public static string GetLongPathName(string path)
    {
        const uint MaximumCapacity = 32768;
        uint capacity = 260;

        for (int attempt = 0; attempt < 8; attempt++)
        {
            StringBuilder buffer = new StringBuilder((int)capacity);
            uint written = GetLongPathNameW(path, buffer, capacity);
            if (written == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "GetLongPathNameW failed for '" + path + "'.");
            }
            if (written < capacity)
            {
                return buffer.ToString();
            }
            if (written > MaximumCapacity)
            {
                throw new PathTooLongException(
                    "GetLongPathNameW returned a path beyond the supported Win32 limit.");
            }
            capacity = written;
        }

        throw new IOException("GetLongPathNameW did not converge within eight attempts.");
    }
}
'@
                }
                $probesRoot = [SendProbePathNative]::GetLongPathName($probesRoot)
                $probeFull = [SendProbePathNative]::GetLongPathName($probeFull)
            }
        }
        # macOS (and some Linux setups) exposes directory aliases such as
        # /tmp -> /private/tmp. Canonicalize both before their containment
        # comparison so a real in-tree probe cannot fall back to results/.
        if ($IsMacOS -or $IsLinux) {
            $realpath = Get-Command realpath -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($realpath) {
                try {
                    $canonicalProbesRoot = @(& $realpath.Source $probesRoot)
                    if ($LASTEXITCODE -eq 0 -and $canonicalProbesRoot.Count -eq 1 -and
                        -not [string]::IsNullOrWhiteSpace([string]$canonicalProbesRoot[0])) {
                        $probesRoot = [string]$canonicalProbesRoot[0]
                    }
                    $canonicalProbeFull = @(& $realpath.Source $probeFull)
                    if ($LASTEXITCODE -eq 0 -and $canonicalProbeFull.Count -eq 1 -and
                        -not [string]::IsNullOrWhiteSpace([string]$canonicalProbeFull[0])) {
                        $probeFull = [string]$canonicalProbeFull[0]
                    }
                } catch {
                    # The provider-normalized paths remain usable when realpath is unavailable.
                }
            }
        }
        # Join-Path yields the directory itself (without a trailing separator).
        # Use the runtime's separator to keep the containment boundary native.
        $probesPrefix = $probesRoot + [System.IO.Path]::DirectorySeparatorChar
        # The separator in $probesPrefix bounds the match, so a sibling
        # directory such as probes-other is not treated as inside probes/.
        $pathComparison = if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
            [System.StringComparison]::OrdinalIgnoreCase
        } else {
            [System.StringComparison]::Ordinal
        }
        $resultsDir = "results"
        if ($probeFull.Length -gt $probesPrefix.Length -and
            $probeFull.StartsWith($probesPrefix, $pathComparison)) {
            $relativeDir = Split-Path -Parent $probeFull.Substring($probesPrefix.Length)
            if ($relativeDir) {
                $resultsDir = Join-Path "results" $relativeDir
            }
        }
        if (-not (Test-Path -LiteralPath $resultsDir)) {
            New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
        }
        $probeName = [System.IO.Path]::GetFileNameWithoutExtension($ProbePath)
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $outPath = Join-Path $resultsDir "$($probeName)_$($timestamp).txt"
        [System.IO.File]::WriteAllBytes($outPath, $responseBytes.ToArray())
        Write-Host "[*] Saved to $outPath"
    }
} catch {
    Write-Error "[!] Error: $_"
    exit 1
} finally {
    if ($stream) { $stream.Close() }
    if ($client) { $client.Close() }
}
