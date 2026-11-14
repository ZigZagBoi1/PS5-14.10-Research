param(
    [int]$IntervalMs = 5000,
    [string]$LogFile = "F:\PS5-14.10-Research\results\crash_monitor.log"
)

# Monitor chiaki-ng for PS5 crash dialog, auto-dismiss and refresh.

Add-Type -AssemblyName System.Drawing

$src = @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Threading;

public class CrashMon2 {
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left, Top, Right, Bottom;
    }

    public static void SendKey(IntPtr h, byte vk) {
        PostMessage(h, 0x0100, (IntPtr)vk, IntPtr.Zero);
        Thread.Sleep(50);
        PostMessage(h, 0x0101, (IntPtr)vk, IntPtr.Zero);
    }

    public static int[] CheckWhiteRegion(IntPtr hWnd) {
        RECT r;
        if (!GetWindowRect(hWnd, out r)) return new int[]{-1,-1};
        int w = r.Right - r.Left;
        int h = r.Bottom - r.Top;
        if (w < 200 || h < 200) return new int[]{-2,-2};

        Bitmap bmp = new Bitmap(w, h, PixelFormat.Format24bppRgb);
        using (Graphics g = Graphics.FromImage(bmp)) {
            IntPtr hdc = g.GetHdc();
            PrintWindow(hWnd, hdc, 0x2);
            g.ReleaseHdc(hdc);
        }

        // Check center area for white OK button
        int cy = (int)(h * 0.58);
        int cx = w / 2;
        int whiteCount = 0;
        for (int x = cx - 100; x < cx + 100; x += 4) {
            if (x < 0 || x >= w) continue;
            for (int dy = -10; dy <= 10; dy += 5) {
                int y = cy + dy;
                if (y < 0 || y >= h) continue;
                Color c = bmp.GetPixel(x, y);
                if (c.R > 230 && c.G > 230 && c.B > 230) whiteCount++;
            }
        }

        // Check for dark overlay
        int darkCount = 0;
        int oy = (int)(h * 0.35);
        for (int x = cx - 100; x < cx + 100; x += 10) {
            if (x < 0 || x >= w) continue;
            Color c = bmp.GetPixel(x, oy);
            if (c.R < 80 && c.G < 80 && c.B < 80) darkCount++;
        }

        bmp.Dispose();
        return new int[]{whiteCount, darkCount};
    }
}
"@

Add-Type -TypeDefinition $src -ReferencedAssemblies System.Drawing

# Auto-detect chiaki-ng HWND
$chiakiProc = Get-Process | Where-Object { $_.ProcessName -like '*chiaki*' -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $chiakiProc) { "No chiaki-ng window found"; exit 1 }
$hwnd = [IntPtr]$chiakiProc.MainWindowHandle
$dismissCount = 0

"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Crash monitor v2 started. HWND=$hwnd" | Tee-Object -FilePath $LogFile -Append

while ($true) {
    try {
        $result = [CrashMon2]::CheckWhiteRegion($hwnd)
        $white = $result[0]
        $dark = $result[1]

        if ($white -gt 15 -and $dark -gt 10) {
            $dismissCount++
            $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $msg = "[$ts] CRASH DIALOG #$dismissCount (white=$white dark=$dark) - auto-dismissing"
            Write-Output $msg
            $msg | Out-File -FilePath $LogFile -Append -Encoding utf8

            [CrashMon2]::SendKey($hwnd, 0x0D)
            Start-Sleep -Seconds 3
            [CrashMon2]::SendKey($hwnd, 0x0D)
            Start-Sleep -Seconds 3
            [CrashMon2]::SendKey($hwnd, [byte][char]'2')

            "[$ts] Dismissed and refreshed" | Out-File -FilePath $LogFile -Append -Encoding utf8
        }
    } catch {
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        "[$ts] ERR: $_" | Out-File -FilePath $LogFile -Append -Encoding utf8
    }

    Start-Sleep -Milliseconds $IntervalMs
}
