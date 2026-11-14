# PS5 keystroke automation via chiaki-ng
param([string]$Action = "screenshot", [int]$Count = 1)

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Threading;
public class PS5K {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    public const uint WM_KEYDOWN = 0x0100;
    public const uint WM_KEYUP = 0x0101;
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }

    public static void Key(IntPtr hwnd, int vk) {
        SetForegroundWindow(hwnd);
        Thread.Sleep(50);
        PostMessage(hwnd, WM_KEYDOWN, (IntPtr)vk, IntPtr.Zero);
        Thread.Sleep(80);
        PostMessage(hwnd, WM_KEYUP, (IntPtr)vk, IntPtr.Zero);
        Thread.Sleep(300);
    }
}
"@

$hwnd = (Get-Process -Name "chiaki" -ErrorAction SilentlyContinue | Select-Object -First 1).MainWindowHandle
if ($hwnd -eq 0) { Write-Error "Chiaki not found"; exit 1 }

$keys = @{
    "enter"=0x0D; "back"=0x08; "escape"=0x1B; "up"=0x26; "down"=0x28;
    "left"=0x25; "right"=0x27; "triangle"=0x43; "options"=0x4F;
    "l1"=0x32; "r1"=0x33; "l2"=0x31; "r2"=0x34
}

if ($Action -eq "screenshot") {
    $rect = New-Object PS5K+RECT
    [PS5K]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
    $w = $rect.Right - $rect.Left; $h = $rect.Bottom - $rect.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($rect.Left, $rect.Top, 0, 0, [System.Drawing.Size]::new($w, $h))
    $g.Dispose()
    $path = "F:\temp\claude\c5bbecfaad4e8472\cd8e5e98-c948-4c39-9e72-b96ec8b1f92d\scratchpad\ps5_$(Get-Date -Format 'HHmmss').png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output $path
} elseif ($keys.ContainsKey($Action)) {
    for ($i = 0; $i -lt $Count; $i++) { [PS5K]::Key($hwnd, $keys[$Action]) }
    Write-Output "sent $Action x$Count"
} else {
    Write-Error "Unknown action: $Action (valid: $($keys.Keys -join ', '), screenshot)"
}
