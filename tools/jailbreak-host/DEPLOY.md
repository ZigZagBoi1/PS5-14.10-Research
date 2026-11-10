# Deploying the 1-Click Jailbreak Host

## Quick Start (Windows server at 10.0.0.80)

### Step 1: Copy files to your server

Copy the entire `tools/jailbreak-host/` folder to your server at 10.0.0.80.

### Step 2: Run setup

Open PowerShell as Administrator on the server:

```powershell
cd path\to\jailbreak-host
.\setup.ps1
```

This downloads:
- Relapse exploit files (from ntfargo/Relapse-Exploit on GitHub)
- etaHEN.bin (from LightningMods/etaHEN releases)

### Step 3: Start the server

```powershell
python server.py
```

This starts:
- HTTP server on port 80 (serves the jailbreak page)
- DNS server on port 53 (redirects PS5 user guide to this server)

If port 80 or 53 is blocked, use `--port 8080 --no-dns`.

### Step 4: Configure your PS5

**Option A: With DNS redirect (recommended)**
1. PS5 > Settings > Network > Settings > Set Up Internet Connection
2. Select your connection > Advanced Settings
3. DNS Settings: Manual
4. Primary DNS: `10.0.0.80`
5. Secondary DNS: `8.8.8.8`
6. Save

Then just open **Settings > User's Guide / Helpful Info** and it loads
the jailbreak page automatically.

**Option B: Direct URL**
1. Open the PS5 web browser (via a game's web link or a redirect)
2. Navigate to `http://10.0.0.80/`
3. Press the Jailbreak button

### Step 5: Jailbreak

Press the single **Jailbreak** button. It will:
1. Run the Relapse exploit (WebKit + kernel)
2. Automatically send etaHEN
3. Wait for two on-screen notifications:
   - "etaHEN loaded"
   - "ShadowMount loaded"
4. Done. Your homebrew apps should now work.

## If Apps Still Don't Work

After jailbreaking, if homebrew apps show errors:

1. **Rebuild Database**: Settings > Storage > Console Storage >
   Rebuild Database. This re-indexes installed packages.

2. **Reinstall**: If an app was installed before the first jailbreak,
   it may need reinstalling after etaHEN loads.

3. **Check both notifications**: You MUST see both "etaHEN loaded" AND
   "ShadowMount loaded". If only one appears, try the jailbreak again
   after a full restart (not rest mode).

4. **No Rest Mode**: Do not put the PS5 in rest mode while jailbroken.
   Always do a full power off and re-jailbreak on next boot.

## Server Options

```
python server.py --help

Options:
  --port N          HTTP port (default: 80)
  --dns-port N      DNS port (default: 53)
  --no-dns          Disable DNS redirect
  --ps5-ip IP       PS5 IP (default: 10.0.0.96)
  --server-ip IP    Server IP (default: 10.0.0.80)
  --research-port N Research app port (default: 9100)
```

## Troubleshooting

**"etaHEN.bin not found"**: Run setup.ps1 or download manually from
https://github.com/LightningMods/etaHEN/releases

**DNS not working**: Run PowerShell as Administrator. Port 53 needs
admin privileges. Or use --no-dns and navigate directly.

**Relapse fails**: Restart the PS5 completely (not rest mode). Each
boot gets one jailbreak attempt. If it fails, power off fully and
try again.

**Port 80 in use**: Use `--port 8080` and navigate to
`http://10.0.0.80:8080/` on the PS5 browser.
