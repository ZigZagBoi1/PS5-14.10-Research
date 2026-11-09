# Chiaki PS5 Remote Play MCP

A local stdio MCP server that lets an AI **see the existing Chiaki stream, press one PS5 button, and see the result**. It does not pair a console, start a second stream, or close Chiaki. It is Windows-only and currently uses a visible desktop capture, so Chiaki must be foreground and unobscured.

## Install

Use a Python environment on the same unlocked Windows desktop as Chiaki:

```powershell
python -m pip install -r tools/chiaki_mcp/requirements.txt
```

Add this server to any MCP client's server configuration, replacing the path with this repository's absolute path:

```json
{
  "mcpServers": {
    "chiaki-ps5": {
      "command": "python",
      "args": ["C:/absolute/path/to/PS5-14.10-Research/tools/chiaki_mcp/server.py"]
    }
  }
}
```

The client must support MCP image content. Restart or reload the client after adding the server.

## AI workflow

1. Call `chiaki_status`. If Chiaki is not foreground, call `focus_chiaki`.
2. Call `observe_ps5`; inspect its PNG and retain `frame_token`.
3. Call `press_ps5_button` with one named button and that token. Inspect the new PNG and token before another action.
4. If capture or focus fails, stop input and diagnose the desktop session. Do not send a blind sequence.

`controls_guide` returns the active mapping and this workflow. Available buttons: `cross`, `circle`, `square`, `triangle`, `up`, `down`, `left`, `right`, `l1`, `r1`, `l2`, `r2`, `l3`, `r3`, `options`, `share`, `touchpad`, `ps`. The default mapping comes from [Chiaki's `settings.cpp`](https://github.com/streetpea/chiaki-ng/blob/main/gui/src/settings.cpp). If your Chiaki keyboard settings differ, set `CHIAKI_MCP_KEYMAP` to a JSON file mapping button names to PyAutoGUI key names, such as `{"cross":"enter","ps":"esc"}`.

MCP clients that support prompts can invoke `recover_lua_loader`. It teaches a screen-guided game relaunch and explicitly avoids a fixed blind macro.

The frame token expires after 10 seconds and is consumed on every input attempt. A `press_ps5_button` call returns a fresh frame. The server never assumes that a key press worked from its own input event; the AI has to inspect the returned image. A uniform frame is reported with a warning, since the PS5 can legitimately show a black loading screen.

## Scope and limitations

- Desktop capture uses Pillow `ImageGrab` on Chiaki's on-screen client rectangle. Another window covering Chiaki can contaminate the image. Keep Chiaki in front.
- The tool does not assert that the Lua loader is healthy. A separate framed ping probe is needed for that.
- The current server does not automate a game restart as a macro; the screen and PS5 menu state must guide each action.
- Existing Chiaki renderers may refuse third-party capture. [Chiaki issue #384](https://github.com/streetpea/chiaki-ng/issues/384) documents a Windows capture problem. If capture fails, this server stops input rather than guessing.
- Do not expose this MCP server over a public network. It controls a local authenticated Remote Play session.

## Live validation on this machine (2026-10-20)

The existing Chiaki 1.9.9 stream was captured at 356×287. It showed the PS5 14.10 Lua loader listening on port 9026. A single `ps` button press opened the PS5 control center; a second `ps` press returned to the loader screen. No game close or relaunch was needed during this validation. Chiaki's window was small, so maximizing it would improve visual inspection. This proves screen capture and PS-button injection for the observed session, not unattended recovery from every crash state.

## Tests

```powershell
python -m unittest discover -s tools/chiaki_mcp -p "test_*.py"
```
