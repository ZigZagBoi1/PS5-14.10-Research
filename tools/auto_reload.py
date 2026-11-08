"""Auto-reload PS5 browser every N seconds via vgamepad Triangle press."""
import vgamepad as vg
import time
import sys

INTERVAL = int(sys.argv[1]) if len(sys.argv) > 1 else 20

gp = vg.VX360Gamepad()
time.sleep(0.5)

i = 0
while True:
    i += 1
    print(f"[{time.strftime('%H:%M:%S')}] Reload #{i}")
    # Triangle = Y
    gp.press_button(vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)
    gp.update()
    time.sleep(0.15)
    gp.release_button(vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)
    gp.update()
    time.sleep(1)
    # X = A (confirm dialog if any)
    gp.press_button(vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
    gp.update()
    time.sleep(0.15)
    gp.release_button(vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
    gp.update()
    time.sleep(INTERVAL)
