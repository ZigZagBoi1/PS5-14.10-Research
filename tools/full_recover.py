import vgamepad as vg
import time

g = vg.VX360Gamepad()
time.sleep(0.5)

def tap(btn, hold=0.15, wait=0.4):
    g.press_button(btn); g.update(); time.sleep(hold)
    g.release_button(btn); g.update(); time.sleep(wait)

B = vg.XUSB_BUTTON.XUSB_GAMEPAD_B
A = vg.XUSB_BUTTON.XUSB_GAMEPAD_A
R = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT
U = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP
D = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN
PS = vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE

# Phase 1: dismiss any dialogs
print("Phase 1: dismiss dialogs (A spam)")
for _ in range(10):
    tap(A, 0.1, 0.3)
time.sleep(2)

# Phase 2: go home
print("Phase 2: PS button to home")
g.press_button(PS); g.update(); time.sleep(1.5)
g.release_button(PS); g.update(); time.sleep(2)

# Phase 3: try to close game via app switcher
# Esc -> down -> right -> enter -> up hold -> enter -> down x2 -> enter
print("Phase 3: close game")
tap(B); time.sleep(0.5)  # dismiss overlay if any
tap(B); time.sleep(0.5)
tap(B); time.sleep(0.5)

# Try direct: press PS to go home, then navigate to game and use options
g.press_button(PS); g.update(); time.sleep(1.5)
g.release_button(PS); g.update(); time.sleep(2)

# A few more dismissals
for _ in range(5):
    tap(A, 0.1, 0.3)
time.sleep(3)

# Try navigating: down to hover home icon
tap(D); time.sleep(0.3)
# Right to app switcher
tap(R); time.sleep(0.3)
# Enter to open app switcher
tap(A); time.sleep(1)
# Up hold to ensure at top
g.press_button(U); g.update(); time.sleep(4)
g.release_button(U); g.update(); time.sleep(0.5)
# Enter to select app
tap(A); time.sleep(1)
# Down x2 to "close game"
tap(D); time.sleep(0.3)
tap(D); time.sleep(0.3)
# Enter to confirm close
tap(A); time.sleep(3)

print("Phase 4: waiting for home menu (5s)")
time.sleep(5)

# Relaunch: Enter
print("Phase 5: relaunch game")
tap(A); time.sleep(2)
tap(A); time.sleep(2)

print("Phase 6: waiting 40s for loader")
time.sleep(40)
print("Done")
