import vgamepad as vg
import time

g = vg.VX360Gamepad()
time.sleep(0.5)

def tap(btn, hold=0.15, wait=0.5):
    g.press_button(btn); g.update(); time.sleep(hold)
    g.release_button(btn); g.update(); time.sleep(wait)

A = vg.XUSB_BUTTON.XUSB_GAMEPAD_A
B = vg.XUSB_BUTTON.XUSB_GAMEPAD_B
PS = vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE

# Dismiss everything first
print("Dismiss dialogs")
for _ in range(5): tap(B, 0.1, 0.3)
for _ in range(5): tap(A, 0.1, 0.3)
time.sleep(2)

# Hold PS to ensure home
print("PS home")
g.press_button(PS); g.update(); time.sleep(1.5)
g.release_button(PS); g.update(); time.sleep(3)

# Dismiss control center
tap(B); time.sleep(1)

# Just spam A to launch whatever is focused
print("Spam A to launch")
for _ in range(10): tap(A, 0.1, 0.5)

print("Wait 50s")
time.sleep(50)
print("Done")
