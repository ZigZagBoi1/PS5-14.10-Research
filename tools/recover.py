import vgamepad as vg
import time

g = vg.VX360Gamepad()
time.sleep(0.5)

def tap(btn, hold=0.1, wait=0.3):
    g.press_button(btn); g.update(); time.sleep(hold)
    g.release_button(btn); g.update(); time.sleep(wait)

B = vg.XUSB_BUTTON.XUSB_GAMEPAD_B
A = vg.XUSB_BUTTON.XUSB_GAMEPAD_A
R = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT

for _ in range(3): tap(B)
time.sleep(0.5)
g.press_button(vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE)
g.update(); time.sleep(1.5)
g.release_button(vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE)
g.update(); time.sleep(1.5)
for _ in range(5): tap(A)
time.sleep(0.5)
for _ in range(3): tap(B)
time.sleep(0.5)
tap(R)
tap(A)
tap(A)
print("Recovery sent, waiting 25s")
time.sleep(25)
print("Done")
