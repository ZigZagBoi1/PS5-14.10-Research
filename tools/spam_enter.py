import vgamepad as vg
import time

g = vg.VX360Gamepad()
time.sleep(0.5)

A = vg.XUSB_BUTTON.XUSB_GAMEPAD_A

print("Spamming A (Enter) 20 times...")
for i in range(20):
    g.press_button(A); g.update()
    time.sleep(0.15)
    g.release_button(A); g.update()
    time.sleep(0.5)

print("Waiting 30s for app to reload...")
time.sleep(30)
print("Done")
