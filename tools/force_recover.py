import vgamepad as vg
import time

g = vg.VX360Gamepad()
time.sleep(0.5)

def tap(btn, hold=0.15, wait=0.5):
    g.press_button(btn); g.update(); time.sleep(hold)
    g.release_button(btn); g.update(); time.sleep(wait)

B = vg.XUSB_BUTTON.XUSB_GAMEPAD_B
A = vg.XUSB_BUTTON.XUSB_GAMEPAD_A
R = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT
U = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP
D = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN
PS = vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE
OPTIONS = vg.XUSB_BUTTON.XUSB_GAMEPAD_START

# Step 1: PS button to go home
print("Step 1: PS home")
g.press_button(PS); g.update(); time.sleep(0.2)
g.release_button(PS); g.update(); time.sleep(2)

# Step 2: dismiss anything
print("Step 2: B x3 to dismiss")
for _ in range(3): tap(B, 0.1, 0.3)
time.sleep(1)

# Step 3: try Options button on the game to get close option
print("Step 3: Options on game icon")
tap(OPTIONS); time.sleep(1.5)

# Step 4: navigate down to "Close Game" in context menu
print("Step 4: navigate to Close Game")
for _ in range(8): tap(D, 0.1, 0.3)
tap(A); time.sleep(3)

# Step 5: Confirm close if needed
print("Step 5: confirm close")
tap(A); time.sleep(1)
tap(A); time.sleep(5)

# Step 6: Wait on home screen then relaunch
print("Step 6: relaunch")
tap(A); time.sleep(2)
tap(A); time.sleep(2)
tap(A); time.sleep(2)

print("Waiting 45s for loader...")
time.sleep(45)
print("Done")
