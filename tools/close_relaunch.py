import vgamepad as vg
import time

g = vg.VX360Gamepad()
time.sleep(0.5)

def tap(btn, hold=0.15, wait=0.5):
    g.press_button(btn); g.update(); time.sleep(hold)
    g.release_button(btn); g.update(); time.sleep(wait)

B = vg.XUSB_BUTTON.XUSB_GAMEPAD_B
A = vg.XUSB_BUTTON.XUSB_GAMEPAD_A
D = vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN
PS = vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE
OPTIONS = vg.XUSB_BUTTON.XUSB_GAMEPAD_START

# First: dismiss any crash error report with Circle (B = O on PS5)
print("1: Dismiss crash dialogs")
for _ in range(5):
    tap(A, 0.1, 0.4)
time.sleep(1)
for _ in range(5):
    tap(B, 0.1, 0.4)
time.sleep(1)

# Hold PS to go to home screen
print("2: Hold PS to go home")
g.press_button(PS); g.update()
time.sleep(1.5)
g.release_button(PS); g.update()
time.sleep(3)

# B to dismiss control center if it appeared instead
print("3: Dismiss control center")
tap(B, 0.1, 0.5)
time.sleep(1)

# Now on home screen. The game tile should be focused.
# Press Options to get context menu
print("4: Options on game tile")
tap(OPTIONS)
time.sleep(2)

# Navigate to Close Game (usually a few items down)
print("5: Navigate to Close Game")
for _ in range(6):
    tap(D, 0.1, 0.3)

# Select Close Game
print("6: Select Close Game")
tap(A)
time.sleep(2)

# Confirm if asked
print("7: Confirm")
tap(A)
time.sleep(5)

# Now on home screen. Relaunch game.
print("8: Relaunch game")
tap(A)
time.sleep(2)
tap(A)
time.sleep(2)

print("9: Waiting 50s for game + loader")
time.sleep(50)
print("Done")
