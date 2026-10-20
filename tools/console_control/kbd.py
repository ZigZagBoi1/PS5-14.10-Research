#!/usr/bin/python3
# uinput keyboard for headless key injection (Plasma 6 Wayland: XTEST is dead)
import struct, fcntl, sys, time

fd = open("/dev/uinput", "wb", buffering=0)
fcntl.ioctl(fd, 0x40045564, 1)   # UI_SET_EVBIT EV_KEY
for _k in range(256):
    fcntl.ioctl(fd, 0x40045565, _k)  # UI_SET_KEYBIT each code
# uinput_user_dev: name[80], id{bustype,vendor,product,version} (4x u16), ffmax, absmax...
name = b"hermes-kbd"
dev = name.ljust(80, b"\0") + struct.pack("HHHHI", 0x19, 1, 1, 1, 0) + b"\0" * (64 * 4 * 4)
fd.write(dev)
fcntl.ioctl(fd, 0x5501)          # UI_DEV_CREATE
time.sleep(1.2)

KEY = {
 "return":28,"enter":28,"escape":1,"esc":1,"down":108,"up":103,"left":105,"right":106,
 "c":46,"t":20,"o":24,"f":33,"backslash":86,"1":2,"2":3,"3":4,"4":5,"5":6,"6":7,
 "ctrl":29,"shift":42,"space":57,"backspace":14,"tab":15,"a":30,"b":48,"d":32,"e":18,
 "g":34,"h":35,"i":23,"j":36,"k":37,"l":38,"m":50,"n":49,"p":25,"q":16,"r":19,"s":31,
 "u":22,"v":47,"w":17,"x":45,"y":21,"z":44,"bracketright":27,"bracketleft":26,
 "insert":110,"delete":111,"equal":13,"minus":12,"pageup":104,"pagedown":109,
}

def ev(t, code, val):
    fd.write(struct.pack("llHHi", int(time.time()), 0, t, code, val))
    fd.flush()

def tap(key, mods=()):
    codes = [KEY[m] for m in mods] + [KEY[key]]
    for c in codes: ev(1, c, 1)
    ev(0, 0, 0)
    time.sleep(0.06)
    for c in reversed(codes): ev(1, c, 0)
    ev(0, 0, 0)
    fd.flush()

if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--daemon":
        # read commands from stdin: "key ctrl+o" style
        for line in sys.stdin:
            line = line.strip()
            if not line: continue
            parts = line.split("+")
            try:
                if len(parts) == 1: tap(parts[0])
                else: tap(parts[-1], mods=parts[:-1])
            except Exception as e:
                pass
    else:
        for spec in args:
            parts = spec.split("+")
            try:
                if len(parts) == 1: tap(parts[0])
                else: tap(parts[-1], mods=parts[:-1])
            except KeyError:
                print("unknown key:", spec, file=sys.stderr)
