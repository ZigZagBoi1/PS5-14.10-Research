-- CRASH_CLASS: LOW
-- PROBE 735a: does memory.alloc(0x4000) plus a full fill end the process?
--
-- 733a and 734a both died between a working step and the next print, in a block
-- that allocates 0x1000 + 0x4000 + 0x4000 and fills them. This bisects that
-- block with a print before and after every allocation and every fill page.

print("=== PROBE 735a: ALLOC BISECT ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function wd(a,v) memory.write_dword(a,v) end
local function fill(p, n, val, tag)
    print(string.format("[%s] filling %d bytes at %08X", tag, n, p))
    for k=0,(n/4)-1 do wd(p+k*4, val) end
    print(string.format("[%s] filled ok", tag))
end

print("[1] before alloc 0x1000")
local a = to_num(memory.alloc(0x1000))
print(string.format("[1] alloc 0x1000 -> %08X", a))
fill(a, 0x1000, 0x11111111, "1f")

print("[2] before alloc 0x4000 (first)")
local b = to_num(memory.alloc(0x4000))
print(string.format("[2] alloc 0x4000 -> %08X", b))
fill(b, 0x4000, 0x22222222, "2f")

print("[3] before alloc 0x4000 (second)")
local c = to_num(memory.alloc(0x4000))
print(string.format("[3] alloc 0x4000 -> %08X", c))
fill(c, 0x4000, 0x33333333, "3f")

print("[4] before alloc 0x4000 (third)")
local d = to_num(memory.alloc(0x4000))
print(string.format("[4] alloc 0x4000 -> %08X", d))
fill(d, 0x4000, 0x44444444, "4f")

print("[5] three pages held: %08X %08X %08X" , a, b, c)
print(string.format("[6] health=%d", to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== 735a DONE ===")
