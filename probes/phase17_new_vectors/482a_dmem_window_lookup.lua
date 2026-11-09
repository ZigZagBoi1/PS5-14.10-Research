-- CRASH_CLASS: LOW
-- PROBE 482a: is any mapping inside the window the dmem dispatcher accepts?
--
-- 13.60 @ 0x3d2213 tests q0 with: rcx = q0 + 0xffffffdb00000000; accept iff
-- rcx < 0x58000001, i.e. q0 in [0x2500000000, 0x2558000001). A heap page is
-- outside it, which is why 0x80108002/0x80108015/0xC010801A returned -1 with
-- q0 = a mapped page and 0 with q0 = 0. This probe lists the process VM map and
-- looks for any region that intersects that window, and tries a read at three
-- addresses inside it.

print("=== PROBE 482a: dmem accepted-window lookup ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(addr)
    local h, l = 0, 0
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if not ok then return 0, 0 end
    if type(v) == "table" and v.h then h, l = v.h, v.l else l = to_num(v) end
    return h, l
end
local WIN_LO_H, WIN_LO_L = 0x00000025, 0x00000000
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local countp = memory.alloc(16)
pcall(function() memory.write_qword(countp, uint64(0)) end)
local ret = make_syscall(674)(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
local n = to_num(memory.read_dword(countp))
print(string.format("[map] ret=%d count=%d", to_num(ret) == 0 and 0 or -1, n))

local hits = 0
for i = 0, math.min(n, MAX) - 1 do
    local rec = buf + i * STRIDE
    local sh, sl = q(rec)
    local eh, el = q(rec + 8)
    local prot = to_num(memory.read_dword(rec + 0x18))
    local inwin = false
    if sh == 0 and eh == 0 then
        if sl < 0x25580001 and el > 0x25000000 then inwin = true end
    elseif sh > 0 or eh > 0 then
        inwin = true
    end
    if inwin then
        hits = hits + 1
        print(string.format("[hit] %3d %08X%08X-%08X%08X prot=%X", i, sh, sl, eh, el, prot))
    end
end
print("[summary] regions in the accepted window: " .. hits)

for _, a in ipairs({ 0x25000000, 0x25200000, 0x25500000 }) do
    local ok, v = pcall(function() return memory.read_dword(a) end)
    print(string.format("[read] %08X ok=%s val=%s", a, tostring(ok), ok and string.format("%08X", to_num(v)) or "fault"))
end
print("=== PROBE 482a COMPLETE ===")
