-- CRASH_CLASS: HIGH
-- PROBE 803a: syscall 548 as a batch VM operation, and whether it can set PROT_EXEC
--
-- 13.60 body 0xffffffff8b47be60 (handler_text_offset 0xabbe60):
--   r13d = uap[0x18]                      ; count, must be >= 0
--   if (uap[8] & 0xe0bffb6f) != 0 -> EINVAL ; uap[8] must be 0 for us
--   loop i < count:
--       copyin(0x20 bytes from uap[0x10] + i*0x20) into a stack record
--       record: +0x00 qword addr, +0x08 qword payload, +0x10 qword len,
--               +0x18 byte prot, +0x1c dword op   (op = 0..4, jump table)
--       two of the op bodies test addr & 0x3fff and len & 0x3fff (16 KB pages),
--       reject prot bit 0x8, require addr + len not to wrap, then call
--       0xffffffff8ac8bdb0([proc+0x200], addr, addr+len, prot', 0) -- a vm_map_protect
--       shaped call.  The ordinary mprotect syscall refuses PROT_EXEC on this firmware;
--       this path is a different entry into the same VM layer.
--
-- This probe maps a throwaway page, records its 674 protection, then runs op 0..4 at
-- prot=3 (no change expected) and finally prot=7 (RWX) and prot=5 (RX) at the op that
-- behaved like a protection update.  Every call prints before and after, so a death
-- still names the op that did it.

print("=== PROBE 803a: SYSCALL 548 BATCH VM OPS ===")
print("")

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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function split(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = (rd(a + i) or 0) % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end

local sc674 = make_syscall(674)
local sc_mmap = make_syscall(477)
local sc548 = make_syscall(548)
pcall(function() return make_syscall(20)() end)

local STRIDE, MAX = 72, 512
local regions = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(regions + i, 0) end
local countp = memory.alloc(16)
wq(countp, uint64(0))

local function query()
    wq(countp, uint64(0))
    local ok, ret = pcall(function()
        return sc674(uint64(regions), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
    end)
    if not ok then return nil, 0 end
    local n = rd(countp) or 0
    if n > MAX then n = MAX end
    return to_num(ret), n
end

local function region_of(va)
    local _, n = query()
    for i = 0, n - 1 do
        local b = regions + i * STRIDE
        local lo = (rd(b) or 0) + (rd(b + 4) or 0) * 4294967296
        local hi = (rd(b + 8) or 0) + (rd(b + 12) or 0) * 4294967296
        if va >= lo and va < hi then
            return lo, hi, rd(b + 0x18) or 0, ascii(b + 0x20, 0x18)
        end
    end
    return nil
end

-- Throwaway target: one 16 KB page, anonymous, RW.
local TARGET = 0x700000000
local ok_map, rv_map = pcall(function()
    return sc_mmap(uint64(TARGET), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local map_n = ok_map and to_num(rv_map) or -999
print(string.format("[0] mmap target ret=%d", map_n))
wd(TARGET, 0x41414141)
local lo, hi, prot0, name0 = region_of(TARGET)
print(string.format("[0] region before: [%s,%s) prot=%s %s",
    lo and string.format("%X", lo) or "?", hi and string.format("%X", hi) or "?",
    prot0 and string.format("%X", prot0) or "?", name0 or "?"))
if not lo then print("  target not mapped, stopping"); return end

-- record array (separate allocation, never inside the target page)
local recs = memory.alloc(0x20 * 8)
local function set_rec(i, addr, payload, len, prot, op)
    local b = recs + i * 0x20
    wq(b, split(0, addr))
    wq(b + 8, split(0, payload))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, op)
end

local function call548(addr, payload, len, prot, op)
    set_rec(0, addr, payload, len, prot, op)
    local ok, ret = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(ret)
end

local function report(tag, ret)
    local l, h, p = region_of(TARGET)
    print(string.format("  %s ret=%s prot=%s [%s,%s)", tag, tostring(ret),
        p and string.format("%X", p) or "?", l and string.format("%X", l) or "?",
        h and string.format("%X", h) or "?"))
    return p
end

print("")
print("[1] count=1, prot=3, each op")
for op = 0, 4 do
    local r = call548(TARGET, 0, 0x4000, 3, op)
    report("op=" .. op, r)
end

print("")
print("[2] count=1 with prot=7 (RWX) on every op")
for op = 0, 4 do
    local r = call548(TARGET, 0, 0x4000, 7, op)
    local p = report("op=" .. op .. " prot7", r)
    if p == 7 then print("  *** PROT IS NOW 7 ***") end
end

print("")
print("[3] prot=5 (RX) on every op")
for op = 0, 4 do
    local r = call548(TARGET, 0, 0x4000, 5, op)
    local p = report("op=" .. op .. " prot5", r)
    if p == 5 then print("  *** PROT IS NOW 5 ***") end
end

print("")
print("[4] count=3 in one call, prot=3")
set_rec(0, TARGET, 0, 0x4000, 3, 0)
set_rec(1, TARGET, 0, 0x4000, 3, 1)
set_rec(2, TARGET, 0, 0x4000, 3, 2)
local ok3, ret3 = pcall(function()
    return sc548(uint64(0), uint64(0), uint64(recs), uint64(3), uint64(0))
end)
print("  count3 ok=" .. tostring(ok3) .. " ret=" .. tostring(ok3 and to_num(ret3) or "-"))

print("")
print("[5] alive pid=" .. to_num(make_syscall(20)()))
