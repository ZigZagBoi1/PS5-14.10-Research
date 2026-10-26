-- CRASH_CLASS: MODERATE
-- PROBE 803e: map the max_protection of every anonymous mapping shape
--
-- 548 op 2 reaches vm_map_protect and returns -1 for any requested prot with the X bit, which is
-- the FreeBSD max_protection check.  FreeBSD's flags2maxprot strips X when the mapping asks for
-- it and keeps it when the mapping does not, so the max_protection of an anonymous mapping
-- depends on the prot passed to mmap.  This probe builds one page per creation prot and asks
-- op 2 for a range of target protections, printing what the kernel actually stored (sys 674).

print("=== PROBE 803e: MAX_PROTECTION MATRIX FOR 548 OP 2 ===")
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

local recs = memory.alloc(0x20 * 8)
local function protect(addr, len, prot)
    local b = recs
    wq(b, split(0, addr))
    wq(b + 8, split(0, 0))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, 2)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end

local BASE = 0x700000000
local SLOT = 0x4000
local function page(i, prot)
    local addr = BASE + i * 0x10000
    pcall(function() return sc_munmap(uint64(addr), uint64(SLOT)) end)
    local ok = pcall(function()
        return sc_mmap(uint64(addr), uint64(SLOT), uint64(prot), uint64(0x1012),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    return addr, ok
end

local creates = {0, 1, 2, 3, 5, 0x30, 0x31, 0x33, 0x34}
local wants = {1, 2, 3, 4, 5, 6, 7, 0x30, 0x33, 0x34}

print(string.format("%-8s", "create") .. "  want: " ..
    " 1    2    3    4    5    6    7    30   33   34")
local i = 0
for _, c in ipairs(creates) do
    i = i + 1
    local addr = page(i, c)
    local _, _, p0 = region_of(addr)
    local row = string.format("%02X(%-3s)", c, tostring(p0))
    for _, w in ipairs(wants) do
        local r = protect(addr, SLOT, w)
        local _, _, p = region_of(addr)
        if type(r) == "string" then
            row = row .. " ERR "
        elseif p == nil then
            row = row .. " GONE"
        else
            row = row .. string.format(" %02X%s ", p, r == 0 and " " or "-")
        end
    end
    print(row)
end

print("")
print("[legend] cell = stored prot after the call, '-' after it means ret ~= 0")
print("")
print("[B] alive pid=" .. to_num(getpid()))
