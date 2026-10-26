-- CRASH_CLASS: LOW
-- PROBE 815c: list every executable region with its name, so the gadget scan
--            can pick the right module instead of guessing a base
--
-- 815b showed eboot is no longer at 0x1A880000 in this process: the map has
-- libSceSystemService at 0x1A710000 and no module covering 0x1A880000.
-- Module text carries prot 4 (execute-only) and eboot carries prot 5 (r+x).
-- Print every prot 4 and prot 5 region with its name and size.

print("=== PROBE 815c: EXECUTABLE REGIONS ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc674 = make_syscall(674)
local REGBUF = memory.alloc(0x10000)
local COUNTP = memory.alloc(0x10)
for off = 0, 0xFFFF, 4 do safe_wd(REGBUF + off, 0) end
safe_wd(COUNTP, 0)

local rv = -1
local okc, rc = pcall(function()
    return sc674(uint64(REGBUF), uint64(72), uint64(0x300), uint64(COUNTP), uint64(0x40000000))
end)
if okc then rv = to_num(rc) end
local n = safe_rd(COUNTP) or 0
print(string.format("[R] 674 ret=%d regions=%d", rv, n))

local found = 0
for i = 0, n - 1 do
    local rec = REGBUF + i * 72
    local lo = safe_rd(rec) or 0
    local hi = safe_rd(rec + 8) or 0
    local prot = safe_rd(rec + 0x18) or 0
    if (prot == 5 or prot == 4) and hi > lo and (hi - lo) >= 0x10000 then
        local s = ""
        for k = 0, 31 do
            local b = to_num(memory.read_byte(rec + 0x20 + k))
            if b == 0 then break end
            s = s .. string.char(b)
        end
        print(string.format("    prot=%d [%08X,%08X) size=0x%-7X %s", prot, lo, hi, hi - lo, s))
        found = found + 1
        if found >= 40 then break end
    end
end
print(string.format("[R] listed %d executable regions", found))

print("")
print("=== PROBE 815c DONE ===")
