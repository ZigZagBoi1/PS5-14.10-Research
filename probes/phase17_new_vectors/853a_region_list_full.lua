-- CRASH_CLASS: LOW
-- PROBE 853a: does syscall 674 enumerate more than this process's own map?
--
-- Context: 848a called 674 with max=1 and the handler reported 1091 available
-- regions, while 55e/55f enumerated 317 and saw only userland VAs.  If the
-- larger count means the walk is over a bigger map (or the count is a global),
-- some records could carry kernel addresses.  This dumps every record and
-- prints any whose start or end is outside the user range.

print("=== PROBE 853a: FULL REGION LIST ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
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
local function safe_str(addr, maxlen)
    local out = {}
    for i = 0, maxlen - 1 do
        local ok, b = pcall(function() return memory.read_byte(addr + i) end)
        if not ok then break end
        local v = to_num(b)
        if v == 0 then break end
        if v < 32 or v > 126 then out[#out + 1] = "." else out[#out + 1] = string.char(v) end
    end
    return table.concat(out)
end

local sc = make_syscall(674)
local sc_mmap = make_syscall(477)

local MAXR = 1200
local STRIDE = 72
local buf = memory.alloc(MAXR * STRIDE + 0x1000)
for off = 0, MAXR * STRIDE + 0xFFF, 4 do safe_wd(buf + off, 0) end
local cnt = memory.alloc(8)
safe_wd(cnt, 0)

print(string.format("[0] pid=%d buf=%s", to_num(syscall.getpid()), hx(buf)))
local ok, ret = pcall(function()
    return sc(uint64(buf), uint64(STRIDE), uint64(MAXR), uint64(cnt), uint64(0x40000000))
end)
print(string.format("[A] 674 ret=%s ok=%s count=%d", hx(ret), tostring(ok), safe_rd(cnt) or 0))

local n = safe_rd(cnt) or 0
if n > MAXR then n = MAXR end

local kernelish = 0
local named = {}
for i = 0, n - 1 do
    local rec = buf + i * STRIDE
    local slo = safe_rd(rec) or 0
    local shi = safe_rd(rec + 4) or 0
    local elo = safe_rd(rec + 8) or 0
    local ehi = safe_rd(rec + 12) or 0
    local prot = safe_rd(rec + 0x18) or 0
    local nm = safe_str(rec + 0x20, 32)
    if shi >= 0xFFFF8000 or ehi >= 0xFFFF8000 or shi ~= 0 or ehi ~= 0 then
        kernelish = kernelish + 1
        print(string.format("[K] %04d %08X_%08X - %08X_%08X prot=%X %s",
            i, shi, slo, ehi, elo, prot, nm))
    else
        if nm ~= "" then named[nm] = true end
    end
end
print(string.format("[B] records=%d high-address records=%d", n, kernelish))

-- Summary of the distinct names, for the write-up.
local names = {}
for k in pairs(named) do names[#names + 1] = k end
table.sort(names)
print(string.format("[C] distinct userland names=%d", #names))
for i = 1, #names do print("    " .. names[i]) end

print("[Z] alive=true")
print("=== PROBE 853a COMPLETE ===")
