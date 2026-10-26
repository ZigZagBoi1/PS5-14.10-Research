-- CRASH_CLASS: MODERATE
-- PROBE 565a: dump what the survey hits actually wrote
--
-- Context: the 564 canary sweep found four numbers that touch a caller page:
--   659  ret=0   writes to both buffers (3 dwords in arg1, 2 in arg3)
--   639  ret=-1  still changed 2 dwords of arg3
--   657  ret=-1  changed 1 dword of arg3
--   572  ret=0   18 dwords of arg3 (the known fixed heap record)
-- This probe prints the changed dwords with their values, testing two lengths
-- per number so a length-dependent copy shows up.

print("=== PROBE 565a: SURVEY HITS ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function rd(addr)
    local ok, v = pcall(function() return to_num(memory.read_dword(addr)) end)
    if ok then return v end
    return -1
end

local CANARY = 0xA5A5A5A5
local PAGE = 0x1000
local function fresh()
    local p = to_num(memory.alloc(PAGE))
    for off = 0, PAGE - 4, 4 do safe_wd(p + off, CANARY) end
    return p
end
local function dump(tag, p)
    local out = {}
    for off = 0, PAGE - 4, 4 do
        local v = rd(p + off)
        if v ~= CANARY and v ~= -1 then
            out[#out + 1] = string.format("%03X=%08X", off, v)
        end
    end
    if #out == 0 then
        print(string.format("  %s: no changes", tag))
    else
        local s = ""
        for i = 1, #out do
            if i > 1 then s = s .. " " end
            s = s .. out[i]
        end
        print(string.format("  %s: %d dwords  %s", tag, #out, s))
    end
end

local CASES = {
    { n = 659, len = 0x100 },
    { n = 659, len = 0x400 },
    { n = 639, len = 0x100 },
    { n = 639, len = 0x400 },
    { n = 657, len = 0x100 },
    { n = 657, len = 0x400 },
    { n = 572, len = 0x100 },
}

for _, c in ipairs(CASES) do
    print(string.format("[%d] len=%03X", c.n, c.len))
    local a = fresh()
    local b = fresh()
    local sc = make_syscall(c.n)
    local ok, ret = pcall(function()
        return sc(uint64(a), uint64(c.len), uint64(b), uint64(c.len), uint64(0), uint64(0))
    end)
    local rv = ok and tostring(ret) or "PCALL-FAIL"
    print(string.format("  ret=%s", rv))
    dump("arg1", a)
    dump("arg3", b)
end

print("=== 565a DONE ===")
