-- CRASH_CLASS: HIGH
-- PROBE 565b: what does syscall 639 write on its failure path?
--
-- Context: 565a found 639 returns -1 and still writes two dwords into arg3:
--   (0x112097C0, 3) for one call and (0x11303C80, 3) for another, i.e. an
--   address pair that changes with the caller's buffers.
-- This probe fixes the buffer and varies arg1 (the queried address) to see
-- whether the written value tracks arg1, and whether a kernel VA produces a
-- kernel-shaped word.

print("=== PROBE 565b: SYS 639 WRITE ===")

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
local function u64(hi, lo)
    return uint64(string.format("0x%08X%08X", hi, lo))
end

local CANARY = 0xA5A5A5A5
local PAGE = 0x1000
local function fresh()
    local p = to_num(memory.alloc(PAGE))
    for off = 0, PAGE - 4, 4 do safe_wd(p + off, CANARY) end
    return p
end

local heap = fresh()
local out = fresh()
print(string.format("[A] heap=0x%08X out=0x%08X", heap, out))

local function probe(tag, hi, lo)
    local sc = make_syscall(639)
    for off = 0, 0x40, 4 do safe_wd(out + off, CANARY) end
    local args = u64(hi, lo)
    print(string.format("[%s] arg1=0x%08X%08X", tag, hi, lo))
    local ok, ret = pcall(function()
        return sc(args, uint64(0x100), uint64(out), uint64(0x100), uint64(0), uint64(0))
    end)
    print(string.format("  ret=%s", ok and tostring(ret) or "PCALL-FAIL"))
    local s = ""
    for off = 0, 0x40, 4 do
        local v = rd(out + off)
        if v ~= CANARY and v ~= -1 then
            s = s .. string.format(" %03X=%08X", off, v)
        end
    end
    if s == "" then s = " (no write)" end
    print("  out:" .. s)
end

probe("B", 0, heap)
probe("C", 0, 0)
probe("D", 0, 0x1000)
probe("E", 0, 0xFFFFFFFF)
probe("F", 0, 0x1A880000)
probe("G", 0, 0x103230000 - 0x100000000)

print("[H] kernel VA 0xFFFF800000000000")
do
    local sc = make_syscall(639)
    for off = 0, 0x40, 4 do safe_wd(out + off, CANARY) end
    local ok, ret = pcall(function()
        return sc(u64(0xFFFF8000, 0), uint64(0x100), uint64(out), uint64(0x100), uint64(0), uint64(0))
    end)
    print(string.format("  ret=%s", ok and tostring(ret) or "PCALL-FAIL"))
    local s = ""
    for off = 0, 0x40, 4 do
        local v = rd(out + off)
        if v ~= CANARY and v ~= -1 then s = s .. string.format(" %03X=%08X", off, v) end
    end
    if s == "" then s = " (no write)" end
    print("  out:" .. s)
end

print("=== 565b DONE ===")
