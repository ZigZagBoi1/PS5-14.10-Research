-- CRASH_CLASS: MODERATE
-- PROBE 242a: the 622 commands that run, and the one that ends the connection
--
-- Context: 241a passed sys 622 the six slots its 13.60 handler reads and the
-- size gate behaved exactly as the analysis says - size 0x41 returns
-- 0x800E0001, size 0x40 returns 0x8002004E (the credential predicate). Two
-- command groups behaved differently from every earlier sweep of this syscall:
--
--   cmd 0x200..0x270 and cmd 0x813 returned 0 and wrote 0xFFFFFFFF into the
--   caller's buffer, so those sub-handlers ran and produced a value;
--   cmd 0x302..0x320 and 0x400..0x493 returned -1 with arg3 null, and the one
--   call with a mapped page as arg3 (cmd 0x302) ended the connection.
--
-- So 622 is not closed. This probe asks three things, safest first:
--   [A] what the 0x200 group writes for a range of sub-commands,
--   [B] whether a non-null arg3 changes the answer for the 0x200 group,
--   [C] what the 0x400 group does with a page filled with 0x41 (a handler that
--       follows a pointer out of caller-supplied data survives this; one that
--       copies a fixed structure from it may not),
--   [D] the 0x302 call that ended the connection, alone and last, so everything
--       above is already on the wire when it happens.

print("=== PROBE 242a: 622 COMMANDS THAT RUN ===")
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
local function safe_wq(addr, val)
    if type(val) == "number" then val = uint64(val) end
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(val)
    if val == nil then return "nil" end
    local text = tostring(val)
    if text == "-1" then return "-1" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local low = l % 0x100000000
        if low == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, low)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return text
end

print(string.format("PID: %d", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local sc622 = make_syscall(622)
local sc477 = make_syscall(477)
local buf = memory.alloc(0x200)

local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local page_valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0
print(string.format("page=%s valid=%s", sgn(page), tostring(page_valid)))

local function call622(cmd, sub, size, use_page)
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
    local addr = uint64(0)
    if use_page and page_valid then addr = page end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(sub), uint64(buf), addr, uint64(size), uint64(0))
    end)
    return (ok and sgn(ret) or "PCALL-FAIL"), sgn(safe_rd(buf)), sgn(safe_rd(buf + 4)), sgn(safe_rd(buf + 8))
end

-- ============================================================
-- [A] the 0x200 group, sub 0..15
-- ============================================================
print("")
print("[A] cmd 0x200 group, sub 0..15, arg3 null")
for sub = 0, 15 do
    local ret, d0, d1, d2 = call622(0x200, sub, 0x40, false)
    print(string.format("  sub=%-2d ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", sub, ret, d0, d1, d2))
end

-- ============================================================
-- [B] same group with arg3 = a mapped page
-- ============================================================
print("")
print("[B] cmd 0x200 group, sub 0..3, arg3 = page")
if page_valid then
    for sub = 0, 3 do
        local ret, d0, d1, d2 = call622(0x200, sub, 0x40, true)
        print(string.format("  sub=%-2d ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", sub, ret, d0, d1, d2))
    end
else
    print("  skipped: no page")
end

-- ============================================================
-- [C] the 0x400 group with a page of 0x41
-- ============================================================
print("")
print("[C] cmd 0x400 group with a page filled with 0x41")
if page_valid then
    for i = 0, 0x3FF do safe_wq(page + i * 8, uint64(0x4141414141414141)) end
    for _, cmd in ipairs({ 0x400, 0x401, 0x410, 0x493 }) do
        local ret, d0, d1, d2 = call622(cmd, 0, 0x40, true)
        print(string.format("  cmd=0x%-4X ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", cmd, ret, d0, d1, d2))
    end
else
    print("  skipped: no page")
end

-- ============================================================
-- [D] the 0x302 call, last
-- ============================================================
print("")
print("[D] cmd 0x302 with the 0x41 page (this one ended the last connection)")
if page_valid then
    local ret, d0, d1, d2 = call622(0x302, 0, 0x40, true)
    print(string.format("  cmd=0x302 ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", ret, d0, d1, d2))
else
    print("  skipped: no page")
end

print("")
print("=== PROBE 242a COMPLETE ===")
