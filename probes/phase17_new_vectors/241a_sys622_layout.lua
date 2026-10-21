-- CRASH_CLASS: MODERATE
-- PROBE 241a: sys 622 with the six-argument layout the 13.60 handler reads
--
-- Context: 55b/55c swept 400+ command codes through 622 and every call came
-- back 0 with the same dword in the buffer, which was read as "no device
-- context" and closed the family. The 13.60 analysis of the same handler
-- (results/kernel_handlers/analysis/sys_622_deep.md) recovers a different
-- shape: six slots, read as
--
--   arg0 cmd (r14d)      arg1 sub-command or device index (r15d)
--   arg2 user buffer     arg3 secondary user address (copyin source)
--   arg4 size, must be <= 0x40   arg5 extra
--
-- and the top-level size gate is `cmp r12, 0x40; ja -> 0x800E0001`. If the
-- earlier sweep put the size somewhere other than arg4, every call died at
-- that gate, and the uniform answer was the gate, not the device context.
--
-- This probe passes all six slots explicitly and uses the gate itself as the
-- control: size 0x41 must fail, size 0x40 must get further. It sweeps one
-- command from each dispatch table rather than all 400, because the point is
-- whether the layout is right, not which command works.

print("=== PROBE 241a: SYS 622 SIX-SLOT LAYOUT ===")
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
local buf = memory.alloc(0x200)

local function call622(cmd, sub, size, addr_off)
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
    local addr = uint64(0)
    if addr_off then addr = uint64(addr_off) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(sub), uint64(buf), addr, uint64(size), uint64(0))
    end)
    local d0 = safe_rd(buf)
    local d1 = safe_rd(buf + 4)
    return (ok and sgn(ret) or "PCALL-FAIL"), sgn(d0), sgn(d1)
end

-- ============================================================
-- [A] the size gate itself: 0x41 must fail, 0x40 must get past it
-- ============================================================
print("")
print("[A] size gate, cmd 0x100")
for _, size in ipairs({ 0x40, 0x41, 0x100 }) do
    local ret, d0, d1 = call622(0x100, 0, size, nil)
    print(string.format("  size=0x%-4X ret=%-24s buf[0]=%-24s buf[4]=%s", size, ret, d0, d1))
end

-- ============================================================
-- [B] one command from each dispatch table
-- ============================================================
print("")
print("[B] one command per table, size 0x40")
local probes = {
    { 0x100, "table 1 first" },
    { 0x133, "table 1 last" },
    { 0x200, "table 2 first" },
    { 0x270, "table 2 last" },
    { 0x12D, "bitmap gate 45" },
    { 0x302, "table 3 first" },
    { 0x320, "table 3 last" },
    { 0x400, "table 4 first" },
    { 0x493, "table 4 last" },
    { 0x271, "triple gate a" },
    { 0x520, "direct call" },
    { 0x813, "special path" },
}
for _, item in ipairs(probes) do
    local ret, d0, d1 = call622(item[1], 0, 0x40, nil)
    print(string.format("  cmd=0x%-4X %-16s ret=%-24s buf[0]=%-24s buf[4]=%s",
        item[1], item[2], ret, d0, d1))
end

-- ============================================================
-- [C] the same commands with a valid secondary address
-- ============================================================
print("")
print("[C] same commands, arg3 = a mapped page")
local sc477 = make_syscall(477)
local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local page_valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0
print(string.format("  page=%s valid=%s", sgn(page), tostring(page_valid)))
if page_valid then
    for _, item in ipairs({ { 0x100, "" }, { 0x200, "" }, { 0x302, "" }, { 0x400, "" }, { 0x813, "" } }) do
        for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
        local ok, ret = pcall(function()
            return sc622(uint64(item[1]), uint64(0), uint64(buf), page, uint64(0x40), uint64(0))
        end)
        print(string.format("  cmd=0x%-4X ret=%-24s buf[0]=%-24s buf[4]=%s",
            item[1], ok and sgn(ret) or "PCALL-FAIL", sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))
    end
end

-- ============================================================
-- [D] sub-command sweep on the first table entry
-- ============================================================
print("")
print("[D] cmd 0x100, sub 0..7")
for sub = 0, 7 do
    local ret, d0, d1 = call622(0x100, sub, 0x40, nil)
    print(string.format("  sub=%d ret=%-24s buf[0]=%-24s buf[4]=%s", sub, ret, d0, d1))
end

print("")
print("=== PROBE 241a COMPLETE ===")
