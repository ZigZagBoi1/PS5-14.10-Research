-- CRASH_CLASS: MODERATE
-- PROBE 1353a: push the 532 low commands past their first rejection
--
-- Context: 1352a (results/phase35_dead_end_reruns/1352a_sys532_unpriv_commands_20261109_105538.txt)
-- showed that for a game process sys 532 really dispatches on the codes the
-- priv_check(0x2aa) failure path allows (results/kernel_handlers/asm/sys_532_deep.asm:118-131):
--
--   0x18 / 0x19      rv=0, status 0x800D0203 (entry not found in the table)
--   0x1A-0x1D        status 0x800D0203 below 0x818, 0x800D0204 at 0x818
--   0x1E             rv=0, status 0, nothing else written
--   0x1F             rv=-1, nothing written
--   0x20             status 0x800D0219 at size 0x30, 0x800D0208 at any other size
--   0x2F             rv=0, status 0, nothing else written
--
-- Every one of those statuses is a sub-handler rejection, so the commands are
-- reachable and their validators are the next wall. This probe moves each of
-- them one step in:
--   [A] 0x1E and 0x2F with a non-zero input page - do they copy anything back
--       into the input page (an in/out struct) or into out+4?
--   [B] 0x20 at exactly 0x30 with its first three dwords swept - 0x800D0219 is
--       a different rejection than the size gate, so some field decides it.
--   [C] 0x18/0x19 with the first dword swept - 0x800D0203 is a table lookup, so
--       the handle/index field is what has to change.
--   [D] 0x1A-0x1D just below the 0x819 cap (0x800, 0x400) to separate the size
--       gate from 0x800D0204.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1352a_sys532_unpriv_commands_20261109_105538.txt
--   results/phase17_new_vectors/430a_sys532_copyout_20261022_234902.txt
--   results/phase17_new_vectors/433a_sys532_handle_map_20261022_235907.txt
--   results/kernel_handlers/analysis/sys_532_deep.md:35-48,255-292

print("=== PROBE 1353a: 532 LOW COMMANDS, SECOND STEP ===")

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
local function hx(v)
    if v == nil then return "nil" end
    if type(v) == "number" and v < 0 then return tostring(v) end
    return string.format("0x%08X", v % 0x100000000)
end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

local sc532 = make_syscall(532)
local sc477 = make_syscall(477)
local getpid = make_syscall(20)
print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function mmap(px)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local out = mmap(0x4000)
local inp = mmap(0x4000)
print(string.format("  out=0x%X in=0x%X", out, inp))
if out == 0 or inp == 0 then print("[!] mmap failed"); return end

local insnap = {}
local function fill_in(v)
    for i = 0, 0x3FF do safe_wd(inp + i * 4, v) end
    for i = 0, 0x1F do insnap[i] = v end
end
local function fill_out()
    for i = 0, 0xFF do safe_wd(out + i * 4, 0xDEADBEEF) end
end
local function call(cmd, size)
    local ok, ret = pcall(function()
        return sc532(uint64(cmd), uint64(0), uint64(out), uint64(inp), uint64(size), uint64(0))
    end)
    return ok and sgn(ret) or "PCALL-FAIL"
end
local function out_changed()
    local n = 0
    for i = 0, 0xFF do
        if safe_rd(out + i * 4) ~= 0xDEADBEEF then n = n + 1 end
    end
    return n
end
local function in_changed()
    local n = 0
    for i = 0, 0x1F do
        if safe_rd(inp + i * 4) ~= insnap[i] then n = n + 1 end
    end
    return n
end

print("")
print("[A] 0x1E / 0x2F with a 0x11223344 input page, size 0x30")
for _, cmd in ipairs({0x1E, 0x2F}) do
    fill_in(0x11223344)
    fill_out()
    local r = call(cmd, 0x30)
    print(string.format("  0x%02X %s outch=%d inch=%d  out[0..3]=%s %s %s %s  in[0..1]=%s %s",
        cmd, tostring(r), out_changed(), in_changed(),
        hx(safe_rd(out)), hx(safe_rd(out + 4)), hx(safe_rd(out + 8)), hx(safe_rd(out + 12)),
        hx(safe_rd(inp)), hx(safe_rd(inp + 4))))
end

print("")
print("[B] 0x20 at size 0x30, first dwords swept (looking past 0x800D0219)")
local bvals = {0, 1, 2, 0x10, 0x18, 0x30, 0x100, 0xFFFFFFFF}
for _, v0 in ipairs(bvals) do
    fill_in(0)
    safe_wd(inp + 0, v0)
    fill_out()
    local r = call(0x20, 0x30)
    print(string.format("  in[0]=%s %s st=%s", hx(v0), tostring(r), hx(safe_rd(out))))
end
for _, v1 in ipairs({1, 2, 0x10, 0x30}) do
    fill_in(0)
    safe_wd(inp + 4, v1)
    fill_out()
    local r = call(0x20, 0x30)
    print(string.format("  in[4]=%s %s st=%s", hx(v1), tostring(r), hx(safe_rd(out))))
end
for _, v2 in ipairs({1, 2, 0x10, 0x30}) do
    fill_in(0)
    safe_wd(inp + 8, v2)
    fill_out()
    local r = call(0x20, 0x30)
    print(string.format("  in[8]=%s %s st=%s", hx(v2), tostring(r), hx(safe_rd(out))))
end
fill_in(0)
safe_wd(inp + 0, 0x30)
safe_wd(inp + 4, 0x30)
safe_wd(inp + 8, 0x30)
fill_out()
print(string.format("  0x30/0x30/0x30 %s st=%s", tostring(call(0x20, 0x30)), hx(safe_rd(out))))

print("")
print("[C] 0x18 / 0x19 with in[0] swept (looking past 0x800D0203)")
for _, cmd in ipairs({0x18, 0x19}) do
    for _, v0 in ipairs({0, 1, 2, 0x100, 0x1000, 0xFFFFFFFF}) do
        fill_in(0)
        safe_wd(inp + 0, v0)
        fill_out()
        local r = call(cmd, 0x18)
        print(string.format("  0x%02X in[0]=%s %s st=%s ch=%d", cmd, hx(v0), tostring(r), hx(safe_rd(out)), out_changed()))
    end
end

print("")
print("[D] 0x1A-0x1D sizes 0x400 / 0x800 with a zero input page")
for _, cmd in ipairs({0x1A, 0x1B, 0x1C, 0x1D}) do
    for _, size in ipairs({0x400, 0x800}) do
        fill_in(0)
        fill_out()
        local r = call(cmd, size)
        print(string.format("  0x%02X s=0x%03X %s st=%s", cmd, size, tostring(r), hx(safe_rd(out))))
    end
end

print("")
print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1353a COMPLETE ===")
