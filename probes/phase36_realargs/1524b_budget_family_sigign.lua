-- CRASH_CLASS: LOW
-- PROBE 1524b: the budget family 569/570/571/609/610 under SIG_IGN
--
-- -- prior art:
--   probes/phase36_realargs/1524a_sys570_budget_get.lua
--     results/phase36_realargs/1524a_sys570_budget_get_20261110_101944.txt
--     -> 570(0, out, &count=1, 0, 0, 0) ENDED the process with no return line (198-byte
--        capture). Without SIGSYS ignored a kill is what a nosys slot does, so the 13.60 name
--        "budget_get" is not yet evidence that 570 has a handler on 14.10.
--   docs/sysent-names-13.60.csv -- 569 budget_delete rva 0x266348, 570 budget_get 0x266350,
--     571 budget_set 0x266358, 609 budget_getid 0x266368, 610 budget_get_ptype 0x266350?;
--     the four thunks at 0x8ac26348/0x8ac26350/0x8ac26358/0x8ac26368/0x8ac25e50 jump to
--     0x8af67300 / 0x8af67610 / 0x8af67900 / 0x8af67f00 / 0x8af67f60.
--   results/phase17_new_vectors/353a_sigign_reclassify.lua -- the SIG_IGN idiom:
--     a zeroed 0x80-byte struct with handler 1 at +0 and 0 at +8, then sigaction(416)(12, &sa, 0).
--     With it installed a nosys slot returns -1/ENOSYS instead of killing.
--   probes/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus.lua -- 569/570/571/609/610 were
--     in the skip list, so none of them has ever been measured.
--
-- Why: 570's body (0xffffffff8af67610) has an unclamped 24-byte record loop bounded only by the
-- caller count and [obj+0x34], with the stack canary at rbp-0x30 and record 14 landing on it.
-- Before designing anything around that, this probe decides whether the slot exists at all: a
-- kill with SIGSYS ignored is a fault, and a -1/ENOSYS is an absent slot.

print("=== PROBE 1524b: BUDGET FAMILY UNDER SIG_IGN ===")
print("")

local function N(v)
    if type(v) == "number" then return v end
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok and n then return n end
    end
    local ok, n = pcall(function() return tonumber(v) end)
    if ok and n then return n end
    return 0
end
local function addr_of(u)
    local n = N(u)
    if n >= 0x10000 and n < 0x8000000000 then return n end
    return nil
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) % 4294967296 end
    return nil
end
local function wd(a, v)
    return pcall(function() memory.write_dword(a, uint64(v)) end)
end
local function wq(a, v)
    return pcall(function() memory.write_qword(a, uint64(v)) end)
end
local function sid(v)
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return n
end
local function errs()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function self_pid()
    local ok, v = pcall(function() return getpid() end)
    if ok then return N(v) end
    return -1
end

local PID0 = self_pid()
print("pid=" .. tostring(PID0))

-- ============================================================
-- [A] SIG_IGN for SIGSYS
-- ============================================================
print("")
print("[A] sigaction(12, SIG_IGN)")
local sa = memory.alloc(0x80)
local saa = addr_of(sa)
if not saa then print("  FAIL: no struct"); return end
for i = 0, 0x80 - 8, 8 do wq(saa + i, 0) end
wq(saa, 1)
wq(saa + 8, 0)
local okA, rvA = pcall(function() return mk(416)(uint64(12), uint64(saa), uint64(0)) end)
print("  rv=" .. tostring(okA and N(rvA) or "EXC") .. "  handler readback=" .. string.format("%X", rd(saa) or 0))
if not okA or N(rvA) ~= 0 then
    print("  FAIL: SIG_IGN not installed; a nosys slot will kill the process")
end

-- ============================================================
-- [B] the family, zeros first
-- ============================================================
print("")
print("[B] each number with six zeros")
local fam = { 569, 570, 571, 609, 610 }
for _, n in ipairs(fam) do
    print("  [" .. n .. "] calling")
    local ok, rv = pcall(function() return mk(n)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then
        print("     pcall raised: " .. tostring(rv))
    else
        print("     rv=" .. tostring(N(rv)) .. " (0x" .. string.format("%X", sid(rv)) .. ") " .. errs())
    end
end

-- ============================================================
-- [C] the family with real pointers, the 1524a shape
-- ============================================================
print("")
print("[C] each number with (index 0, out, &count=1)")
local out = memory.alloc(0x400)
local outa = addr_of(out)
local cnt = memory.alloc(0x10)
local cnta = addr_of(cnt)
if not outa or not cnta then print("  FAIL: buffers"); return end
for _, n in ipairs(fam) do
    for off = 0, 0x400, 4 do wd(outa + off, 0xA5A5A5A5) end
    wd(cnta, 1)
    print("  [" .. n .. "] calling")
    local ok, rv = pcall(function()
        return mk(n)(uint64(0), uint64(outa), uint64(cnta), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print("     pcall raised: " .. tostring(rv))
    else
        local changed = 0
        for off = 0, 0x400 - 4, 4 do
            local v = rd(outa + off)
            if v and v ~= 0xA5A5A5A5 then changed = changed + 1 end
        end
        print("     rv=" .. tostring(N(rv)) .. " (0x" .. string.format("%X", sid(rv)) .. ") " .. errs() ..
              "  count_field=" .. tostring(rd(cnta)) .. "  changed_dwords=" .. changed)
        if changed > 0 then
            local line = "     first: "
            for off = 0, 20, 4 do line = line .. string.format("%08X ", rd(outa + off) or 0) end
            print(line)
        end
    end
end

print("")
print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
print("")
print("=== PROBE 1524b COMPLETE ===")
