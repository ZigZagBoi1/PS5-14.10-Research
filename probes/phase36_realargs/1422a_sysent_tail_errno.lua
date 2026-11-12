-- CRASH_CLASS: MODERATE
-- PROBE 1422a: is the 14.10 sysent really empty above 676, or just refusing?
--
-- prior art:
--   results/phase17_new_vectors/275b_sysent_tail_guarded_20261022_223712.txt
--     with SIGSYS ignored, 676 and 677 and 687/689/690/705-734 ALL returned -1 and
--     the probe printed "*** 705 RETURNED - SYSENT EXTENDS PAST 676! ***". That banner
--     is wrong on its own evidence: 353a/353b established that an absent slot answers
--     -1 once SIGSYS is ignored, so -1 proves nothing. 275b never printed errno.
--   docs/SYSENT_PRESENCE_14_10.md:413 and the docs/DEAD_ENDS.md bullet say 677..707
--     "each killed the process", measured WITHOUT SIG_IGN - that is SIGSYS from nosys.
--   docs/sysent-names-13.60.csv says 677-735 are REAL handlers on 13.60: 677 wait6,
--     687 pipe2, 689 procctl, 690 ppoll, 705 get_phys_page_size, 715 ioreq,
--     717 dl_get_info_2, 724 dynlib_get_lid_mid_info, 725 mmap2,
--     728 virtual_query_by_pid, 732 cffmgr_call, 733 get_resident_fmem_count2.
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101208.txt
--     used errno ENOSYS(78) as the discriminator that identified 568/569/574-584/589/
--     590/597/610/619/620 as nosys. That test has never been applied above 676.
--
-- Question: for N in 677..735, does N answer ENOSYS(78) (slot absent, a trampoline),
-- or any other errno / a return value (a real handler, i.e. ~59 unexplored syscalls)?
--
-- Shape: every argument is the SAME mapped zero page, so a real handler that
-- dereferences any of its six arguments finds legal memory and cannot fault merely
-- because of the arguments. SIGSYS is ignored first, so an absent slot answers -1
-- instead of terminating, and a kill here is therefore evidence of a HANDLER, not of
-- absence. Controls first: 568 (known nosys), 596 and 557 (known real).
--
-- A kill is a result about the call. The line printed before each call names it.

print("=== PROBE 1422a: SYSENT TAIL ERRNO (677-735) ===")

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
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function safe_wd(a, v) local ok = pcall(function() memory.write_dword(a, v) end) return ok end
local function safe_rq(a) local ok, v = pcall(function() return memory.read_qword(a) end) if ok then return to_num(v) end return -1 end
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

-- ---- SIGSYS ignored, for 13.60's nosys trampoline (signal 12) ----
local sc416 = make_syscall(416)
local sa = memory.alloc(0x80)
for i = 0, 0x7F, 8 do safe_wd(sa + i, 0) end
pcall(function() memory.write_qword(sa, uint64(1)) end)   -- SIG_IGN
local ok12 = pcall(function() sc416(uint64(12), uint64(sa), uint64(0)) end)
print(string.format("[A] sigaction(12, SIG_IGN) ok=%s handler_readback=%s",
    tostring(ok12), tostring(safe_rq(sa))))

local sc477 = make_syscall(477)
local function mmap(px, prot)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(prot or 3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a > 0x10000 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
        return a
    end
    return 0
end
local page = mmap(0x20000)
print(string.format("[B] page=0x%X", page))
if page == 0 then print("[!] mmap failed"); return end

local function probe(n)
    local mk = make_syscall(n)
    local rv
    local ok = pcall(function()
        rv = mk(uint64(page), uint64(page), uint64(page), uint64(page), uint64(page), uint64(page))
    end)
    if not ok then
        print(string.format("  %4d  EXC (lua error)", n))
        return
    end
    local e = es()
    local verdict = "REAL?"
    if string.find(string.lower(e), "not implemented") then verdict = "nosys" end
    print(string.format("  %4d  rv=%-20s errno=%-28s %s", n, sgn(rv), e, verdict))
end

print("")
print("[C] controls")
io.write("  calling 568 (known nosys) ... "); io.flush(); probe(568)
io.write("  calling 596 (known real, returns 0) ... "); io.flush(); probe(596)
io.write("  calling 557 (known real, returns a handle) ... "); io.flush(); probe(557)

print("")
print("[D] 676..735")
for n = 676, 735 do
    io.write("  calling " .. n .. " ... "); io.flush()
    probe(n)
end

print("")
print("[E] out-of-range numbers")
for _, n in ipairs({ 0x1000, 0x8000, 0x10000, 0x40000000, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF }) do
    io.write("  calling " .. n .. " ... "); io.flush()
    probe(n)
end

print("")
print("=== PROBE 1422a COMPLETE ===")
