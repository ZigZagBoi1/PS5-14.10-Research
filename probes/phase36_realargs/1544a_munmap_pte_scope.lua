-- CRASH_CLASS: MODERATE -- this probe reads only addresses it mapped itself, and the two loads that
-- could fault (the munmap'd page, and page 15 under the stale-PTE hypothesis) run inside a child Lua
-- thread, where an ordinary fault is contained (1331a spawned 512 faulting children and finished).
-- The main thread never dereferences an address it did not verify with 547 first, so the process
-- should survive even in the worst case.
-- PROBE 1544a: does munmap(73) of one 16 KiB page inside a sixteen-page entry SPLIT the entry, and
-- do the surviving pages keep live page-table translations?
--
-- Context. This kernel uses **16 KiB pages (0x4000)**. 1450a mapped 0x4000 - one page - and then
-- asked 547 about four addresses 0x1000 apart, which are all inside that single page, so its
-- conclusion that "munmap removes the whole entry" was never measured. Its record offset was also
-- wrong: the protection lives at record+0x10, not +0x18 (see the correction in
-- docs/VM_LAYER_14_10.md section 1, and 1537b's working helper).
--
-- What is actually known: 548 op 1 SPLITS a 0x40000 entry precisely, leaving BIG..BIG+0x20000 and
-- BIG+0x24000..BIG+0x40000 after removing the page at BIG+0x20000 (1537b). Whether syscall 73 does
-- the same has never been tested on a multi-page entry, because every probe that tried used a
-- four-address illusion of a one-page mapping.
--
-- Why the split itself is worth a probe: a replaced or removed page must have its PTEs torn down and
-- its object reference dropped. If the split leaves a survivor holding a live translation to a page
-- the object layer already released, that is a page-level use-after-free - and it is the first
-- kernel-memory-safety question this project has been able to ask about the VM layer.
--
-- The distinction cannot be made with 547 alone, and not with copyin/copyout either: both walk the
-- vm_map and answer EFAULT once the entry is gone, whether or not the PTE survived. Only an actual
-- load tests a translation, so the probe closes with two loads in a child thread.
--
-- Measurement channel: the child stamps a shared page, so the result does not depend on the child's
-- print surviving a fault or on socket ordering. Flags: +0x00 started, +0x08 value read from page 15,
-- +0x10 page-15 outcome, +0x18 value read from the munmapped page, +0x20 its outcome.
--
-- -- prior art:
--   results/phase36_realargs/1537b_sys548_op4_and_op0_semantics_20261110_151410.txt (548 op 1 splits)
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (the 4 KiB artifact, corrected)
--   results/1331a_20261110_101848.txt (child-thread fault containment, 512 spawns)
--   probes/phase36_realargs/1537b_sys548_op4_and_op0_semantics.lua:144-163 (the 547 record helper)
--   docs/VM_LAYER_14_10.md sections 1 and 15.1 (both corrections)

print("=== PROBE 1544a: munmap entry scope vs page-table scope ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sc477 = mk(477)
local sc73  = mk(73)
local sc547 = mk(547)
local PAGE, NPAGES, LEN = 0x4000, 16, 0x40000
local REC = memory.alloc(0x40)

-- 547 record: {start lo@0x00 hi@0x04, end lo@0x08 hi@0x0C, prot@0x10, flags@0x14}
local function rec(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(REC + i, 0xDEADBEEF) end) end
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(N(REC))) end)
    if not ok or N(rv) ~= 0 then return nil end
    local sl = N(memory.read_dword(REC + 0x00)) + N(memory.read_dword(REC + 0x04)) * 4294967296
    local el = N(memory.read_dword(REC + 0x08)) + N(memory.read_dword(REC + 0x0C)) * 4294967296
    return sl, el, N(memory.read_dword(REC + 0x10))
end
local function prot_at(addr) local s,e,p = rec(addr) return p end

print("")
print(string.format("[A] map 0x%X = sixteen 16 KiB pages; stamp page N with 0xA0000000+N", LEN))
local base = N(sc477(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("    477 -> 0x%X %s", base, (base == 0 or base > 550000000000) and es() or ""))
if base == 0 or base > 550000000000 then
    print("[!] mmap failed, aborting")
    print("=== PROBE 1544a ABORTED ===")
    do return end
end
for p = 0, NPAGES - 1 do
    pcall(function() memory.write_dword(base + p * PAGE, 0xA0000000 + p) end)
end
print(string.format("    base %% 0x4000 = 0x%X %s", base % 0x4000,
    (base % 0x4000 == 0) and "(page aligned)" or "*** NOT ALIGNED: munmap would round to a different page"))

print("")
print("[B] baseline. The span must be ONE 547 entry and every page must read back its sentinel.")
local bs, be, bp = rec(base)
print(string.format("    547 at base -> start=%s end=%s prot=%s",
    bs and string.format("0x%X", bs) or "none",
    be and string.format("0x%X", be) or "none",
    bp and string.format("0x%X", bp) or "none"))
local bad = 0
if bs == nil then bad = bad + 1
elseif bs ~= base or be ~= base + LEN then
    bad = bad + 1
    print(string.format("    *** the entry is 0x%X-0x%X, not the whole 0x%X span; SPLIT/WHOLE below cannot be read from pages 0 and 15 alone", bs, be, LEN))
end
if base % 0x4000 ~= 0 then bad = bad + 1 end
for p = 0, NPAGES - 1 do
    local a = base + p * PAGE
    local want = 0xA0000000 + p
    local ok, v = pcall(function() return N(memory.read_dword(a)) end)
    local note = ""
    if not ok then note = note .. " READ-FAULT" bad = bad + 1 end
    if ok and v ~= want then note = note .. string.format(" want 0x%08X", want) bad = bad + 1 end
    local rr = rec(a)
    if rr == nil then note = note .. " 547-NONE" bad = bad + 1 end
    print(string.format("    page %2d @0x%X %s%s", p, a, (ok and string.format("0x%08X", v)) or "fault", note))
end
print(string.format("    baseline problems: %d %s", bad, (bad == 0) and "(clean)" or "(anything below is unsound)"))

print("")
print("[C] unmap exactly ONE middle 16 KiB page: 73(base+0x10000, 0x4000)")
local r1 = N(sc73(uint64(base + 4 * PAGE), uint64(PAGE), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    73 -> %s %s", tostring(r1), (r1 == -1) and es() or ""))

print("")
print("[D] 547 after the call, for the page that was asked for and for its neighbours")
local q = {}
for _, p in ipairs({0, 1, 2, 3, 4, 5, 14, 15}) do
    local pr = prot_at(base + p * PAGE)
    q[p] = pr
    print(string.format("    page %2d @0x%X 547=%s", p, base + p * PAGE,
        (pr and string.format("0x%X", pr)) or "unmapped"))
end

print("")
print("[E] classification")
local p0, p15 = q[0], q[15]
if bad > 0 then
    print(string.format("    NO CLASSIFICATION: baseline had %d problems, so a mapped/unmapped answer", bad))
    print("    here cannot be attributed to the munmap. Re-run before interpreting [F].")
elseif r1 ~= 0 then
    print(string.format("    NO CLASSIFICATION: 73 answered %s, so it was not accepted", tostring(r1)))
elseif q[4] ~= nil then
    print("    73 LEFT THE REQUESTED PAGE MAPPED: nothing was removed, so there is no split to judge")
elseif p0 == nil and p15 == nil then
    print("    WHOLE ENTRY: pages 0 and 15 are both gone. 73 is entry-scoped after all, this time")
    print("    measured on a real sixteen-page entry rather than on one page queried four ways.")
elseif p0 ~= nil and p15 ~= nil then
    print("    SPLIT: pages 0 and 15 both survive while page 4 is gone. This is the same shape")
    print("    548 op 1 produced in 1537b, so 73 and 548 op 1 agree and the DEAD_ENDS note is wrong.")
else
    print(string.format("    MIXED: page0=%s page15=%s. Neither model predicts this; treat as a defect",
        (p0 and "mapped") or "unmapped", (p15 and "mapped") or "unmapped"))
end

print("")
print("[F] the translation question. Two loads, both in a child thread, results stamped into a page")
print("    so a fault cannot lose them. Page 15 is the interesting one: it is only a UAF candidate")
print("    when 547 says it is unmapped, so both facts are needed.")
local SH = memory.alloc(0x40)
for i = 0, 0x3C, 8 do pcall(function() memory.write_qword(SH + i, uint64(0)) end) end
local fd = 0
do local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end) if ok then fd = v end end
local TAIL, MID = base + 15 * PAGE, base + 4 * PAGE
local CHILD = string.format([[
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function put(o, v) memory.write_qword(%d + o, uint64(v)) end
put(0x00, 1)
local a = memory.read_dword(%d)
put(0x08, N(a)); put(0x10, 1)
local b = memory.read_dword(%d)
put(0x18, N(b)); put(0x20, 1)
print(string.format("CHILD done 0x%%08X 0x%%08X", N(a), N(b)))
]], N(SH), TAIL, MID)
local spok, spres = pcall(run_lua_code_in_new_thread, CHILD, { async = true, client_fd = fd })
print(string.format("    spawn ok=%s %s", tostring(spok), tostring(spres)))
local function sh(o) local ok, v = pcall(function() return N(memory.read_qword(SH + o)) end) if ok then return v end return -1 end
local waited = 0
while waited < 40000000 and sh(0x10) == 0 do waited = waited + 1 end
local started = sh(0x00)
local ok15, v15, okMid, vMid = sh(0x10), sh(0x08), sh(0x20), sh(0x18)
print(string.format("    child started=%d  waited=%d", started, waited))
print(string.format("    page 15 load: %s   value=%s", (ok15 == 1) and "SUCCEEDED" or "no stamp (faulted or never reached)",
    (ok15 == 1) and string.format("0x%08X", v15) or "-"))
print(string.format("    page  4 load: %s   value=%s", (okMid == 1) and "SUCCEEDED" or "no stamp (faulted or never reached)",
    (okMid == 1) and string.format("0x%08X", vMid) or "-"))

print("")
print("[G] verdict")
if started == 0 then
    print("    the child never ran, so [F] measured nothing. Any absence of CHILD15 above is")
    print("    explained by that and must not be read as a fault.")
elseif ok15 == 0 then
    print("    page 15's load produced no stamp: the child faulted there. Whatever 547 said, the")
    print("    translation did not survive, so no stale-PTE condition exists on this mapping.")
elseif p15 ~= nil then
    print("    page 15 was still mapped per 547, so its load succeeding is EXPECTED and is not a")
    print("    UAF. This is the clean-split case: content and translations both survive.")
    if v15 ~= 0xA0000000 + 15 then
        print(string.format("    BUT the value is 0x%08X, not the 0x%08X sentinel - the survivors lost", v15, 0xA0000000 + 15))
        print("    their content across the split. That IS a defect and needs its own probe.")
    else
        print("    the sentinel survived too, so the split preserved content and mapping alike.")
    end
else
    print(string.format("    *** STALE PTE: 547 says page 15 is unmapped, yet the load landed and read 0x%08X.", v15))
    print("        The entry is gone from the VM map while the translation still points at memory")
    print("        the object layer has released: a page-level use-after-free, and the first real")
    print("        kernel-memory-safety condition this project has produced.")
end

print("")
print(string.format("=== PROBE 1544a COMPLETE pid=%s ===", tostring(PID)))
