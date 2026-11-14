-- CRASH_CLASS: MODERATE -- the decisive sections ([A] through [F]) are 547 queries only, and [F]
-- prints the verdict before the frame is dereferenced. Reads happen in two places, both gated on a
-- 547 record that covers the address: [B] re-derives the frame slide, and [G] reads the frame only
-- after [F] has printed its verdict. A 547 protection is NOT a backing test -- 1397g reads page
-- 0x17000 and faults inside a mapping that spans it -- so either place may die, and a death there
-- costs one loader relaunch and nothing else.
-- PROBE 1547a: does the vm_map entry round a sub-page device mmap up to the 16 KiB page?
--
-- THE ONE QUESTION, and why it decides everything else.
--   The kernel page size is 0x4000 (1544a: one 0x40000 mmap is one 547 record
--   0x310AB0000-0x310AF0000 and sixteen addresses at 0x4000 stride each read a distinct sentinel).
--   The /dev/dmem0 offset, by contrast, is honoured at 4 KiB: 1478a maps offset 0x1000, 1397e
--   cross-reads prove the frame slides with the offset rather than quantising to 0x4000.
--   The vm_map ENTRY rounds up: `mmap(off, len = 0x1000)` gives a 0x4000 entry. That is already
--   measured, not assumed -- 1441a mapped offset 0x01000000000 with len 0x1000 at Va 0x311db8000
--   and its 547 answered w0=0x11DB8000 w8=0x11DBC000, a span of 0x4000 for a 0x1000 request:
--     results/phase36_realargs/1441a_mprotect_device_window_20261109_165212.txt lines 16 and 19.
--   So a page-sized request already covers 0x3000 bytes past its own end. [A] re-measures it inside
--   this run so the conclusion does not depend on another capture's arithmetic, but the interesting
--   quantity is what the ACL does with it:
--   547 answers this directly and without dereferencing anything: it returns the entry's own
--   start and end. Compare (end - start) against the 0x1000 that was requested.
--
--   The ACL, separately, refuses some offset outright with EACCES(13), and it already accounts for
--   the length: 1411a [D] refuses `off=0 len=0x140000000` although offset 0 maps on its own, and
--   [E] refuses `off=0x100000000 len=0x40000000` although that offset maps alone. (1411a [E]'s third
--   rung, `off=0x13F000000 len=0x2000000`, is explained by the offset alone -- 0x13F000000 is past
--   the 0x120000000 ladder boundary -- so do not cite it as length evidence.) The untested
--   combination is a request whose offset+length stops EXACTLY
--   at that boundary: it respects the guard as stated, but its rounded entry covers 0x3000 bytes
--   past it. Bisect the boundary, then map one page-sized request ending exactly there and ask 547
--   whether the entry extends over device address space the ACL refuses to map directly. That
--   mapping would be prot 3 and therefore writable.
--
-- Prior art:
--   results/phase36_realargs/1544a_munmap_pte_scope_20261110_162901.txt (page size 0x4000, measured)
--   results/phase36_realargs/1397e_dmem_page0_liveness_20261109_142921.txt (frame slides with the offset)
--   results/phase36_realargs/1478a_dev_mmap_wrap_ftruncate_20261109_192453.txt (raw-offset ACL, EACCES)
--   results/phase36_realargs/1411a_dmem_range_check_20261109_153133.txt ([D]/[E] a length is summed into the check)
--   results/phase36_realargs/1410a_dmem_offset_space_20261109_153054.txt (ladder; zeros above offset 0)
--   results/phase36_realargs/1513a_sys548_op3_vnode_clip_20261109_230353.txt (a 0x4000 request gives a 0x4000 entry)
--   results/phase36_realargs/1441a_mprotect_device_window_20261109_165212.txt (a 0x1000 request gives a 0x4000 entry)
--   results/phase36_realargs/1463a_dev_mmap_census_20261109_175504.txt (which nodes map at all)
--   docs/DMEM_WINDOW_14_10.md, docs/VM_LAYER_14_10.md section 1
--
-- What this is unlikely to yield, stated up front: 1410a read the first three dwords at every mapped
-- offset above zero up to 4 GiB and every one was 0x00000000; only offset 0 holds GPU registers
-- (C0012800). So bytes past the limit are probably zeros. The finding to chase is the MAPPING -- a
-- writable frame over device address space the ACL refuses -- not the content.

print("=== PROBE 1547a: does a sub-page device mmap round up to the 16 KiB page? ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc_open, sc_close = mk(5), mk(6)
local sc_mmap, sc_munmap = mk(477), mk(73)
local sc_547 = mk(547)
local O_RDWR, PROT_RW, MAP_SHARED = 2, 3, 1
local PAGE = 0x4000

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return N(b)
end

-- 547's record is {start_lo, start_hi, end_lo, end_hi, prot, flags} (1362a, corrected in
-- docs/ARG23_CLASSES_14_10.md:74). The old +0x04 reading was the high dword of the start address.
local REC = memory.alloc(0x40)
local function rec(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(REC + i, 0xDEADBEEF) end) end
    local ok, rv = pcall(function() return N(sc_547(uint64(addr), uint64(N(REC)), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    if not ok or rv ~= 0 then return nil end
    local sl = N(memory.read_dword(REC + 0x00)) + N(memory.read_dword(REC + 0x04)) * 4294967296
    local el = N(memory.read_dword(REC + 0x08)) + N(memory.read_dword(REC + 0x0C)) * 4294967296
    return sl, el, N(memory.read_dword(REC + 0x10)), N(memory.read_dword(REC + 0x14))
end
local function covered(addr)
    local sl, el, pr = rec(addr)
    if sl == nil then return nil end
    if addr >= sl and addr < el and pr ~= 0 then return pr end
    return nil
end

local fd = -1
do
    local p = str_addr("/dev/dmem0")
    local ok, v = pcall(function() return N(sc_open(uint64(p), uint64(O_RDWR), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    if ok then fd = v end
end
print(string.format("[0] /dev/dmem0 fd=%d", fd))
if fd <= 0 then print("[!] no descriptor; aborting"); print("=== PROBE 1547a ABORTED ===") return end

local function try_map(off, len)
    local ok, v = pcall(function()
        return N(sc_mmap(uint64(0), uint64(len), uint64(PROT_RW), uint64(MAP_SHARED), uint64(fd), uint64(off)))
    end)
    if not ok then return -2 end
    return v
end
local function release(addr, len)
    if addr and addr > 0x1000 and addr < 549755813888 then
        pcall(function() return sc_munmap(uint64(addr), uint64(len), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end
local function rd(va) local ok, v = pcall(function() return N(memory.read_dword(va)) end) if ok then return v end return nil end

-- `bail` must be declared after `release` and `rd`, or its body captures globals that do not exist.
bailA, bailALen = nil, 0
local function bail(tag)
    release(bailA, bailALen)
    pcall(function() return sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print(string.format("=== PROBE 1547a COMPLETE (%s) pid=%s ===", tag, tostring(PID)))
end

-- [A] THE DECISIVE TEST. mmap exactly one page (0x1000) at a device offset that is known to map
-- (1410a: offset 0x1000 maps) and ask 547 what entry exists at that address. No dereference.
print("")
print("--- [A] does a len=0x1000 request produce a 0x1000 entry or a 0x4000 one? ---")
local S0 = try_map(0x1000, 0x1000)
print(string.format("[A] map(off=0x1000, len=0x1000) -> %s",
    (S0 > 0) and string.format("va=0x%X", S0) or string.format("rv=%d %s", S0, es())))
if S0 <= 0 then
    print("[!] the one-page request did not map; the question cannot be asked")
    bail("no map")
    return
end
bailA, bailALen = S0, 0x4000
local sl, el, pr, fl = rec(S0)
if sl == nil then
    print("[A] 547 failed at the mapped address; the entry cannot be read")
    bail("no record")
    return
end
local entry_len = el - sl
print(string.format("[A] 547 at 0x%X: start=0x%X end=0x%X len=0x%X prot=0x%X flags=0x%X",
    S0, sl, el, entry_len, pr, fl))
print(string.format("[A] requested 0x1000; the entry is 0x%X bytes", entry_len))

-- The entry must START at or below the request and END past the requested end. Testing the length
-- alone would credit an entry that begins below S0 and happens to be 0x4000 long.
local rounded = nil
if entry_len >= PAGE and sl <= S0 and el > S0 + 0x1000 then
    rounded = true
elseif entry_len == 0x1000 then
    rounded = false
end

-- Corroborate with further 547 queries, which are also read-free. If the entry rounds up, a query
-- one page in reports the SAME entry; if it does not, that address is either a different entry or
-- unmapped.
print("")
print("--- [A2] what 547 says at the addresses past the requested length ---")
local past = {}
for _, d in ipairs({0x0, 0x1000, 0x2000, 0x3000}) do
    local r2s, r2e, r2p = rec(S0 + d)
    past[d] = (r2s ~= nil and r2s == sl)
    print(string.format("[A2] va=0x%X (dev off 0x%X): %s",
        S0 + d, 0x1000 + d,
        (r2s == nil) and "547 refused -> outside any entry"
        or string.format("entry 0x%X..0x%X prot=0x%X%s", r2s, r2e, r2p or 0,
            (r2s == sl) and "  (same entry as the map)" or "  (a DIFFERENT entry)")))
end

if rounded == nil then
    print(string.format("[A] entry length 0x%X is neither 0x1000 nor >= 0x4000: report the number, claim nothing", entry_len))
elseif rounded then
    print("")
    print("    ROUNDED: a 0x1000 request produced an entry of at least 0x4000. The mapping therefore")
    print("    covers address space past the end of what was asked for, which is the precondition")
    print("    for straddling an ACL boundary with a request that respects it.")
else
    print("")
    print("    NOT ROUNDED: the entry is exactly the requested 0x1000. A page-sized device request")
    print("    cannot reach past its own end, so no straddle exists at any offset and the aperture")
    print("    limit cannot be crossed this way. [B]-[F] are skipped.")
    print(string.format("[A] but note what [A2] measured at 0x%X: %s", S0 + 0x1000,
        past[0x1000] and "the same entry, which contradicts the length" or "not this entry"))
    bail("entry not rounded")
    return
end

-- [B] with the entry rounded, is the device frame also byte-addressed? Re-derive it in this run
-- rather than leaning on 1397e. Anchor on device offset 0, which reads GPU registers.
print("")
print("--- [B] does the frame slide with the offset, or quantise to 0x4000? ---")
local A0 = try_map(0x0, 0x1000)
local A1 = try_map(0x1000, 0x1000)
local A2 = try_map(0x2000, 0x1000)
print(string.format("[B] map(off=0x0000,len=0x1000) -> %s", (A0 > 0) and string.format("0x%X", A0) or string.format("rv=%d %s", A0, es())))
print(string.format("[B] map(off=0x1000,len=0x1000) -> %s", (A1 > 0) and string.format("0x%X", A1) or string.format("rv=%d %s", A1, es())))
print(string.format("[B] map(off=0x2000,len=0x1000) -> %s", (A2 > 0) and string.format("0x%X", A2) or string.format("rv=%d %s", A2, es())))
if A0 > 0 and A1 > 0 and A2 > 0 then
    -- every read below is gated on the entry covering the address
    local function g(va)
        if not covered(va) then return nil, "no covering entry" end
        return rd(va)
    end
    local a00, e00 = g(A0)
    local a01, e01 = g(A0 + 0x1000)
    local a02, e02 = g(A0 + 0x2000)
    local a10 = g(A1)
    local a20 = g(A2)
    local function show(tag, v, why)
        print(string.format("[B] %-22s = %s", tag, v and ("0x" .. hex(v)) or ("skipped: " .. tostring(why))))
    end
    show("A0+0x0000 (dev 0)", a00, e00)
    show("A0+0x1000 (dev 1k)", a01, e01)
    show("A0+0x2000 (dev 2k)", a02, e02)
    show("A1+0x0000 (dev 1k)", a10)
    show("A2+0x0000 (dev 2k)", a20)
    if a00 == nil or a10 == nil or a20 == nil then
        print("    a read was skipped or failed, so the model is not re-derived here")
    elseif a00 == 0 then
        print("    device offset 0 read as zero, which contradicts 1410a; the anchor is unusable and")
        print("    the slide question stays open. [D] below is still meaningful on its own.")
    elseif a10 == a00 and a20 == a00 then
        print("    QUANTISED: every offset maps the same frame, so a frame never crosses a 0x4000")
        print("    boundary and no straddle is constructible even with a rounded entry. Stop here.")
        release(A0, PAGE); release(A1, PAGE); release(A2, PAGE)
        bail("frame quantised")
        return
    elseif a01 ~= nil and a02 ~= nil and a10 == a01 and a20 == a02 then
        print("    SLIDE: the 0x1000 map reaches device offset 0x1000 at +0, matching what the")
        print("    offset-0 frame shows at +0x1000. Frames are byte-addressed and 0x4000 long.")
    else
        print(string.format("    NEITHER model fits (A1+0=%s vs A0+1k=%s, A2+0=%s vs A0+2k=%s).",
            a10 and ("0x" .. hex(a10)) or "na", a01 and ("0x" .. hex(a01)) or "na",
            a20 and ("0x" .. hex(a20)) or "na", a02 and ("0x" .. hex(a02)) or "na"))
        print("    The device is not simply byte-addressed; treat [E] as unattributed and say so.")
    end
end
-- Released outside the branch: a partial success must not leave frames live for the rest of the run.
if A0 > 0 then release(A0, PAGE) end
if A1 > 0 then release(A1, PAGE) end
if A2 > 0 then release(A2, PAGE) end
release(S0, PAGE)
bailA, bailALen = nil, 0

-- [C] coarse ladder, so a non-monotonic window is visible rather than assumed away
print("")
print("--- [C] coarse ladder over the aperture (each rung maps then releases) ---")
local LADDER = {
    0x0, 0x4000, 0x100000, 0x10000000, 0x20000000, 0x40000000, 0x60000000,
    0x80000000, 0xA0000000, 0xC0000000, 0xE0000000, 0x100000000,
    0x120000000, 0x140000000, 0x180000000, 0x1C0000000, 0x200000000, 0x400000000,
}
local verdict, any_ok = {}, false
for _, off in ipairs(LADDER) do
    local a = try_map(off, 0x1000)
    local ok = (a > 0)
    verdict[#verdict + 1] = { off = off, ok = ok }
    if ok then any_ok = true end
    print(string.format("[C] off=0x%09X len=0x1000 -> %s", off,
        ok and string.format("va=0x%X", a) or string.format("rv=%d %s", a, es())))
    if ok then release(a, PAGE) end
end
if not any_ok then
    print("[!] nothing in the ladder mapped; aborting")
    bail("no ladder")
    return
end
local transitions = 0
for i = 1, #verdict - 1 do
    if verdict[i].ok and not verdict[i + 1].ok then transitions = transitions + 1 end
end
-- The TOPMOST accepted -> refused transition is the aperture edge. Selecting the widest gap instead
-- would pick an interior hole whenever the window is non-monotonic (1410a mapped a lone rung at
-- 0x1000000000 above a refused region), and then every read in [F] would be inside the window.
local last_ok, first_bad = nil, nil
for i = 1, #verdict - 1 do
    local v, w = verdict[i], verdict[i + 1]
    if v.ok and not w.ok and (last_ok == nil or v.off > last_ok) then
        last_ok, first_bad = v.off, w.off
    end
end
print(string.format("[C] accepted -> refused transitions: %d%s", transitions,
    (transitions == 1) and " (monotonic over the sampled offsets)" or " (NON-MONOTONIC)"))
if last_ok ~= nil then
    for i = 1, #verdict do
        if verdict[i].ok and verdict[i].off > last_ok then
            print(string.format("[C] WARNING: off=0x%X maps although it lies above the chosen boundary", verdict[i].off))
            print("    The window is NOT monotonic, so the boundary below may be an interior hole rather")
            print("    than the aperture edge. If so, a read past it is still inside the window.")
            break
        end
    end
end
if last_ok == nil then
    print("[!] no accepted rung is followed by a refused one; no boundary to measure")
    bail("no bracket")
    return
end

-- [D] bisect
print("")
print(string.format("--- [D] bisect 0x%X (accepted) .. 0x%X (refused) at 0x%X steps ---", last_ok, first_bad, PAGE))
local lo, hi, steps = last_ok, first_bad, 0
while hi - lo > PAGE and steps < 40 do
    steps = steps + 1
    local mid = lo + math.floor((hi - lo) / (2 * PAGE)) * PAGE
    if mid <= lo then mid = lo + PAGE end
    local a = try_map(mid, 0x1000)
    if a > 0 then
        lo = mid
        release(a, PAGE)
        print(string.format("[D] %2d off=0x%09X accepted", steps, mid))
    else
        hi = mid
        print(string.format("[D] %2d off=0x%09X refused (%d)", steps, mid, a))
    end
end
local LIMIT = hi
print(string.format("[D] LIMIT = 0x%X  (multiple of 0x%X: %s)", LIMIT, PAGE,
    (LIMIT % PAGE == 0) and "yes" or "NO -- a straddling frame is not constructible"))
if LIMIT % PAGE ~= 0 then
    print("    The refusal lands mid-frame, so the accepted frame below it cannot cross.")
    bail("limit not frame aligned")
    return
end
-- The bisection always ends with lo accepted and hi refused, so LIMIT is bracketed by construction.
-- What can go wrong is the opposite: LIMIT may sit at the LAST ladder transition with nothing sampled
-- above it, in which case the true boundary could be beyond the sampled range.
if LIMIT >= 0x400000000 then
    print(string.format("    LIMIT is the top ladder rung (0x%X): nothing above it was sampled, so the", LIMIT))
    print("    true boundary may lie further out. [E] still measures this offset exactly.")
end

-- [E0] the control that makes [E] readable. A 16 KiB request that also ends exactly at the limit
-- rounds to itself, so it tests whether the guard is "off + len <= LIMIT" at all. Three outcomes
-- then separate cleanly:
--   [E0] accepted and [E] refused  -> the guard rounds the length up to the page
--   [E0] accepted and [E] accepted -> the guard uses the requested length: straddle
--   [E0] refused                   -> the guard covers the end even at a page-aligned length
print("")
print("--- [E0] control: map(off = LIMIT - 0x4000, len = 0x4000), also ending exactly at the limit ---")
local E0 = try_map(LIMIT - 0x4000, PAGE)
print(string.format("[E0] map(off=0x%X, len=0x4000) -> %s   (off+len=0x%X)",
    LIMIT - 0x4000, (E0 > 0) and string.format("va=0x%X", E0) or string.format("rv=%d %s", E0, es()), LIMIT))
if E0 > 0 then
    local e0s, e0e = rec(E0)
    print(string.format("[E0] 547: %s", e0s and string.format("start=0x%X end=0x%X", e0s, e0e) or "none"))
    release(E0, PAGE)
end

-- [E] the straddling request: one page, ending exactly at the limit
print("")
print("--- [E] map(off = LIMIT - 0x1000, len = 0x1000): ends exactly at the limit ---")
local S = try_map(LIMIT - 0x1000, 0x1000)
print(string.format("[E] map(off=0x%X, len=0x1000) -> %s   (off+len=0x%X, LIMIT=0x%X)",
    LIMIT - 0x1000, (S > 0) and string.format("va=0x%X", S) or string.format("rv=%d %s", S, es()),
    LIMIT, LIMIT))
if S <= 0 then
    print("    refused. Nothing is read.")
    if E0 > 0 then
        print("    [E0] was ACCEPTED at the same ending, so the only difference is the length: the")
        print("    guard rounds the requested 0x1000 up to 0x4000 before comparing, which is why a")
        print("    request that ends exactly at the limit is refused once its frame is counted.")
        print("    The ACL and the rounded entry agree. There is no straddle.")
    else
        print("    [E0] was refused too, so LIMIT is above the true boundary by less than 0x4000 and")
        print("    the frame-aligned candidate missed it. Nothing here is attributed to a guard:")
        print("    whether a straddle exists at the true boundary is NOT measured by this run.")
    end
    print("=== PROBE 1547a COMPLETE (no straddle) pid=" .. tostring(PID) .. " ===")
    return
end
bailA, bailALen = S, PAGE
local ss, se, sp = rec(S)
print(string.format("[E] 547 at the map: start=%s end=%s len=%s prot=%s",
    ss and string.format("0x%X", ss) or "none", se and string.format("0x%X", se) or "none",
    (ss and se) and string.format("0x%X", se - ss) or "none", sp and string.format("0x%X", sp) or "none"))

local offs = { 0x0, 0x1000, 0x2000, 0x3000 }
local prot_at = {}
for _, d in ipairs(offs) do
    local va = S + d
    local rs, re_, rp = rec(va)
    -- A protection at `va` only counts if the covering entry is the crossing map's own. Otherwise a
    -- neighbouring heap or device mapping would be credited to the frame.
    local mine = (rs ~= nil and ss ~= nil and rs == ss and va >= rs and va < re_)
    prot_at[d] = mine and rp or nil
    print(string.format("[E] frame+0x%X is dev off 0x%X: %s", d, LIMIT - 0x1000 + d,
        (rs == nil) and "547 refused"
        or string.format("entry 0x%X..0x%X prot=0x%X%s", rs, re_, rp or 0,
            mine and "" or "  <<< NOT this mapping")))
end

-- [E1] THE DISCRIMINATOR. [E] alone cannot tell "the entry crosses the ACL's size" from "the entry
-- lies inside the ACL's size but a 0x1000 request ending at LIMIT is refused because the guard rounds
-- the length". The same start with a 16 KiB length ends at LIMIT+0x3000, so:
--   accepted -> the ACL really does reach past LIMIT, the straddle frame is entirely inside it, and
--               the only thing the rounding bought is that a direct 0x1000 request was refused.
--   refused  -> the ACL's size stops below the frame end, so [E]'s entry does cross it.
print("")
print("--- [E1] control: map(off = LIMIT - 0x1000, len = 0x4000), ends at LIMIT + 0x3000 ---")
local EF = try_map(LIMIT - 0x1000, PAGE)
print(string.format("[E1] map(off=0x%X, len=0x4000) -> %s   (off+len=0x%X)",
    LIMIT - 0x1000, (EF > 0) and string.format("va=0x%X", EF) or string.format("rv=%d %s", EF, es()),
    LIMIT + 0x3000))
if EF > 0 then
    local e1s, e1e = rec(EF)
    print(string.format("[E1] 547: %s", e1s and string.format("start=0x%X end=0x%X", e1s, e1e) or "none"))
    release(EF, PAGE)
end

-- [F] verdict, printed before any read, so a fault cannot lose it
print("")
print("--- [F] verdict, computed from 547 alone, before anything is dereferenced ---")
local beyond = 0
for _, d in ipairs({0x1000, 0x2000, 0x3000}) do
    if prot_at[d] and prot_at[d] ~= 0 then beyond = beyond + 1 end
end
local inwin = prot_at[0x0] and prot_at[0x0] ~= 0
if not inwin then
    print("    the frame's own first sub-block, which is INSIDE the limit, does not report a")
    print("    protection under this mapping, so nothing below is attributable to it.")
elseif beyond == 3 then
    print(string.format("    THE ENTRY CROSSES LIMIT: one mmap(off=0x%X, len=0x1000) produced an entry", LIMIT - 0x1000))
    print(string.format("    reported as 0x%X..0x%X, and 547 places device offsets 0x%X..0x%X", ss or 0, se or 0,
        LIMIT, LIMIT + 0x2FFF))
    print("    inside it, while a direct mmap at 0x" .. string.format("%X", LIMIT) .. " is refused.")
    if EF > 0 then
        print("    BUT [E1] mapped that whole frame directly with len=0x4000, so the ACL's own size")
        print("    reaches past LIMIT: the straddle frame lies ENTIRELY INSIDE what the ACL permits.")
        print("    This is NOT an ACL bypass. What the rounding bought is only that a direct 0x1000")
        print("    request ending at LIMIT is refused while the same frame's tail is reachable.")
    else
        print("    AND [E1] was refused, so the ACL's size stops below the frame end: the entry")
        print("    crosses device address space the ACL refuses to map directly, at prot")
        print(string.format("    0x%X. That is a writable mapping past the limit. Read [G] for content.", sp or 0))
    end
elseif beyond == 0 then
    print("    NO STRADDLE: the entry ends at the limit even though the request was one aligned page")
    print("    that ended exactly there. The ACL and the entry agree; nothing extends past it.")
else
    print(string.format("    PARTIAL: only %d of the three offsets past the limit report a protection", beyond))
    print("    under this mapping. Report the table above rather than a conclusion.")
end

-- [G] the reads, last, each pre-printed, each gated on its own covering entry
print("")
print("--- [G] the four sub-blocks (read only, no writes) ---")
local got = {}
for _, d in ipairs(offs) do
    local va = S + d
    local p = prot_at[d]
    if p and p ~= 0 and covered(va) then
        print(string.format("[G] reading dev off 0x%09X (va 0x%X, prot 0x%X) ...", LIMIT - 0x1000 + d, va, p))
        local v = rd(va)
        got[d] = v
        print(string.format("[G] dev off 0x%09X  first dword = %s", LIMIT - 0x1000 + d,
            v and ("0x" .. hex(v)) or "READ FAILED"))
    else
        print(string.format("[G] dev off 0x%09X  no covering entry, skipped", LIMIT - 0x1000 + d))
    end
end
if got[0x0] ~= nil then
    print(string.format("[G] control: the in-window sub-block read 0x%X", got[0x0]))
    for _, d in ipairs({0x1000, 0x2000, 0x3000}) do
        if got[d] ~= nil and got[d] ~= got[0x0] then
            print(string.format("[G] out-of-window +0x%X differs (0x%X): the pager served a distinct", d, got[d]))
            print("    page rather than repeating the in-window one.")
        end
    end
end
print("    A nonzero dword past the limit is data the ACL refuses to map directly but that this frame")
print("    exposes. All zeros is inconclusive for content; the mapping is still the finding.")

-- teardown
print("")
print("--- [H] teardown ---")
release(S, PAGE)
pcall(function() return sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print("[H] frame released, descriptor closed")
print(string.format("=== PROBE 1547a COMPLETE pid=%s ===", tostring(PID)))
