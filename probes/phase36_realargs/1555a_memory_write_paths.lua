-- CRASH_CLASS: LOW
-- PROBE 1555a: does memory.write_dword land on a GPU-mapped page, and does a
--              qword store land where a dword store did not?
--
-- Context: 1554a printed "H reads 0x11223344556677 now" *before* any child ran,
-- even though zero(Hv, 0x4000) had just written 0 through every dword of that
-- page. The page was fresh (477 anon, mtype 0x1002), so it should have read 0.
-- Two candidate explanations, and this probe separates them:
--   (a) memory.write_dword is a silent no-op (or writes elsewhere) on these
--       pages, while memory.write_qword works -- docs/DEAD_ENDS.md already notes
--       "the write path swallows faults, so a store to an unmapped address also
--       reports success" (probe 381a).
--   (b) the page was not fresh: the pool handed back a page from a previous
--       process that held the marker.
-- (a) matters far more: every probe in this tree zeroes buffers with write_dword.
--
-- prior art:
--   docs/DEAD_ENDS.md -- "the write path swallows faults, so a store to an
--     unmapped address also reports success (381a)".
--   probes/phase36_realargs/1557a_unmap_pte_removal.lua -- its arm check used
--     write_qword and read back 0 correctly, so qword stores are known to land.
--   results/phase36_realargs/1554a_unmap_vs_first_touch_fault_20261110_193300.txt
--     -- the run that raised this question (it then died on an unrelated
--     undefined-global bug before [B] reached the unmap).
--
-- Method: no child, no 548 call, no unmapped access. One page.
--   [A] write_qword(MARK); read back. Establishes the page accepts stores at all.
--   [B] zero every dword of the page with write_dword; read back. If it still
--       reads MARK, write_dword never landed.
--   [C] write_dword at +0x10 only, with a qword-visible sentinel pattern around
--       it: 16 bytes of 0xAA written as qwords, then one dword at +0x10, then a
--       qword read of +0x08 and +0x10. Locates a dword store that lands at the
--       wrong offset.
--   [D] write_buffer of 0x4000 zero bytes; read back. The bulk path is what
--       1554a/1557a use to fill their walk stacks.
--   [E] write_dword to a mapped page's LAST dword (base+0x3FFC) -- a store one
--       dword past a full-page loop is the boundary a `for off = 0, n-4` loop
--       relies on.

print("=== PROBE 1555a: memory write paths ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc_mmap = mk(477)
local sc_getpid = mk(20)

local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(uint64(a), uint64(v)) end)
    return ok
end
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(uint64(a), uint64(v)) end)
    return ok
end

local function mmap_anon(len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(len), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    return n
end

local pid = to_num(sc_getpid())
print(string.format("[0] pid=%d", pid))

local MARK  = 0x0011223344556677
local MARK2 = 0xDEADBEEFCAFEF00D

local P = mmap_anon(0x4000)
if not P then
    print("=== ABORT: no page ===")
    return
end
print(string.format("[0] P=0x%X", P))

-- ---- [A] baseline: does the page accept a qword store at all ----
print("")
print("[A] qword store baseline")
print(string.format("[A] before      P[0]=0x%X", tostring(rq(P))))
local okA = wq(P, MARK)
print(string.format("[A] write_qword ok=%s", tostring(okA)))
local a1 = rq(P)
print(string.format("[A] after       P[0]=0x%X (want 0x%X)", tostring(a1), MARK))
if a1 ~= MARK then
    print("=== VOID: qword stores do not land on this page; nothing below is readable ===")
    return
end
print("[A] OK: qword stores land")

-- ---- [B] the question: does write_dword land ----
print("")
print("[B] dword zeroing of the whole page")
local okB = true
for off = 0, 0x4000 - 4, 4 do
    if not wd(P + off, 0) then okB = false end
end
print(string.format("[B] 4096 write_dword calls, all pcall-ok=%s", tostring(okB)))
local b1 = rq(P)
print(string.format("[B] P[0] after dword zeroing = 0x%X", tostring(b1)))
if b1 == 0 then
    print("[B] VERDICT: write_dword LANDS. The stale marker in 1554a was not a dword bug.")
else
    print("[B] VERDICT: write_dword did NOT land (P[0] still holds the qword).")
    print("[B] Every buffer zeroed with write_dword in this tree is suspect.")
end

-- ---- [C] does a single dword store land at the right offset ----
print("")
print("[C] single dword store inside a qword pattern")
for off = 0, 0x30, 8 do wq(P + off, 0xAAAAAAAAAAAAAAAA) end
print(string.format("[C] seeded 7 qwords of 0xAA at +0x00..+0x30"))
local okC = wd(P + 0x10, 0x12345678)
local c0 = rq(P + 0x08)
local c1 = rq(P + 0x10)
local c2 = rq(P + 0x18)
print(string.format("[C] write_dword(+0x10, 0x12345678) pcall-ok=%s", tostring(okC)))
print(string.format("[C] +0x08=0x%X (want 0xAAAAAAAAAAAAAAAA)", tostring(c0)))
print(string.format("[C] +0x10=0x%X (want 0xAAAAAAAA12345678)", tostring(c1)))
print(string.format("[C] +0x18=0x%X (want 0xAAAAAAAAAAAAAAAA)", tostring(c2)))
if c1 == 0xAAAAAAAA12345678 then
    print("[C] VERDICT: the dword landed at exactly +0x10 and only those 4 bytes changed.")
elseif c1 == 0xAAAAAAAAAAAAAAAA then
    print("[C] VERDICT: the dword did not land.")
else
    print("[C] VERDICT: the dword landed somewhere unexpected; see the three reads.")
end

-- ---- [D] the bulk path ----
print("")
print("[D] write_buffer of 0x4000 zero bytes")
wq(P, MARK)
local okD = pcall(function()
    memory.write_buffer(uint64(P), string.rep("\0", 0x4000))
end)
local d1 = rq(P)
print(string.format("[D] write_buffer pcall-ok=%s, P[0]=0x%X (want 0)",
    tostring(okD), tostring(d1)))
if d1 == 0 then
    print("[D] VERDICT: write_buffer zeroes the page.")
else
    print("[D] VERDICT: write_buffer did not land.")
end

-- ---- [E] the last dword of the page ----
print("")
print("[E] last-dword boundary")
wq(P, MARK)
wq(P + 0x3FF8, MARK)
local okE = wd(P + 0x3FFC, 0x0BADF00D)
print(string.format("[E] write_dword(+0x3FFC, 0x0BADF00D) pcall-ok=%s", tostring(okE)))
print(string.format("[E] +0x3FF8=0x%X (want 0x%X)", tostring(rq(P + 0x3FF8)), MARK))
print(string.format("[E] +0x3FFC reads 0x%X (want low dword 0xBADF00D)", tostring(rq(P + 0x3FFC))))
print("[E] no store in this probe went past base+0x4000")

print("")
print("=== PROBE 1555a COMPLETE ===")
