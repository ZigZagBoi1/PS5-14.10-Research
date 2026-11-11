-- CRASH_CLASS: LOW -- every call here is one of 557/558/662/664/669, all already measured returning
-- values rather than kills on 14.10.
-- PROBE 1501a: do two object families share the same handle slots, and does each family's delete or
-- poll reject a handle minted by the other family?
--
-- 96b proved the handle encoding is slot|generation with a 3 bit generation and a period of 8
-- (results/phase17_new_vectors/96b_handle_generation_wrap_20261028_194828.txt: one namedobj slot
-- 0x206 cycled gen 7,0,1..7,0,1 and the id repeated exactly). 96b then tried to recycle that slot
-- with a semaphore, but osem_create returns -1 on 14.10, so the slot was never recycled by a live
-- family and the cross family half of the test proved nothing.
--
-- Meanwhile the slots are visibly shared: 96b saw namedobj at slot 0x206, 538 (named evf) returned
-- 0x4207 = slot 0x207 gen 2, and 70a/1445a saw AIO ids at slots 0x205-0x218. One table, one slot
-- space, several families. The resolver (0xffffffff8b0ee020) walks the table at [proc+0x48] and then
-- compares [obj+8] against a family type descriptor, so the gate is one comparison per call site - 
-- which is exactly the sort of gate that a wrong call skips.
--
-- [A] 557 mints a namedobj, decode its slot
-- [B] 558 frees it, then 669 mints an AIO id
-- [C] did the AIO id land in the freed slot? If not, retry the cycle a few times to force the share
-- [D] 558 (namedobj_delete) on the AIO id  <-- wrong family
-- [E] 664 (aio poll) on the AIO id, to see whether it is still a healthy AIO request
-- [F] the mirror: free an AIO id with 662, mint a namedobj into that slot, then 664 on it
-- [G] report both directions
--
-- -- prior art:
--   results/phase17_new_vectors/96b_handle_generation_wrap_20261028_194828.txt
--   results/phase16_kwrite/70a_generation_wraparound_20261025_154511.txt
--   results/phase36_realargs/1445a_aio_id_generation_20261109_171255.txt
--   probes/phase17_new_vectors/465a_aio_complete_then_delete.lua (the 669/664 shapes used here)
--   docs/DEAD_ENDS.md (object handles are predictable and generation checked)

print("=== PROBE 1501a: CROSS FAMILY HANDLE SLOTS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h, l = N(v.h), N(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return h * 4294967296 + l
end
local function dw(a) return N(memory.read_dword(a)) end
local function nstr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return b
end
local function slot(id) return id % 8192 end
local function gen(id) return math.floor(id / 8192) % 8 end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

-- buffers the AIO shapes need
local PAIR = memory.alloc(0x10)
local REQ  = memory.alloc(0x40)
local DST  = memory.alloc(0x40)
local RESW = memory.alloc(0x10)
local IDS  = memory.alloc(0x40)
local STATE= memory.alloc(0x40)
for i = 0, 0x0F, 4 do pcall(function() memory.write_dword(PAIR + i, uint64(0)) end) end
local okp, rvp = pcall(function() return N(mk(135)(uint64(1), uint64(1), uint64(0), uint64(PAIR), uint64(0), uint64(0))) end)
local fd = dw(PAIR)
print(string.format("  socketpair rv=%s fd=%d", okp and tostring(rvp) or "EXC", fd))

local function aio_submit()
    for i = 0, 0x27, 4 do pcall(function() memory.write_dword(REQ + i, uint64(0)) end) end
    pcall(function() memory.write_dword(REQ + 0x08, uint64(8)) end)
    pcall(function() memory.write_qword(REQ + 0x10, uint64(string.format("0x%X", DST))) end)
    pcall(function() memory.write_qword(REQ + 0x18, uint64(string.format("0x%X", RESW))) end)
    pcall(function() memory.write_dword(REQ + 0x20, uint64(fd)) end)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(IDS + i, uint64(0)) end) end
    pcall(function() memory.write_dword(RESW, uint64(0)) end)
    local ok, rv = pcall(function()
        return N(mk(669)(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
    end)
    return ok and rv or nil, dw(IDS), dw(RESW)
end

local function poll(id)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(STATE + i, uint64(0xEEEEEEEE)) end) end
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(IDS + i, uint64(0)) end) end
    pcall(function() memory.write_dword(IDS, uint64(id)) end)
    local ok, rv = pcall(function()
        return N(mk(664)(uint64(IDS), uint64(1), uint64(STATE), uint64(0), uint64(0), uint64(0)))
    end)
    return ok and rv or nil, dw(STATE)
end

local function del662(id)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(STATE + i, uint64(0xEEEEEEEE)) end) end
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(IDS + i, uint64(0)) end) end
    pcall(function() memory.write_dword(IDS, uint64(id)) end)
    local ok, rv = pcall(function()
        return N(mk(662)(uint64(IDS), uint64(1), uint64(STATE), uint64(0), uint64(0), uint64(0)))
    end)
    return ok and rv or nil, dw(STATE)
end

local function nmcreate(name)
    local ok, v = pcall(function()
        return N(mk(557)(uint64(nstr(name)), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok then return nil, "EXC" end
    return sgn(v), (v == -1) and es() or ""
end
local function nmdelete(h)
    local ok, v = pcall(function()
        return N(mk(558)(uint64(h), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok then return nil end
    return sgn(v)
end

-- ---------------------------------------------------------------- [A]
print("")
print("--- [A] mint a namedobj ---")
local H1, e1 = nmcreate("xfam")
print(string.format("  557 -> %s %s   slot=0x%X gen=%d", tostring(H1), e1, H1 and slot(H1) or 0, H1 and gen(H1) or 0))
if not H1 or H1 == -1 then
    print("  namedobj create failed; stopping")
    print("=== PROBE 1501a INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B]
print("")
print("--- [B] free it, then mint an AIO id ---")
print(string.format("  558(0x%X) -> %s", H1, tostring(nmdelete(H1))))
local okA, A1, st = aio_submit()
print(string.format("  669 -> rv=%s id=0x%X status=0x%X   slot=0x%X gen=%d",
    tostring(okA), A1 or 0, st or 0, (A1 or 0) % 8192, gen(A1 or 0)))
print(string.format("  AIO slot 0x%X vs freed namedobj slot 0x%X  ->  %s",
    (A1 or 0) % 8192, slot(H1), ((A1 or 0) % 8192 == slot(H1)) and "SHARED" or "different"))

-- force the share if the first cycle missed
local tries = 0
while A1 and ((A1 % 8192) ~= slot(H1)) and tries < 6 do
    tries = tries + 1
    del662(A1)
    local Hn = nmcreate("xfam" .. tries)
    if Hn and Hn ~= -1 then
        nmdelete(Hn)
    end
    okA, A1, st = aio_submit()
    print(string.format("  retry %d: 669 -> id=0x%X slot=0x%X %s", tries, A1 or 0, (A1 or 0) % 8192,
        ((A1 or 0) % 8192 == slot(H1)) and "SHARED" or ""))
end

-- ---------------------------------------------------------------- [C]
print("")
print("--- [C] 558 namedobj_delete on the AIO id (wrong family) ---")
print(string.format("  558(0x%X) -> %s", A1 or 0, tostring(nmdelete(A1 or 0))))

-- ---------------------------------------------------------------- [D]
print("")
print("--- [D] is the AIO id still a healthy request? ---")
local okP, pst = poll(A1 or 0)
print(string.format("  664 -> rv=%s state=0x%X", tostring(okP), pst or 0))

-- ---------------------------------------------------------------- [E]
print("")
print("--- [E] mirror: 662 delete the AIO id, mint a namedobj into the slot, then 664 on it ---")
local okD, dst2 = del662(A1 or 0)
print(string.format("  662(0x%X) -> rv=%s state=0x%X", A1 or 0, tostring(okD), dst2 or 0))
local H2, e2 = nmcreate("xfam2")
print(string.format("  557 -> %s %s   slot=0x%X gen=%d", tostring(H2), e2, H2 and slot(H2) or 0, H2 and gen(H2) or 0))
if H2 and H2 ~= -1 then
    local okP2, pst2 = poll(H2)
    print(string.format("  664(0x%X) on a namedobj handle -> rv=%s state=0x%X", H2, tostring(okP2), pst2 or 0))
    print(string.format("  558(0x%X) cleanup -> %s", H2, tostring(nmdelete(H2))))
end

-- ---------------------------------------------------------------- [F]
print("")
print("--- [F] report ---")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1501a COMPLETE ===")
