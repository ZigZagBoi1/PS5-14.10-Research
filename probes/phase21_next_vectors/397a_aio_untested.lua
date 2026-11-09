-- CRASH_CLASS: MODERATE
-- PROBE 397a: test AIO 665 (aio_get_data) and 668 (aio_create) with real args
--
-- Gap: 665/668 killed on zeros, declared dead. But 669 submit WORKS and
-- returns real IDs. Nobody tested 665/668 with valid pointers or real IDs.
-- 668 is aio_create (narg=2) — might need to be called BEFORE submit.
-- 665 is aio_get_data (narg=2) — might return data from completed requests.
-- 13.60: 668 thunk at 0x265708 (before 661's 0x265710), 665 at 0x265730.

print("=== PROBE 397a: AIO untested ===")

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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- SIGSYS + SIGSEGV + SIGBUS ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end) -- SIGSYS
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end) -- SIGSEGV
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end) -- SIGBUS

-- Open /dev/urandom for AIO reads
local urandom_path = memory.alloc(32)
local ur_str = "/dev/urandom"
for i = 1, #ur_str do wd(N(urandom_path) + i - 1, string.byte(ur_str, i)) end
wd(N(urandom_path) + #ur_str, 0)
local ok_o, ur_fd = pcall(function()
    return mk(5)(uint64(N(urandom_path)), uint64(0), uint64(0)) -- O_RDONLY
end)
ur_fd = ok_o and N(ur_fd) or -1
print("urandom_fd=" .. ur_fd)

-- ============================================
-- PART A: 668 (aio_create) with various args
-- ============================================
print("")
print("-- 668 aio_create --")

local buf_a = memory.alloc(256)
for i = 0, 252, 4 do wd(N(buf_a) + i, 0) end

local patterns_668 = {
    {uint64(N(buf_a)), uint64(0)},
    {uint64(0), uint64(N(buf_a))},
    {uint64(N(buf_a)), uint64(N(buf_a))},
    {uint64(1), uint64(N(buf_a))},
    {uint64(N(buf_a)), uint64(8)},
    {uint64(N(buf_a)), uint64(0x1000)},
    {uint64(2), uint64(N(buf_a))},
    {uint64(3), uint64(N(buf_a))},
}

for i, args in ipairs(patterns_668) do
    for j = 0, 252, 4 do wd(N(buf_a) + j, 0xCC) end
    local ok_c, rv_c = pcall(function()
        return mk(668)(args[1], args[2])
    end)
    local ret = ok_c and N(rv_c) or -999
    local d0 = rd(N(buf_a)) or 0
    local d1 = rd(N(buf_a) + 4) or 0
    local d2 = rd(N(buf_a) + 8) or 0
    local d3 = rd(N(buf_a) + 12) or 0
    print(string.format("[%d] 668(%s,%s)=%d buf=%08X %08X %08X %08X",
        i, tostring(args[1]), tostring(args[2]), ret, d0, d1, d2, d3))
    if not alive() then print("CANARY FAIL after 668"); return end
end

-- ============================================
-- PART B: 670 (aio_init) then 669 (submit)
-- ============================================
print("")
print("-- AIO submit flow --")

-- aio_init
local ok_init, rv_init = pcall(function()
    return mk(670)(uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("670(init)=%d", ok_init and N(rv_init) or -999))

-- Build AIO request for 16-byte read from urandom
local aio_req = memory.alloc(0x30)  -- 0x28 per entry + padding
local aio_data = memory.alloc(64)   -- destination buffer
local aio_result = memory.alloc(16) -- result pointer
local aio_ids = memory.alloc(16)    -- receives ID

for i = 0, 0x2C, 4 do wd(N(aio_req) + i, 0) end
for i = 0, 60, 4 do wd(N(aio_data) + i, 0xDD) end
for i = 0, 12, 4 do wd(N(aio_result) + i, 0xEE) end
wd(N(aio_ids), 0xFFFF)

-- req: +0x00 offset=0, +0x08 nbytes=16, +0x10 data_ptr, +0x18 result_ptr, +0x20 fd, +0x24 pad=0
wq(aio_req, uint64(0))                        -- offset
wq(uint64(N(aio_req) + 8), uint64(16))        -- nbytes
wq(uint64(N(aio_req) + 0x10), uint64(N(aio_data)))   -- data ptr
wq(uint64(N(aio_req) + 0x18), uint64(N(aio_result))) -- result ptr
wd(N(aio_req) + 0x20, ur_fd)                   -- fd
wd(N(aio_req) + 0x24, 0)                       -- padding

-- 669(cmd=1, reqs, count=1, class=1, ids)
local ok_sub, rv_sub = pcall(function()
    return mk(669)(uint64(1), uint64(N(aio_req)), uint64(1),
        uint64(1), uint64(N(aio_ids)))
end)
local sub_ret = ok_sub and N(rv_sub) or -999
local aio_id = rd(N(aio_ids)) or 0xFFFF
local result_w = rd(N(aio_result)) or 0xEE
print(string.format("669(submit)=%d id=0x%04X result=0x%08X", sub_ret, aio_id, result_w))

if not alive() then print("CANARY FAIL after 669"); return end

-- Wait and poll
local dummy = 0
for i = 1, 200000 do dummy = dummy + 1 end

-- 664(ids_ptr, count, out_ptr) — poll
local poll_out = memory.alloc(16)
wd(N(poll_out), 0)
local ok_poll, rv_poll = pcall(function()
    return mk(664)(uint64(N(aio_ids)), uint64(1), uint64(N(poll_out)))
end)
local poll_ret = ok_poll and N(rv_poll) or -999
local poll_state = rd(N(poll_out)) or 0
result_w = rd(N(aio_result)) or 0xEE
print(string.format("664(poll)=%d state=0x%X result=0x%08X", poll_ret, poll_state, result_w))

-- Read the data
local d0 = rd(N(aio_data)) or 0xDD
local d1 = rd(N(aio_data) + 4) or 0xDD
local d2 = rd(N(aio_data) + 8) or 0xDD
local d3 = rd(N(aio_data) + 12) or 0xDD
print(string.format("data=%08X %08X %08X %08X", d0, d1, d2, d3))

if not alive() then print("CANARY FAIL after 664"); return end

-- ============================================
-- PART C: 665 (aio_get_data) with real ID
-- ============================================
print("")
print("-- 665 aio_get_data --")

local buf_665 = memory.alloc(256)
for i = 0, 252, 4 do wd(N(buf_665) + i, 0xBB) end

-- Try: 665(id, output_buf)
local ok_g1, rv_g1 = pcall(function()
    return mk(665)(uint64(aio_id), uint64(N(buf_665)))
end)
local g1_ret = ok_g1 and N(rv_g1) or -999
local g1_d0 = rd(N(buf_665)) or 0xBB
local g1_d1 = rd(N(buf_665) + 4) or 0xBB
print(string.format("665(id=0x%X, buf)=%d d0=%08X d1=%08X", aio_id, g1_ret, g1_d0, g1_d1))
if not alive() then print("CANARY FAIL after 665 attempt 1"); return end

-- Try: 665(output_buf, id) — reversed
for i = 0, 252, 4 do wd(N(buf_665) + i, 0xBB) end
local ok_g2, rv_g2 = pcall(function()
    return mk(665)(uint64(N(buf_665)), uint64(aio_id))
end)
local g2_ret = ok_g2 and N(rv_g2) or -999
local g2_d0 = rd(N(buf_665)) or 0xBB
local g2_d1 = rd(N(buf_665) + 4) or 0xBB
print(string.format("665(buf, id=0x%X)=%d d0=%08X d1=%08X", aio_id, g2_ret, g2_d0, g2_d1))
if not alive() then print("CANARY FAIL after 665 attempt 2"); return end

-- Try with the raw integer id value (not shifted)
for i = 0, 252, 4 do wd(N(buf_665) + i, 0xBB) end
local ok_g3, rv_g3 = pcall(function()
    return mk(665)(uint64(aio_id), uint64(N(buf_665)))
end)
print(string.format("665(raw_id, buf)=%d", ok_g3 and N(rv_g3) or -999))
if not alive() then print("CANARY FAIL after 665 attempt 3"); return end

-- ============================================
-- PART D: 668 (aio_create) AFTER init + submit
-- Maybe it needs AIO to be initialized first
-- ============================================
print("")
print("-- 668 after init --")
local buf_668 = memory.alloc(256)
for i = 0, 252, 4 do wd(N(buf_668) + i, 0xAA) end

-- Try creation patterns
local patterns_668b = {
    {uint64(N(buf_668)), uint64(0x28)},    -- ptr, size of one aiocb
    {uint64(N(buf_668)), uint64(1)},       -- ptr, count
    {uint64(0x28), uint64(N(buf_668))},    -- size, ptr
    {uint64(1), uint64(N(buf_668))},       -- class/type, ptr
    {uint64(N(buf_668)), uint64(ur_fd)},   -- ptr, fd
}

for i, args in ipairs(patterns_668b) do
    for j = 0, 252, 4 do wd(N(buf_668) + j, 0xAA) end
    local ok_c, rv_c = pcall(function()
        return mk(668)(args[1], args[2])
    end)
    local ret = ok_c and N(rv_c) or -999
    local d0 = rd(N(buf_668)) or 0
    local d1 = rd(N(buf_668) + 4) or 0
    print(string.format("[%d] 668(%s,%s)=%d buf=%08X %08X",
        i, tostring(args[1]), tostring(args[2]), ret, d0, d1))
    if not alive() then print("CANARY FAIL after 668 attempt " .. i); return end
end

-- ============================================
-- PART E: 663 (aio_multi_wait) with real ID
-- 663 has narg=5, tested as batch call
-- ============================================
print("")
print("-- 663 aio_multi_wait --")

local wait_ids = memory.alloc(16)
wd(N(wait_ids), aio_id)
local wait_out = memory.alloc(64)
for i = 0, 60, 4 do wd(N(wait_out) + i, 0x77) end

-- 663(ids, count, out, timeout?, flags?)
local ok_w, rv_w = pcall(function()
    return mk(663)(uint64(N(wait_ids)), uint64(1), uint64(N(wait_out)),
        uint64(0), uint64(0))
end)
local w_ret = ok_w and N(rv_w) or -999
local w_d0 = rd(N(wait_out)) or 0x77
print(string.format("663(wait)=%d out[0]=%08X", w_ret, w_d0))
if not alive() then print("CANARY FAIL after 663"); return end

-- ============================================
-- PART F: 666 (aio_multi_cancel) with real ID
-- ============================================
print("")
print("-- 666 aio_multi_cancel --")

local cancel_ids = memory.alloc(16)
wd(N(cancel_ids), aio_id)
local cancel_out = memory.alloc(16)
wd(N(cancel_out), 0x66)

local ok_cc, rv_cc = pcall(function()
    return mk(666)(uint64(N(cancel_ids)), uint64(1), uint64(N(cancel_out)))
end)
local cc_ret = ok_cc and N(rv_cc) or -999
local cc_d0 = rd(N(cancel_out)) or 0x66
print(string.format("666(cancel)=%d out[0]=%08X", cc_ret, cc_d0))
if not alive() then print("CANARY FAIL after 666"); return end

-- Cleanup
pcall(function() mk(6)(uint64(ur_fd)) end)

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 397a COMPLETE ===")
