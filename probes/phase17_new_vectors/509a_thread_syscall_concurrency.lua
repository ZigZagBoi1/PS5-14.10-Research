-- CRASH_CLASS: LOW
-- PROBE 509a: do two Lua threads execute syscalls concurrently?
--
-- 506a-506c showed a helper thread making ~4-11 aio cycles per second while the
-- parent slept, which looks like the loader serializing every syscall behind one
-- lock.  If that is true, no kernel race can ever be won from this harness, and
-- the aio TOC-TOU window is unreachable.  This measures it directly:
--   A: parent alone, N getpid calls, wall time.
--   B: same N calls while a helper thread hammers getpid in parallel.
-- B/A ~= 1 means true concurrency; B/A >> 1 means serialization.
-- The helper also reports its own progress, so a starting thread cannot look
-- like contention.

print("=== PROBE 509a: thread syscall concurrency ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rdq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end

local CTX = memory.alloc(0x80)
local TS  = memory.alloc(0x40)
local sc_getpid = make_syscall(20)
local sc_clock  = make_syscall(232)
local function now_us()
    for o = 0, 0x1F, 4 do wr(TS + o, 0) end
    local ok = pcall(function() return sc_clock(4, uint64(string.format("0x%X", to_num(TS)))) end)
    if not ok then return nil end
    local lo = 0
    local okv, v = pcall(function() return memory.read_qword(TS) end)
    if okv then lo = to_num(v) end
    local okv2, v2 = pcall(function() return memory.read_qword(TS + 8) end)
    local ns = okv2 and to_num(v2) or 0
    return lo * 1000000 + math.floor(ns / 1000)
end
local function rdq2(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok and type(v) == "table" and v.h then return to_num(v.h) * 4294967296 + to_num(v.l) end
    if ok then return to_num(v) end
    return 0
end
-- simple arithmetic instead of the helper above (read_qword returns uint64 userdata)
local function wall_us()
    return now_us()
end

local N = 20000
local function burst(n)
    for i = 1, n do pcall(function() return sc_getpid() end) end
end

local t0 = wall_us()
burst(200)
local t1 = wall_us()
if not t0 or not t1 then print("clock_gettime(232) unavailable; aborting"); print("=== DONE ==="); return end
print(string.format("A warmup 200 calls: %d us", t1 - t0))

t0 = wall_us(); burst(N); t1 = wall_us()
local a = t1 - t0
print(string.format("B alone %d calls: %d us (%.2f us/call)", N, a, a / N))

-- helper: hammer getpid and publish a counter
local C = string.format("0x%X", to_num(CTX))
local body = ([[
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
local sc = make_syscall(20)
local CTX = %s
local n = 0
while to_num(memory.read_dword(CTX + 4)) == 0 do
    for i = 1, 500 do
        pcall(function() return sc() end)
    end
    n = n + 500
    pcall(function() memory.write_dword(CTX, n) end)
end
pcall(function() memory.write_dword(CTX + 8, 1) end)
]]):format(C)

wr(CTX, 0); wr(CTX + 4, 0); wr(CTX + 8, 0)
local thr = run_lua_code_in_new_thread(body, { async = true })
print("helper spawned")

local samples = {}
for k = 1, 6 do
    local before = rd(CTX)
    t0 = wall_us(); burst(N); t1 = wall_us()
    local b = t1 - t0
    local after = rd(CTX)
    samples[#samples + 1] = b
    print(string.format("  C[%d] parent=%d us (%.2f us/call) helper=%d (%+d while parent burst)",
        k, b, b / N, after, after - before))
end

wr(CTX + 4, 1)
print(string.format("D helper started=%d helper_total=%d", rd(CTX + 8), rd(CTX)))
local sum = 0
for _, v in ipairs(samples) do sum = sum + v end
print(string.format("E alone=%d us  concurrent_mean=%d us  ratio=%.2f",
    a, math.floor(sum / #samples), (sum / #samples) / a))
print("=== DONE ===")
