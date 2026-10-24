-- CRASH_CLASS: LOW
-- PROBE 509b: thread syscall concurrency, with per-burst progress.
--
-- 509a measured 21.4 us per getpid through the loader's Lua path, then died
-- within ~9 s of spawning a helper that hammers getpid, without printing its
-- first sample.  This run uses short bursts (2000 calls) and prints after every
-- burst, so the per-call cost under contention is visible before any death.

print("=== PROBE 509b: thread syscall concurrency, short bursts ===")
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

local CTX = memory.alloc(0x80)
local TS  = memory.alloc(0x40)
local sc_getpid = make_syscall(20)
local sc_clock  = make_syscall(232)
local function wall_us()
    for o = 0, 0x1F, 4 do wr(TS + o, 0) end
    local okv = pcall(function() return sc_clock(4, uint64(string.format("0x%X", to_num(TS)))) end)
    if not okv then return nil end
    local s = 0
    local ok1, v1 = pcall(function() return memory.read_qword(TS) end)
    if ok1 and type(v1) == "table" and v1.h then
        s = to_num(v1.h) * 4294967296 + to_num(v1.l)
    elseif ok1 then s = to_num(v1) end
    local ns = 0
    local ok2, v2 = pcall(function() return memory.read_qword(TS + 8) end)
    if ok2 and type(v2) == "table" and v2.h then
        ns = to_num(v2.h) * 4294967296 + to_num(v2.l)
    elseif ok2 then ns = to_num(v2) end
    return s * 1000000 + math.floor(ns / 1000)
end

local N = 2000
local function burst(n)
    for i = 1, n do pcall(function() return sc_getpid() end) end
end

local t0 = wall_us(); burst(200); local t1 = wall_us()
if not t0 or not t1 then print("clock_gettime(232) unavailable"); print("=== DONE ==="); return end
print(string.format("A warmup 200: %d us", t1 - t0))

t0 = wall_us(); burst(N); t1 = wall_us()
local a = t1 - t0
print(string.format("B alone %d: %d us (%.2f us/call)", N, a, a / N))

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
    for i = 1, 100 do pcall(function() return sc() end) end
    n = n + 100
    pcall(function() memory.write_dword(CTX, n) end)
end
pcall(function() memory.write_dword(CTX + 8, 1) end)
]]):format(C)

wr(CTX, 0); wr(CTX + 4, 0); wr(CTX + 8, 0)
local thr = run_lua_code_in_new_thread(body, { async = true })
print("helper spawned")

for k = 1, 20 do
    local before = rd(CTX)
    t0 = wall_us(); burst(N); t1 = wall_us()
    local b = (t1 and t0) and (t1 - t0) or -1
    local after = rd(CTX)
    print(string.format("  C[%d] parent=%d us (%.2f/call) ratio=%.2f helper=%d (%+d)",
        k, b, b / N, b / a, after, after - before))
end
wr(CTX + 4, 1)
print(string.format("D helper_started=%d total=%d", rd(CTX + 8), rd(CTX)))
print("=== DONE ===")
