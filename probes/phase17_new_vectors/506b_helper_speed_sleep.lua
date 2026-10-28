-- CRASH_CLASS: HIGH
-- PROBE 506b: does a helper thread run at full speed while the parent sleeps?
--
-- 506a: the helper executed 4 aio cycles in 12 s while the parent spun on getpid.
-- Either the new Lua thread is starved by the parent's loop, or the loader runs
-- Lua threads at a few Hz.  This run replaces the parent spin with nanosleep(240)
-- so the parent is properly blocked, and measures the helper's rate.

print("=== PROBE 506b: helper rate with a sleeping parent ===")
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

local DATA = memory.alloc(0x100)
local OUT  = memory.alloc(0x80)
local IDS  = memory.alloc(0x40)
local RES  = memory.alloc(0x80)
local CTRL = memory.alloc(0x40)
local TS   = memory.alloc(0x40)
for o = 0, 0x3C, 4 do wr(CTRL + o, 0) end
wr(DATA, 0)

local A = string.format("0x%X", to_num(DATA))
local O = string.format("0x%X", to_num(OUT))
local I = string.format("0x%X", to_num(IDS))
local R = string.format("0x%X", to_num(RES))
local C = string.format("0x%X", to_num(CTRL))

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
local c, p, d = make_syscall(669), make_syscall(664), make_syscall(662)
local DATA, OUT, IDS, RES, CTRL = %s, %s, %s, %s, %s
local function rd(a) return to_num(memory.read_dword(a)) end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
local n = 0
while rd(CTRL + 4) == 0 do
  n = n + 1
  wr(OUT, 0)
  local ok = pcall(function() c(1, DATA, 1, 1, OUT) end)
  local id = rd(OUT)
  if id ~= 0 then
    wr(IDS, id)
    pcall(function() p(IDS, 1, RES) end)
    pcall(function() d(IDS, 1, RES) end)
  end
  wr(CTRL, n)
end
wr(CTRL + 8, 1)
]]):format(A, O, I, R, C)

local thr = run_lua_code_in_new_thread(body, { async = true })
local sc_sleep = make_syscall(240)
local function sleep_ms(ms)
    -- FreeBSD nanosleep(clockid, const struct timespec *rqtp, struct timespec *rmtp)
    wr(TS, math.floor(ms / 1000))
    wr(TS + 4, 0)
    wr(TS + 8, (ms % 1000) * 1000000)
    wr(TS + 12, 0)
    pcall(function() return sc_sleep(0, uint64(string.format("0x%X", to_num(TS))), 0) end)
end
print("helper spawned")
for k = 1, 10 do
    sleep_ms(200)
    print(string.format("t=%dms n=%d done=%d", k * 200, rd(CTRL), rd(CTRL + 8)))
end
wr(CTRL + 4, 1)
sleep_ms(300)
print(string.format("stop: helper done=%d final n=%d", rd(CTRL + 8), rd(CTRL)))
print("=== DONE ===")
