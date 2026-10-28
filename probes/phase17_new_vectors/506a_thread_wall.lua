-- CRASH_CLASS: HIGH
-- PROBE 506a: is there a ~9 second wall on a helper thread that runs aio calls?
--
-- 502a/502b/502d/502i/502j all died between 8.8 and 9.1 seconds with the helper
-- mid-loop, while single-threaded churn (505a: 1100 objects) is clean.  This run
-- isolates the helper: it creates/polls/deletes a fresh id in a loop, publishing
-- a progress counter every iteration; the parent pulses a cheap syscall and
-- reports progress for 12 seconds, then asks the helper to stop.

print("=== PROBE 506a: helper thread wall ===")
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
for o = 0, 0x3C, 4 do wr(CTRL + o, 0) end
wr(DATA, 0)

local A  = string.format("0x%X", to_num(DATA))
local O  = string.format("0x%X", to_num(OUT))
local I  = string.format("0x%X", to_num(IDS))
local R  = string.format("0x%X", to_num(RES))
local C  = string.format("0x%X", to_num(CTRL))

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

wr(CTRL + 4, 0)
local thr = run_lua_code_in_new_thread(body, { async = true })
print("helper spawned")

local sc_getpid = make_syscall(20)
local t0 = os.time()
local last, lastn = 0, 0
for tick = 1, 120 do
    pcall(function() return sc_getpid() end)
    local n = rd(CTRL)
    local now = os.time()
    if n ~= lastn or tick % 10 == 0 then
        print(string.format("t=%2ds n=%d (+%d) done=%d", tick / 10, n, n - lastn, rd(CTRL + 8)))
        lastn = n
    end
end
wr(CTRL + 4, 1)
for i = 1, 50 do pcall(function() return sc_getpid() end) end
print(string.format("stop requested, helper done=%d final n=%d", rd(CTRL + 8), rd(CTRL)))
print("=== DONE ===")
