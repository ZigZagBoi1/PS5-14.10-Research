-- CRASH_CLASS: MODERATE
-- PROBE 786b: real SIGALRM handler to break a blocking sleep (base re-derived)
--
-- Context: 785a showed SIG_IGN does not interrupt nanosleep - an ignored signal
-- never kicks a thread out of an interruptible sleep. A deliverable handler is
-- needed. 786a hardcoded last session's eboot base and died reading unmapped
-- memory; this version takes the base from the region map (sys 674) each run.
--
-- The handler body is a single `ret` from the executable image; the kernel's
-- sigreturn trampoline sits on the signal frame, so `ret` is a complete
-- handler. If the sleep is interrupted, risky probes can arm this watchdog and
-- stop costing a console reboot whenever a syscall blocks.

print("=== PROBE 786b: REAL SIGNAL HANDLER ===")

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
local function ascii(a, n)
    local s = {}
    for i = 0, n - 1 do
        local b = to_num(memory.read_byte(a + i))
        if b == 0 then break end
        s[#s + 1] = string.char(b)
    end
    return table.concat(s)
end

local SIGACTION, SETITIMER, NANOSLEEP, CLOCK = 416, 83, 240, 232
local SIGALRM = 14

local ts  = to_num(memory.alloc(0x40))
local sa  = to_num(memory.alloc(0x40))
local sao = to_num(memory.alloc(0x40))
local itv = to_num(memory.alloc(0x40))
local slp = to_num(memory.alloc(0x40))

local function clear(buf, n)
    for i = 0, n - 1 do wd(buf + i * 4, 0) end
end
local function now_ms()
    clear(ts, 16)
    make_syscall(CLOCK)(U(4), U(ts), Z)
    return rd(ts) * 1000 + math.floor(rd(ts + 8) / 1000000)
end
local function sleep_ms(ms)
    clear(slp, 16)
    wq(slp, U(math.floor(ms / 1000)))
    wq(slp + 8, U((ms % 1000) * 1000000))
    return sgn(make_syscall(NANOSLEEP)(U(slp), Z, Z))
end

-- [0] locate the executable image
local STRIDE, MAX = 72, 512
local buf = to_num(memory.alloc(STRIDE * MAX + 0x100))
clear(buf, 0x100)
local countp = to_num(memory.alloc(16))
wq(countp, Z)
local ok, ret = pcall(function()
    return make_syscall(674)(U(buf), U(STRIDE), U(MAX), U(countp), U(0x40000000), Z)
end)
local count = rd(countp)
print(string.format("[0] 674 ret=%s regions=%d", ok and tostring(sgn(ret)) or "pcall-fail", count))
if count > MAX then count = MAX end

local exec_lo, exec_hi = nil, nil
for i = 0, count - 1 do
    local b = buf + i * STRIDE
    local prot = rd(b + 0x18)
    if (prot % 8) >= 4 then
        local lo = rd(b) + rd(b + 4) * 4294967296
        local hi = rd(b + 8) + rd(b + 12) * 4294967296
        local nm = ascii(b + 0x20, 0x18)
        if nm:find("executable") and (exec_hi == nil or (hi - lo) > (exec_hi - exec_lo)) then
            exec_lo, exec_hi = lo, hi
        end
    end
end
if not exec_lo then
    print("[0b] no executable region found; aborting")
    return
end
print(string.format("[0b] executable [%08X,%08X) size=0x%X", exec_lo, exec_hi, exec_hi - exec_lo))

-- [A] a `ret` followed by int3 padding: a real function end
local ret_gadget = nil
local limit = math.min(exec_hi - exec_lo - 8, 0x180000)
for off = 0, limit, 4 do
    local v = rd(exec_lo + off)
    local b0 = v % 256
    local b1 = math.floor(v / 256) % 256
    local b2 = math.floor(v / 65536) % 256
    local b3 = math.floor(v / 16777216) % 256
    if b0 == 0xC3 then ret_gadget = exec_lo + off; break end
    if b1 == 0xC3 then ret_gadget = exec_lo + off + 1; break end
    if b2 == 0xC3 then ret_gadget = exec_lo + off + 2; break end
    if b3 == 0xC3 then ret_gadget = exec_lo + off + 3; break end
end
print(string.format("[A] ret gadget=%s", ret_gadget and string.format("%08X", ret_gadget) or "none"))
if not ret_gadget then return end

-- [B] install it, no SA_RESTART
clear(sa, 32)
wq(sa, U(ret_gadget))
wd(sa + 8, 0)
local ar = sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sa), U(sao)))
print(string.format("[B] sigaction=%d old_handler=%08X old_flags=%08X", ar, rd(sao), rd(sao + 8)))

if ar == 0 then
    clear(itv, 32)
    wq(itv + 16, U(2))
    print(string.format("[B1] setitimer=%d", sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))))
    local t0 = now_ms()
    local sr = sleep_ms(10000)
    local dt = now_ms() - t0
    print(string.format("[B2] nanosleep(10000) ret=%d elapsed=%dms", sr, dt))
    print(dt < 6000 and "[B3] INTERRUPTED" or "[B3] not interrupted")
    clear(itv, 32)
    sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
end

-- [C] restore, then a control sleep
print(string.format("[C] restore=%d", sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sao), Z))))
local t1 = now_ms()
sleep_ms(500)
print(string.format("[D] control sleep 500ms elapsed=%dms", now_ms() - t1))
print("=== PROBE 786b DONE ===")
