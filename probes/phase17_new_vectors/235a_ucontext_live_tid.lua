-- CRASH_CLASS: MODERATE
-- PROBE 235a: 634 thr_get_ucontext against a real live thread
--
-- Context: 156b tried two argument shapes for 634 and left the buffer
-- untouched, but it never had a real thread id to give it. thr_create (430)
-- works, so a spinning child can supply one: spawn a thread on the `jmp $` in
-- eboot (it never returns, so it stays alive), read its id from the create
-- buffer, confirm it with thr_kill(tid, 0) -> 0, and only then call 634.
--
-- The question is not the return value: it is whether the call writes a
-- register context we can recognise. If it does, the buffer will contain the
-- child's RIP (the `jmp $` address, a value we know), its RSP (a page we
-- mapped), and its CS/SS selectors (0x43 / 0x3b), which identify the layout
-- exactly and hand 635 thr_set_ucontext a buffer to write back.
--
--   A  spawn a spinning child, thr_kill(tid, 0)
--   B  634(tid, BUF) with a canary page: does anything land, and where
--   C  634(tid, BUF, size) and 634(BUF, tid): do the layouts differ
--   D  634(thr_self(), BUF): the caller's own context
--
-- Every canary is re-filled before each call, and getpid() after each pair
-- says whether the process survived. Read-only: this probe never calls 635.

print("=== PROBE 235a: thr_get_ucontext with a live thread ===")
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
local function fill(buf, n, val)
    for off = 0, n - 4, 4 do wd(buf + off, val) end
end

local sc_getpid = make_syscall(20)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_mmap = make_syscall(477)
local sc_get_ucontext = make_syscall(634)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RCX = 0x048, 0x050, 0x058, 0x060
local C_R8, C_RAX = 0x068, 0x078

local dead = false
local function pid()
    local ok, v = pcall(function() return sc_getpid():tonumber() end)
    if ok then return v end
    dead = true
    return nil
end
print("[0] canary pid=" .. tostring(pid()))

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
    print("[0] jmp $ mismatch at " .. q(jmp_self) .. "; aborting")
    return
end
print("[0] eboot=" .. q(eboot_base) .. " sw=" .. q(SW) .. " jmp$=" .. q(jmp_self))

local function map(n)
    return sc_mmap(uint64(0), uint64(n), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end

-- A spinning child: its RIP is the jmp $ address and never leaves it.
local function spawn_spinner(rsp)
    local ctx = map(0x1000)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, jmp_self)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, 0x3B)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local STACK = map(0x4000)
local jmp_self_num = tonumber(string.format("%d", 0)) -- placeholder, unused

print("")
print("[A] spawn a spinning child")
local tid, ok, rv = spawn_spinner(STACK + 0x3000)
print(string.format("    thr_create ok=%s tid=%s", tostring(ok), q(tid)))
if tid == nil then
    print("    no tid; aborting")
    return
end
local okk, alive = pcall(function() return sc_thr_kill(tid, uint64(0)):tonumber() end)
print(string.format("    thr_kill(tid,0) ok=%s -> %s", tostring(okk), tostring(alive)))

local BUF = map(0x4000)
local function scan(label, before)
    local changed, first = 0, -1
    for off = 0, 0x400 - 4, 4 do
        local v = rd(BUF + off)
        if v ~= 0xABABABAB then
            changed = changed + 1
            if first < 0 then first = off end
        end
    end
    print(string.format("    %-26s changed=%d first=+0x%X pid=%s",
        label, changed, first, tostring(pid())))
    return changed
end

local function dump(n)
    for off = 0, n - 8, 8 do
        print(string.format("      +0x%03X  %s", off, q(rq(BUF + off))))
    end
end

local function attempt(label, fn)
    fill(BUF, 0x400, 0xABABABAB)
    local okc, r = pcall(fn)
    local rv2 = nil
    if okc and r ~= nil then rv2 = to_num(r) end
    local changed = scan(label, nil)
    if changed > 0 then dump(0x80) end
    return changed, rv2
end

print("")
print("[B] 634(tid, BUF)")
local changedB = attempt("634(tid, BUF)", function()
    return sc_get_ucontext(tid, uint64(BUF))
end)

print("")
print("[C] other layouts")
attempt("634(tid, BUF, 0x400)", function()
    return sc_get_ucontext(tid, uint64(BUF), uint64(0x400))
end)
attempt("634(BUF, tid)", function()
    return sc_get_ucontext(uint64(BUF), tid)
end)
attempt("634(tid, BUF, 0x1000)", function()
    return sc_get_ucontext(tid, uint64(BUF), uint64(0x1000))
end)

print("")
print("[D] the caller's own thread")
local me = nil
pcall(function() me = make_syscall(432)():tonumber() end)
print("    thr_self -> " .. tostring(me))
if me ~= nil then
    attempt("634(self, BUF)", function()
        return sc_get_ucontext(uint64(me), uint64(BUF))
    end)
end

print("")
print("[E] thr_kill(tid,0) after the reads: " ..
    tostring((function()
        local o, v = pcall(function() return sc_thr_kill(tid, uint64(0)):tonumber() end)
        if o then return v end
        return "killed"
    end)()))
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 235a COMPLETE ===")
