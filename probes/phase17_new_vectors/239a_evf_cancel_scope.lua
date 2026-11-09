-- CRASH_CLASS: HIGH
-- PROBE 239a: does 546 kill because of the handle or because of the waiter
--
-- Context: 238a created a flag, blocked a child on a clear bit, then called
-- 546(H) - and the process died. The console stream turned to binary garbage
-- right after the [C] header and the loader came back with a new pid, so
-- something was corrupted rather than cleanly refused. 546 answers -1 for six
-- zeros, so the slot is present; the question is which argument made it fatal.
--
--   A  546 on a live flag with NO waiter      - if this kills, the handle alone
--                                                is enough and the waiter is
--                                                irrelevant
--   B  546 on a flag WITH a blocked waiter    - if only this kills, the
--                                                cancellation path is the bug
--   C  546 on a made-up handle and on zero    - the control the sweep already
--                                                recorded as -1
--
-- A kills only section B, which is the first genuinely suspension-shaped bug
-- the evf family has shown. A kills in section A, so 546 is not a cancel path
-- on 14.10 at all and the 13.60 name does not carry over. Run after a relaunch;
-- section B will probably take the process with it.

print("=== PROBE 239a: 546 with and without a waiter ===")
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
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_create = make_syscall(538)
local sc_set = make_syscall(544)
local sc_cancel = make_syscall(546)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)

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
local SW = syscall.syscall_address
print("[0] sw=" .. q(SW))

local function map(n)
    return sc_mmap(uint64(0), uint64(n), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end

local function spawn_wait(h, bits, out)
    local ctx = map(0x1000)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, SW)
    wq(ctx + C_RSP, map(0x4000) + 0x3000)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, uint64(542))
    wq(ctx + C_RDI, uint64(h))
    wq(ctx + C_RSI, uint64(bits))
    wq(ctx + C_RDX, uint64(1))
    wq(ctx + C_RCX, out)
    wq(ctx + C_R8, uint64(0))
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, uint64(string.format("0x%02X", s:byte(i)))) end)
    end
    pcall(function() memory.write_byte(addr + #s, uint64(0)) end)
end
local function create(name)
    put_str(NAME, name)
    local ok, h = pcall(function() return sc_create(uint64(NAME), uint64(0), uint64(0)):tonumber() end)
    if ok then return h end
    return nil
end
local function delay(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end

print("")
print("[C] controls first: zero and a made-up handle")
do
    local ok, r = pcall(function() return sc_cancel(uint64(0), uint64(0), uint64(0)) end)
    print("    546(0)          ret=" .. (ok and tostring(to_num(r)) or "killed") .. "  pid=" .. tostring(pid()))
end
do
    local ok, r = pcall(function() return sc_cancel(uint64(0xDEAD), uint64(0), uint64(0)) end)
    print("    546(0xDEAD)     ret=" .. (ok and tostring(to_num(r)) or "killed") .. "  pid=" .. tostring(pid()))
end

print("")
print("[A] a live flag with no waiter")
local H1 = create("evf_239a_a")
print("    538 -> " .. tostring(H1))
if H1 ~= nil then
    local ok, r = pcall(function() return sc_cancel(uint64(H1), uint64(0), uint64(0)) end)
    print("    546(H1)         ret=" .. (ok and tostring(to_num(r)) or "killed") .. "  pid=" .. tostring(pid()))
    local ok2, r2 = pcall(function() return sc_cancel(uint64(H1), uint64(1), uint64(0)) end)
    print("    546(H1,1)       ret=" .. (ok2 and tostring(to_num(r2)) or "killed") .. "  pid=" .. tostring(pid()))
end

print("")
print("[B] a live flag WITH a blocked waiter")
local H2 = create("evf_239a_b")
local OUT = map(0x4000)
wd(OUT, 0xDEADBEEF)
print("    538 -> " .. tostring(H2) .. "  page=" .. q(rd(OUT)))
if H2 ~= nil then
    pcall(function() sc_set(uint64(H2), uint64(1)) end)
    local tid, ok = spawn_wait(H2, 2, OUT)
    print("    waiter tid=" .. q(tid) .. "  page=" .. q(rd(OUT)))
    delay(30000)
    print("    page before cancel=" .. q(rd(OUT)))
    local okc, r = pcall(function() return sc_cancel(uint64(H2), uint64(2), uint64(0)) end)
    print("    546(H2,2)       ret=" .. (okc and tostring(to_num(r)) or "killed") .. "  pid=" .. tostring(pid()))
end

print("")
print("    page=" .. q(rd(OUT)) .. "  pid -> " .. tostring(pid()))
print("")
print("=== PROBE 239a COMPLETE ===")
