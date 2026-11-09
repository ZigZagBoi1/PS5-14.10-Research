-- CRASH_CLASS: HIGH
-- PROBE 238a: evf_cancel (546) against a blocked waiter
--
-- Context: 542 blocks a child thread on a clear bit and 544 from the main
-- thread completes it; 539 delete also completes it with mask 0. 546
-- evf_cancel has never been called. Cancellation is the classic place for an
-- object-lifetime bug: the waiter sits on a list owned by the flag, and cancel
-- has to unlink it while the flag can be set, deleted or recreated from another
-- thread. If it unlinks without holding the object, the completion path walks a
-- freed entry.
--
--   A  create a flag, set bit 1
--   B  spawn a child blocked on bit 2, with a null timeout
--   C  546 in five layouts, 40 ms apart: does the wait page change, does the
--      process survive, does the child still exist
--   D  set bit 2 afterwards: a cancelled waiter that completes again is a
--      second completion, a waiter that never completes is a leak
--   E  delete the flag and read the page once more
--
-- The page is the channel: a waiter that was cancelled cleanly leaves the
-- result dword alone; one that is completed writes a mask.

print("=== PROBE 238a: evf_cancel against a blocked waiter ===")
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
local sc_delete = make_syscall(539)
local sc_wait = make_syscall(542)
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
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
local SW = syscall.syscall_address
local jmp_self = eboot_base + 0x15481
print("[0] eboot=" .. q(eboot_base) .. " sw=" .. q(SW))

local function map(n)
    return sc_mmap(uint64(0), uint64(n), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end

local function spawn_call(rax, rdi, rsi, rdx, rcx, r8, rsp)
    local ctx = map(0x1000)
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
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, uint64(string.format("0x%02X", s:byte(i)))) end)
    end
    pcall(function() memory.write_byte(addr + #s, uint64(0)) end)
end

local function delay(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end

local OUT = map(0x4000)
wd(OUT, 0xDEADBEEF)

print("")
print("[A] create a flag and set bit 1")
put_str(NAME, "evf_238a")
local okc, h = pcall(function() return sc_create(uint64(NAME), uint64(0), uint64(0)):tonumber() end)
H = okc and h or nil
print("    538 -> " .. tostring(H))
if H == nil then
    print("    no handle; aborting")
    return
end
pcall(function() sc_set(uint64(H), uint64(1)) end)

print("")
print("[B] spawn a child blocked on bit 2")
local STACK = map(0x4000)
local tid = spawn_call(uint64(542), uint64(H), uint64(2), uint64(1), uint64(OUT), uint64(0),
    STACK + 0x3000)
print("    tid=" .. q(tid) .. "  result page=" .. q(rd(OUT)))

local function alive(t)
    if t == nil then return "no tid" end
    local ok, v = pcall(function() return sc_thr_kill(t, uint64(0)):tonumber() end)
    if ok then return tostring(v) end
    return "killed"
end

print("")
print("[C] 546 in five layouts")
local function cancel(label, a1, a2, a3)
    local ok, r = pcall(function()
        return sc_cancel(a1 or uint64(0), a2 or uint64(0), a3 or uint64(0))
    end)
    local rv = nil
    if ok and r ~= nil then rv = to_num(r) end
    print(string.format("    %-20s ret=%s  page=%s  tid=%s  pid=%s",
        label, rv == nil and "killed" or tostring(rv), q(rd(OUT)), alive(tid), tostring(pid())))
    delay(4000)
end

cancel("546(H)", uint64(H))
cancel("546(H,1)", uint64(H), uint64(1))
cancel("546(H,2)", uint64(H), uint64(2))
cancel("546(H,2,1)", uint64(H), uint64(2), uint64(1))
cancel("546(H,tid)", uint64(H), tid)

print("")
print("[D] set bit 2 after the cancels")
pcall(function() sc_set(uint64(H), uint64(2)) end)
delay(20000)
print("    page=" .. q(rd(OUT)) .. "  tid=" .. alive(tid))

print("")
print("[E] delete the flag")
local okd, rdv = pcall(function() return sc_delete(uint64(H)):tonumber() end)
print("    539 -> " .. (okd and tostring(rdv) or "killed"))
delay(20000)
print("    page=" .. q(rd(OUT)) .. "  tid=" .. alive(tid))
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 238a COMPLETE ===")
