-- CRASH_CLASS: MODERATE
-- PROBE 240a: 546 after the waiter has already been completed
--
-- Context: 239a showed the split cleanly - 546 on a live flag with no waiter
-- returns 0, and the same call on a flag with a blocked waiter turns the
-- console stream into binary garbage and takes the process with it. So the
-- fatal part is the cancellation of a parked thread, not the handle.
--
-- This probe asks whether the waiter still has to be parked at the moment of
-- the call. Same setup, but the waiter is completed by 544 first and the cancel
-- comes afterwards:
--
--   A  create, block a waiter on bit 2, complete it with 544(H,2), confirm the
--      result page changed, then 546(H,2)
--   B  if A survived, delete the flag and confirm the process is still whole
--
-- A survives  -> cancel only corrupts while a waiter is still linked, which
--                 points at the unlink path and makes the race window explicit
-- A kills     -> cancel damages state that outlives the waiter, which is worse:
--                 the completion path left something the cancel then frees

print("=== PROBE 240a: 546 after completion ===")
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
local function delay(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end

print("")
print("[A] block a waiter, complete it, then cancel")
put_str(NAME, "evf_240a")
local okc, H = pcall(function() return sc_create(uint64(NAME), uint64(0), uint64(0)):tonumber() end)
H = okc and H or nil
print("    538 -> " .. tostring(H))
if H == nil then
    print("    aborting")
    return
end
local OUT = map(0x4000)
wd(OUT, 0xDEADBEEF)
pcall(function() sc_set(uint64(H), uint64(1)) end)
local tid = spawn_wait(H, 2, OUT)
print("    waiter tid=" .. q(tid) .. "  page=" .. q(rd(OUT)))
delay(30000)
print("    page before set=" .. q(rd(OUT)))
local oks, rs = pcall(function() return sc_set(uint64(H), uint64(2)):tonumber() end)
print("    544(H,2) -> " .. (oks and tostring(rs) or "killed"))
delay(30000)
print("    page after set=" .. q(rd(OUT)) .. "  (a mask means the waiter completed)")
local okk, rk = pcall(function() return sc_thr_kill(tid, uint64(0)):tonumber() end)
print("    thr_kill(tid,0) -> " .. (okk and tostring(rk) or "killed"))

print("")
local okx, rx = pcall(function() return sc_cancel(uint64(H), uint64(2), uint64(0)) end)
print("    546(H,2) -> " .. (okx and tostring(to_num(rx)) or "killed") .. "  pid=" .. tostring(pid()))
delay(20000)
print("    page=" .. q(rd(OUT)) .. "  pid=" .. tostring(pid()))

print("")
print("[B] delete")
local okd, rdd = pcall(function() return sc_delete(uint64(H)):tonumber() end)
print("    539 -> " .. (okd and tostring(rdd) or "killed") .. "  pid=" .. tostring(pid()))
print("")
print("=== PROBE 240a COMPLETE ===")
