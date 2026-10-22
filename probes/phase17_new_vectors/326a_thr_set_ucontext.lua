-- CRASH_CLASS: MODERATE
-- PROBE 326a: sys 635 rewrites a suspended thread's saved registers
--
-- Context: 325a showed sys 634 copies a 0x4c0-byte ucontext out of a thread
-- that has been suspended with sys 632, and that a running thread refuses.
-- If 635 writes the same structure back, a thread's RIP/RSP/segment words can
-- be changed while it exists. The check avoids guessing about execution: spin
-- at one `jmp $`, suspend, move RIP and RSP with 635, resume, suspend again
-- and read them back with 634.

print("=== PROBE 326a: SET UCONTEXT ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function ptr(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end

local sc_thr = make_syscall(430)
local sc_632 = make_syscall(632)
local sc_633 = make_syscall(633)
local sc_634 = make_syscall(634)
local sc_635 = make_syscall(635)
local sc_info = make_syscall(593)
local sc_mmap = make_syscall(477)

local CTX = memory.alloc(0x600)
local REQ = memory.alloc(0x600)

local function zero(p, n)
    for i = 0, n - 8, 8 do safe_wq(p + i, uint64(0)) end
end

local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
print(string.format("[A] eboot text = 0x%08X%08X", ehi, elo))

local spins = {}
for off = 0, 0x200000 do
    local v = to_num(memory.read_dword(ptr(ehi, elo + off)))
    if (v % 0x10000) == 0xFEEB then
        spins[#spins + 1] = elo + off
        if #spins >= 2 then break end
    end
end
for i = 1, #spins do
    print(string.format("[A] jmp$ #%d = 0x%08X%08X", i, ehi, spins[i]))
end
if #spins < 2 then
    print("[A] need two jmp $ sites; stopping")
    print("=== 326a DONE ===")
    return
end

zero(CTX, 0x500)
safe_wq(CTX + 0x108, uint64(0x480))
safe_wq(CTX + 0x0d0, uint64(0))
safe_wq(CTX + 0x110, uint64(0x10000))
safe_wq(CTX + 0x0c0, uint64(0x43))
safe_wq(CTX + 0x0e0, ptr(ehi, spins[1]))
local stack = sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sl, sh = lo_of(stack)
safe_wq(CTX + 0x0f8, ptr(sh, sl + 0x3000))
safe_wq(CTX + 0x100, uint64(0x3b))

local tidp = memory.alloc(8)
safe_wq(tidp, uint64(0))
local ok, rv = pcall(function() return sc_thr(uint64(CTX), uint64(tidp), uint64(0)) end)
local tid = safe_rd(tidp) or 0
print(string.format("[B] thr_create -> %s tid=0x%X",
    ok and tostring(sgn(lo_of(rv))) or "RAISED", tid))
if tid == 0 then
    print("=== 326a DONE ===")
    return
end

local ok1, rv1 = pcall(function() return sc_632(uint64(tid), uint64(0)) end)
print(string.format("[C] 632 suspend -> %s", ok1 and tostring(sgn(lo_of(rv1))) or "RAISED"))
zero(REQ, 0x600)
local ok2, rv2 = pcall(function() return sc_634(uint64(tid), uint64(REQ)) end)
print(string.format("[C] 634 read   -> %s", ok2 and tostring(sgn(lo_of(rv2))) or "RAISED"))
if not ok2 or sgn(lo_of(rv2)) ~= 0 then
    print("=== 326a DONE ===")
    return
end
local rip_lo, rip_hi = lo_of(safe_rq(REQ + 0x0E0) or uint64(0))
print(string.format("[C] before: RIP=0x%08X%08X", rip_hi, rip_lo))

safe_wq(REQ + 0x0E0, ptr(ehi, spins[2]))
safe_wq(REQ + 0x0F8, ptr(sh, sl + 0x2000))
local ok3, rv3 = pcall(function() return sc_635(uint64(tid), uint64(REQ)) end)
print(string.format("[D] 635 write  -> %s", ok3 and tostring(sgn(lo_of(rv3))) or "RAISED"))

local ok4, rv4 = pcall(function() return sc_633(uint64(tid), uint64(0)) end)
print(string.format("[E] 633 resume -> %s", ok4 and tostring(sgn(lo_of(rv4))) or "RAISED"))
local ok5, rv5 = pcall(function() return sc_632(uint64(tid), uint64(0)) end)
print(string.format("[E] 632 suspend-> %s", ok5 and tostring(sgn(lo_of(rv5))) or "RAISED"))
zero(REQ, 0x600)
local ok6, rv6 = pcall(function() return sc_634(uint64(tid), uint64(REQ)) end)
print(string.format("[E] 634 reread -> %s", ok6 and tostring(sgn(lo_of(rv6))) or "RAISED"))
if ok6 and sgn(lo_of(rv6)) == 0 then
    local nl, nh = lo_of(safe_rq(REQ + 0x0E0) or uint64(0))
    local rl, rh = lo_of(safe_rq(REQ + 0x0F8) or uint64(0))
    print(string.format("[E] after : RIP=0x%08X%08X want=0x%08X%08X %s",
        nh, nl, ehi, spins[2], (nh == ehi and nl == spins[2]) and "CHANGED" or "unchanged"))
    print(string.format("[E] after : RSP=0x%08X%08X want=0x%08X%08X %s",
        rh, rl, sh, sl + 0x2000, (rh == sh and rl == sl + 0x2000) and "CHANGED" or "unchanged"))
end

print("")
print("=== 326a DONE ===")
