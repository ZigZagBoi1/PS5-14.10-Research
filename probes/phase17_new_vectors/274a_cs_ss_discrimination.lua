-- CRASH_CLASS: MODERATE (SS=0 variant may panic the kernel; separate connection)
-- PROBE 274a: set_mcontext CS/SS discrimination (13.60 copy map)
--
-- Context: the 13.60 copy map (docs/THR_CREATE_SETMCONTEXT_COPYMAP_13_60.md)
-- shows set_mcontext never reads the context CS field (+0xC0); it copies
-- GPRs, RIP, RSP, SS (raw) and masked rflags. That predicts CS=0 and CS=0x40
-- both yield live threads (189a confirmed CS=0x40), and the zeroed-context
-- panic comes from SS=0 (iretq -> #SS -> double fault) or RIP/RSP=0.
--
-- This probe runs the two discriminating contexts:
--   A: CS=0x00, SS=0x3B, valid RIP=jmp$, valid RSP -> predict LIVE thread
--   B: CS=0x43, SS=0x00, valid RIP/RSP -> predict PANIC (run last)
--
-- If A lives and B panics, the copy map is confirmed on 14.10 and the
-- PR #30/#31 CS narrative is retired. If A panics, 14.10 differs from 13.60
-- and CS is validated somewhere else.

print("=== PROBE 274a: CS/SS discrimination ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function zero(addr, n)
    for off = 0, n - 1, 8 do wq(addr + off, uint64(0)) end
end

local sc_getpid = make_syscall(20)
local sc_thr_self = make_syscall(432)
local sc_thr_kill = make_syscall(431)
local sc_thr_create = make_syscall(430)
local sc_mmap = make_syscall(477)
local sc_nanosleep = make_syscall(240)

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
print("[0] eboot text base=" .. q(eboot_base))

local jmp_self = eboot_base + 0x15481
local store = eboot_base + 0x92C67

local C_RDI, C_RAX = 0x048, 0x078
local C_MAGIC, C_FLAGS, C_TYPE, C_CS, C_RIP, C_RSP, C_SS = 0x108, 0x0D0, 0x110, 0x0C0, 0x0E0, 0x0F8, 0x100

local function new_page()
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(p, 0x38)
    return p
end

local function spawn_ctx(cs, ss)
    local ctx = sc_mmap(uint64(0), uint64(0x1000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(ctx, 0x500)
    local st = new_page()
    wq(st, jmp_self)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, cs)
    wq(ctx + C_RIP, jmp_self)
    wq(ctx + C_RSP, st + 0x800)
    wd(ctx + C_SS, ss)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    wq(ts, 0)
    wq(ts + 8, ms * 1000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

print("")
print("[A] CS=0x00, SS=0x3B, RIP=jmp$, RSP=valid stack")
local tidA, okA, rvA = spawn_ctx(0x00, 0x3B)
print("    thr_create: ok=" .. tostring(okA) .. " rv=" .. tostring(to_num(rvA)) .. " tid=" .. q(tidA))
sleep_ms(800)
local killA = sc_thr_kill(uint64(tidA), uint64(0))
print("    thr_kill(tidA,0)=" .. tostring(to_num(killA)) .. "  (0 = thread ALIVE -> CS ignored, copy map holds)")
pcall(function() sc_thr_kill(uint64(tidA), uint64(9)) end)
local okA2, pidA2 = pcall(function() return sc_getpid():tonumber() end)
print("    canary after A: ok=" .. tostring(okA2) .. " pid=" .. tostring(pidA2))

print("")
print("[B] CS=0x43, SS=0x00 (suspected panic trigger - if output stops here, SS=0 is the killer)")
local tidB, okB, rvB = spawn_ctx(0x43, 0x00)
print("    thr_create: ok=" .. tostring(okB) .. " rv=" .. tostring(to_num(rvB)) .. " tid=" .. q(tidB))
sleep_ms(800)
local killB = sc_thr_kill(uint64(tidB), uint64(0))
print("    thr_kill(tidB,0)=" .. tostring(to_num(killB)))
local okB2, pidB2 = pcall(function() return sc_getpid():tonumber() end)
print("    canary after B: ok=" .. tostring(okB2) .. " pid=" .. tostring(pidB2))
print("    *** SS=0 DID NOT PANIC -> SS is validated or replaced somewhere ***")
print("=== PROBE 274a DONE ===")
