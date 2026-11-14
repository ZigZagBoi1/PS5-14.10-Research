-- CRASH_CLASS: HIGH
-- PROBE 990a: does a lethal syscall produce the loader's fault report?
--
-- 221 semget(IPC_PRIVATE, 1, 0666) kills the process. If the loader's SIGSEGV handler
-- catches that death, the reply is the 440-byte report (magic 0x13371337) and its
-- mcontext carries the RIP at the fault, which attributes the death to a module+offset
-- because the module bases are printed before the call.

print("=== PROBE 990a: CRASH ATTRIBUTION ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function fmt(v) local h,l=hi_lo(v) if h==0 then return string.format("0x%X", l) end return string.format("0x%X%08X", h,l) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end

-- module bases first: the report that follows cannot print anything itself
local info = memory.alloc(0x200)
for i=0,0x1FF,4 do wd(info+i,0) end
wd(info, 0x160)
local okm, rvm = pcall(function() return mk(593)(uint64(0), uint64(tostring(info):match("0x(%x+)")) and uint64(tonumber(tostring(info):match("0x(%x+)"),16)) or uint64(0)) end)
print(string.format("[A] 593(handle 0) -> %s", okm and fmt(rvm) or "PCALL-FAIL"))
if okm then
    print(string.format("    text_lo=0x%08X text_hi=0x%08X size=0x%X", to_num(memory.read_dword(info+0x108)), to_num(memory.read_dword(info+0x10C)), to_num(memory.read_dword(info+0x110))))
end
print(string.format("[B] pid=%u  about to call 221 semget(0,1,0666)", to_num(mk(20)())))
print("[C] MARKER-BEFORE-SEMGET")
local oks, rvs = pcall(function() return mk(221)(uint64(0), uint64(1), uint64(0x1B6)) end)
print(string.format("[D] semget returned ok=%s rv=%s", tostring(oks), oks and fmt(rvs) or ""))
print("[E] MARKER-AFTER-SEMGET")
print("=== COMPLETE ===")
