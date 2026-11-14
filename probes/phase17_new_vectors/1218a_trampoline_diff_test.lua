-- CRASH_CLASS: MODERATE
-- PROBE 1218a: A/B test every stub-table slot for a real "mov r10, rcx" trampoline.
--
-- 1217a showed the cheap discriminator is ambiguous: a stale r10 that happens to be below 3
-- produces exactly the same 0x80020003 as a delivered mode 0. The fix is a differential test
-- that does not depend on what r10 happens to hold:
--
--   call A : 663(ids={0}, 1, out, mode = 0)   -> if mode 0 arrives, out[0] becomes 0x80020003
--   call B : 663(ids={0}, 1, out, mode = 4)   -> if mode 4 arrives, the bound at 0x3b03b8/0x3b041c
--                                               rejects it and out[0] stays 0xAAAAAAAA
--
-- A stub that moves rcx into r10 shows A = 0x80020003 and B = 0xAAAAAAAA. A stub that ignores rcx
-- shows the same result for both calls, whatever stale r10 is at that moment. Two adjacent calls
-- use the same chain, so the stale value cannot masquerade as a mode change.
--
-- The walk covers 0x3B0..0x10F0 at 0x20 stride, the region where every slot ever executed
-- (0x3B0 0x3F0 0x410 0xB50 0xB70 0xD50 0xFF0 0x10F0) turned out to be a live stub.

print("=== PROBE 1218a: differential trampoline search ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local pid0 = N(mk(20)())
local lk = N(libkernel_base)
print(string.format("[0] pid=%d libkernel=0x%X", pid0, lk))
local ids = memory.alloc(16)
local out = memory.alloc(16)
local tb  = memory.alloc(8)
wd(ids,0) wd(ids+4,0) wd(tb,0)

local found = nil
local off = 0x3B0
while off <= 0x10F0 do
    wd(out, 0xAAAAAAAA)
    local ok1 = pcall(function() return native.fcall_with_rax(lk+off+7, 663, ids, 1, out, 0, tb, 0) end)
    local a = rd(out) local ea = ES()
    wd(out, 0xAAAAAAAA)
    local ok2 = pcall(function() return native.fcall_with_rax(lk+off+7, 663, ids, 1, out, 4, tb, 0) end)
    local b = rd(out) local eb = ES()
    local verdict = "same"
    if a == 0x80020003 and b == 0xAAAAAAAA then verdict = "**TRAMPOLINE**" found = off end
    print(string.format("   0x%04X A=0x%08X(%s) B=0x%08X(%s) %s", off, a, ea, b, eb, verdict))
    if found then break end
    off = off + 0x20
end
if found then print(string.format("[1] trampoline = libkernel+0x%X+7" , found))
else print("[1] no differential trampoline in 0x3B0..0x10F0") end
print("=== DONE ===")
