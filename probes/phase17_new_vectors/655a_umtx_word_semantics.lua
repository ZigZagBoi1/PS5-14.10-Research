-- CRASH_CLASS: LOW
-- PROBE 655a: what a mutex word means. M=4 was assumed to be PRIO_INHERIT,
-- but 654a showed a thread "locking" it and the word never changing, which
-- reads as "already owned by someone else". Measure 0 vs 4 directly.
print("=== PROBE 655a: UMTX MUTEX WORD SEMANTICS ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc=function(op,addr,a2) return select(2,pcall(function() return mk(454)(U(addr),uint64(op),U(a2 or 0),uint64(0),uint64(0),uint64(0)) end)) end
local me=N(select(2,pcall(function() local b=memory.alloc(8) mk(432)(U(N(b)),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) return memory.read_dword(b) end)))
print(string.format("[A] my tid=%s",tostring(me)))
local M=memory.alloc(8)
wd(N(M),0)
print(string.format("[B] M=0 lock rv=%s M=%X",tostring(sc(5,N(M))),rd(N(M)) or 0))
print(string.format("[D] M=0 unlock rv=%s M=%X",tostring(sc(6,N(M))),rd(N(M)) or 0))
print(string.format("[F] M=0 trylock rv=%s M=%X",tostring(sc(4,N(M))),rd(N(M)) or 0))
print(string.format("[G] M=0 unlock-now rv=%s M=%X",tostring(sc(6,N(M))),rd(N(M)) or 0))
print("[Z] done")
