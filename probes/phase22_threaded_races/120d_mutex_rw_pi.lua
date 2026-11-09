-- CRASH_CLASS: LOW
-- PROBE 120d: UMTX ops 20-26 (skip 19/23 SEM) + PI mutex + RW locks
--
-- SEM2_WAIT(19) blocks regardless of count=1. Skip it.
-- Focus on ops that matter for races: mutex, RW lock, PI mutex.

print("=== PROBE 120d: MUTEX/RW/PI ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local sc=mk(454)
local UP=N(memory.alloc(0x2000))
for i=0,0x1FF,4 do wd(UP+i,0) end

-- ============================================================
print("--- A: SAFE OPS 20-26 (skip 19,23) ---")
for _,op in ipairs({20, 21, 22, 24, 25, 26}) do
    local addr=UP+op*32
    wd(addr,0); wd(addr+4,0)

    local ret
    local ok,rv=pcall(function()
        if op==25 then return sc(uint64(addr),uint64(op),uint64(8),uint64(0),uint64(0)) end
        if op==26 then return sc(uint64(0),uint64(op),uint64(16),uint64(addr),uint64(0)) end
        return sc(uint64(addr),uint64(op),uint64(0),uint64(0),uint64(0))
    end)
    if ok then ret=N(rv); if ret<0 then ret=-1 end else ret="PFAIL" end
    local w=rd(addr)
    local tag=(w and w~=0) and string.format(" w=0x%X",w) or ""
    print(string.format("  op%02d: %s%s", op, tostring(ret), tag))
end

local c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- B: LOCK/UNLOCK CYCLE ---")
local mx=UP+0x800
wd(mx,0); wd(mx+4,0)

local r1=N(sc(uint64(mx),uint64(5),uint64(0),uint64(0),uint64(0)))
local w1=rd(mx)
print(string.format("  LOCK(5): ret=%d w=0x%X", r1, w1 or 0))

local r2=N(sc(uint64(mx),uint64(6),uint64(0),uint64(0),uint64(0)))
local w2=rd(mx)
print(string.format("  UNLOCK(6): ret=%d w=0x%X", r2, w2 or 0))

-- TRYLOCK
wd(mx,0)
local r3=N(sc(uint64(mx),uint64(4),uint64(0),uint64(0),uint64(0)))
local w3=rd(mx)
print(string.format("  TRYLOCK(4): ret=%d w=0x%X", r3, w3 or 0))
local r3u=N(sc(uint64(mx),uint64(6),uint64(0),uint64(0),uint64(0)))
print(string.format("  UNLOCK: ret=%d", r3u))

-- Double lock (same thread owns it — should fail or succeed depending on recursion)
wd(mx,0)
N(sc(uint64(mx),uint64(5),uint64(0),uint64(0),uint64(0)))
local r4=N(sc(uint64(mx),uint64(4),uint64(0),uint64(0),uint64(0)))
print(string.format("  TRYLOCK(owned): ret=%d", r4))
N(sc(uint64(mx),uint64(6),uint64(0),uint64(0),uint64(0)))

c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- C: PI MUTEX ---")
local pi=UP+0xA00
for i=0,31,4 do wd(pi+i,0) end
wd(pi+4, 0x4) -- UMUTEX_PRIO_INHERIT

local pi1=N(sc(uint64(pi),uint64(5),uint64(0),uint64(0),uint64(0)))
local pw1=rd(pi); local pf1=rd(pi+4)
print(string.format("  PI_LOCK: ret=%d owner=0x%X flags=0x%X", pi1, pw1 or 0, pf1 or 0))

local pi2=N(sc(uint64(pi),uint64(6),uint64(0),uint64(0),uint64(0)))
local pw2=rd(pi)
print(string.format("  PI_UNLOCK: ret=%d owner=0x%X", pi2, pw2 or 0))

-- PI trylock
wd(pi,0)
local pi3=N(sc(uint64(pi),uint64(4),uint64(0),uint64(0),uint64(0)))
local pw3=rd(pi)
print(string.format("  PI_TRYLOCK: ret=%d owner=0x%X", pi3, pw3 or 0))
N(sc(uint64(pi),uint64(6),uint64(0),uint64(0),uint64(0)))

-- PP mutex (priority protect)
local pp=UP+0xB00
for i=0,31,4 do wd(pp+i,0) end
wd(pp+4, 0x8) -- UMUTEX_PRIO_PROTECT
wd(pp+8, 100) -- ceiling

local pp1=N(sc(uint64(pp),uint64(5),uint64(0),uint64(0),uint64(0)))
local ppw=rd(pp); local ppf=rd(pp+4)
print(string.format("  PP_LOCK: ret=%d owner=0x%X flags=0x%X", pp1, ppw or 0, ppf or 0))
if pp1>=0 then
    N(sc(uint64(pp),uint64(6),uint64(0),uint64(0),uint64(0)))
end

-- SET_CEILING
wd(pp,0)
local sc7=N(sc(uint64(pp),uint64(7),uint64(50),uint64(UP+0xB20),uint64(0)))
local ppce=rd(pp+8)
print(string.format("  SET_CEIL: ret=%d ceil=0x%X", sc7, ppce or 0))

c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- D: RW LOCK CYCLE ---")
local rw=UP+0xC00
for i=0,15,4 do wd(rw+i,0) end

local rr1=N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
local rs1=rd(rw)
print(string.format("  RDLOCK: ret=%d st=0x%X", rr1, rs1 or 0))

local rr2=N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs2=rd(rw)
print(string.format("  RDUNLOCK: ret=%d st=0x%X", rr2, rs2 or 0))

wd(rw,0)
local rr3=N(sc(uint64(rw),uint64(13),uint64(0),uint64(0),uint64(0)))
local rs3=rd(rw)
print(string.format("  WRLOCK: ret=%d st=0x%X", rr3, rs3 or 0))

local rr4=N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs4=rd(rw)
print(string.format("  WRUNLOCK: ret=%d st=0x%X", rr4, rs4 or 0))

-- Multiple readers
wd(rw,0)
N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
local rs5=rd(rw)
print(string.format("  3xRDLOCK: st=0x%X", rs5 or 0))
N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs6=rd(rw)
print(string.format("  3xRDUNLOCK: st=0x%X", rs6 or 0))

-- ============================================================
print("")
print("--- E: NWAKE (op21) ---")
local nwa=UP+0xE00
memory.write_qword(nwa, uint64(UP+0xF00))
memory.write_qword(nwa+8, uint64(UP+0xF10))
local nwr=N(sc(uint64(nwa),uint64(21),uint64(2),uint64(0),uint64(0)))
print(string.format("  NWAKE: ret=%d", nwr))

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("DONE canary=%s", c==pid and "OK" or "FAIL"))
print("=== 120d COMPLETE ===")
