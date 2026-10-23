-- CRASH_CLASS: LOW
-- PROBE 120e: Lock/unlock cycles — mutex, PI mutex, RW locks
--
-- No op survey. Straight to the lock cycle tests.

print("=== PROBE 120e: LOCK CYCLES ===")
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
for i=0,0xFF,4 do wd(UP+i,0) end

-- ============================================================
print("--- A: REGULAR MUTEX ---")
local mx=UP
wd(mx,0); wd(mx+4,0)

local r1=N(sc(uint64(mx),uint64(5),uint64(0),uint64(0),uint64(0)))
local w1=rd(mx)
print(string.format("LOCK: ret=%d w=0x%X", r1, w1 or 0))

local r2=N(sc(uint64(mx),uint64(6),uint64(0),uint64(0),uint64(0)))
local w2=rd(mx)
print(string.format("UNLOCK: ret=%d w=0x%X", r2, w2 or 0))

wd(mx,0)
local r3=N(sc(uint64(mx),uint64(4),uint64(0),uint64(0),uint64(0)))
local w3=rd(mx)
print(string.format("TRYLOCK: ret=%d w=0x%X", r3, w3 or 0))

-- Double lock (already owned)
local r4=N(sc(uint64(mx),uint64(4),uint64(0),uint64(0),uint64(0)))
print(string.format("TRYLOCK2(owned): ret=%d", r4))

N(sc(uint64(mx),uint64(6),uint64(0),uint64(0),uint64(0)))

-- ============================================================
print("")
print("--- B: PI MUTEX ---")
local pi=UP+0x100
for i=0,31,4 do wd(pi+i,0) end
wd(pi+4, 0x4) -- UMUTEX_PRIO_INHERIT

local p1=N(sc(uint64(pi),uint64(5),uint64(0),uint64(0),uint64(0)))
local pw1=rd(pi); local pf1=rd(pi+4)
print(string.format("PI_LOCK: ret=%d own=0x%X fl=0x%X", p1, pw1 or 0, pf1 or 0))

local p2=N(sc(uint64(pi),uint64(6),uint64(0),uint64(0),uint64(0)))
local pw2=rd(pi)
print(string.format("PI_UNLOCK: ret=%d own=0x%X", p2, pw2 or 0))

-- PI trylock
wd(pi,0)
local p3=N(sc(uint64(pi),uint64(4),uint64(0),uint64(0),uint64(0)))
local pw3=rd(pi)
print(string.format("PI_TRYLOCK: ret=%d own=0x%X", p3, pw3 or 0))
N(sc(uint64(pi),uint64(6),uint64(0),uint64(0),uint64(0)))

-- PP MUTEX: skipped (ret=-1 in 120e run 1)
-- SET_CEILING (op7): skipped (blocked in 120e run 1)
print("PP_MUTEX: SKIPPED (dead)")
print("SET_CEIL: SKIPPED (blocks)")

-- ============================================================
print("")
print("--- D: RW LOCK ---")
local rw=UP+0x300
for i=0,15,4 do wd(rw+i,0) end

local rr1=N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
local rs1=rd(rw)
print(string.format("RDLOCK: ret=%d st=0x%X", rr1, rs1 or 0))

local rr2=N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs2=rd(rw)
print(string.format("RDUNLOCK: ret=%d st=0x%X", rr2, rs2 or 0))

wd(rw,0)
local rr3=N(sc(uint64(rw),uint64(13),uint64(0),uint64(0),uint64(0)))
local rs3=rd(rw)
print(string.format("WRLOCK: ret=%d st=0x%X", rr3, rs3 or 0))

local rr4=N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs4=rd(rw)
print(string.format("WRUNLOCK: ret=%d st=0x%X", rr4, rs4 or 0))

-- 3 readers
wd(rw,0)
N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
local rs5=rd(rw)
print(string.format("3xRD: st=0x%X", rs5 or 0))
N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs6=rd(rw)
print(string.format("3xUNLOCK: st=0x%X", rs6 or 0))

-- ============================================================
print("")
print("--- E: SHM (op25) + ROBUST (op26) ---")
local shm=UP+0x400
wd(shm,0)
local sh1=N(sc(uint64(shm),uint64(25),uint64(1),uint64(0),uint64(0)))
print(string.format("SHM(create): ret=%d", sh1))
local sh2=N(sc(uint64(shm),uint64(25),uint64(8),uint64(0),uint64(0)))
print(string.format("SHM(alive): ret=%d", sh2))

local rob=UP+0x500
wd(rob,0); wd(rob+4,0); wd(rob+8,0); wd(rob+12,0)
local rb1=N(sc(uint64(0),uint64(26),uint64(16),uint64(rob),uint64(0)))
print(string.format("ROBUST_LISTS: ret=%d", rb1))

-- ============================================================
print("")
local c=N(native.fcall_with_rax(stub,20))
print(string.format("DONE canary=%s", c==pid and "OK" or "FAIL"))
print("=== 120e COMPLETE ===")
