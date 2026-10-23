-- CRASH_CLASS: LOW
-- PROBE 120c: UMTX ops 19-26 + PI mutex + lock/unlock cycle
--
-- 120b blocked on op19 (SEM2_WAIT with count=0).
-- Fix: set word=1 for semaphore ops so they don't block.

print("=== PROBE 120c: UMTX REST ===")
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
print("--- A: OPS 19-26 ---")
for op=19,26 do
    local addr=UP+op*32
    wd(addr,0); wd(addr+4,0); wd(addr+8,0); wd(addr+12,0)

    -- Semaphore ops: set count=1 so they don't block
    if op==19 or op==23 then
        wd(addr, 1) -- sem count=1
    end

    local ret
    local ok,rv=pcall(function()
        if op==25 then -- SHM
            return sc(uint64(addr), uint64(op), uint64(8), uint64(0), uint64(0))
        elseif op==26 then -- ROBUST_LISTS
            return sc(uint64(0), uint64(op), uint64(16), uint64(addr), uint64(0))
        else
            return sc(uint64(addr), uint64(op), uint64(0), uint64(0), uint64(0))
        end
    end)

    if ok then
        ret=N(rv); if ret<0 then ret=-1 end
    else
        ret="PFAIL"
    end
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

-- Regular mutex lock/unlock
local r1=N(sc(uint64(mx),uint64(5),uint64(0),uint64(0),uint64(0)))
local w1=rd(mx)
print(string.format("  LOCK: ret=%d w=0x%X", r1, w1 or 0))

local r2=N(sc(uint64(mx),uint64(6),uint64(0),uint64(0),uint64(0)))
local w2=rd(mx)
print(string.format("  UNLOCK: ret=%d w=0x%X", r2, w2 or 0))

-- Try lock on free mutex
wd(mx,0)
local r3=N(sc(uint64(mx),uint64(4),uint64(0),uint64(0),uint64(0)))
local w3=rd(mx)
print(string.format("  TRYLOCK: ret=%d w=0x%X", r3, w3 or 0))
-- Unlock
local r3u=N(sc(uint64(mx),uint64(6),uint64(0),uint64(0),uint64(0)))
print(string.format("  UNLOCK: ret=%d", r3u))

-- ============================================================
print("")
print("--- C: PI MUTEX ---")
local pi=UP+0xA00
for i=0,31,4 do wd(pi+i,0) end
-- umutex: m_owner(4), m_flags(4), m_ceilings[2](8), m_rb_lnk(8)
-- Set UMUTEX_PRIO_INHERIT=0x4
wd(pi+4, 0x4)

local pi1=N(sc(uint64(pi),uint64(5),uint64(0),uint64(0),uint64(0)))
local pw1=rd(pi); local pf1=rd(pi+4)
print(string.format("  PI LOCK: ret=%d owner=0x%X flags=0x%X", pi1, pw1 or 0, pf1 or 0))

local pi2=N(sc(uint64(pi),uint64(6),uint64(0),uint64(0),uint64(0)))
local pw2=rd(pi)
print(string.format("  PI UNLOCK: ret=%d owner=0x%X", pi2, pw2 or 0))

-- PI TRYLOCK
wd(pi,0)
local pi3=N(sc(uint64(pi),uint64(4),uint64(0),uint64(0),uint64(0)))
local pw3=rd(pi)
print(string.format("  PI TRYLOCK: ret=%d owner=0x%X", pi3, pw3 or 0))
-- Unlock
local pi4=N(sc(uint64(pi),uint64(6),uint64(0),uint64(0),uint64(0)))
print(string.format("  PI UNLOCK2: ret=%d", pi4))

-- ============================================================
print("")
print("--- D: RW LOCK CYCLE ---")
local rw=UP+0xC00
-- urwlock: rw_state(4), rw_flags(4), rw_blocked_readers(4), rw_blocked_writers(4)
wd(rw,0); wd(rw+4,0); wd(rw+8,0); wd(rw+12,0)

-- RDLOCK
local rr1=N(sc(uint64(rw),uint64(12),uint64(0),uint64(0),uint64(0)))
local rs1=rd(rw)
print(string.format("  RDLOCK: ret=%d state=0x%X", rr1, rs1 or 0))

-- RDUNLOCK
local rr2=N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs2=rd(rw)
print(string.format("  RD_UNLOCK: ret=%d state=0x%X", rr2, rs2 or 0))

-- WRLOCK
wd(rw,0)
local rr3=N(sc(uint64(rw),uint64(13),uint64(0),uint64(0),uint64(0)))
local rs3=rd(rw)
print(string.format("  WRLOCK: ret=%d state=0x%X", rr3, rs3 or 0))

-- WRUNLOCK
local rr4=N(sc(uint64(rw),uint64(14),uint64(0),uint64(0),uint64(0)))
local rs4=rd(rw)
print(string.format("  WR_UNLOCK: ret=%d state=0x%X", rr4, rs4 or 0))

-- ============================================================
print("")
print("--- E: NWAKE_PRIVATE (op21) ---")
local nw_arr=UP+0xE00
local nw_t1=UP+0xF00
local nw_t2=UP+0xF10
memory.write_qword(nw_arr, uint64(nw_t1))
memory.write_qword(nw_arr+8, uint64(nw_t2))
local nwr=N(sc(uint64(nw_arr),uint64(21),uint64(2),uint64(0),uint64(0)))
print(string.format("  NWAKE: ret=%d", nwr))

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("DONE canary=%s", c==pid and "OK" or "FAIL"))
print("=== 120c COMPLETE ===")
