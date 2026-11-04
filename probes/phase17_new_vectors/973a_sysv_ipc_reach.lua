-- CRASH_CLASS: HIGH
-- PROBE 973a: SysV IPC (220-231) with valid arguments
--
-- The isolation sweep killed 221/222/225/226/227/228/230/231 on all-zero arguments,
-- while an unimplemented slot (219) returns -1. Present-and-faulting is not the same
-- as present-and-reachable, so each is called here with a legal call shape.

print("=== PROBE 973a: SYSV IPC 220-231 ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a,o) local ok,v=pcall(function() return to_num(memory.read_dword(a+(o or 0))) end) if ok then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function zero(p,n) for i=0,n-4,4 do wd(p+i,0) end end
local function call(tag, num, ...)
    local args={...} local rv
    local ok=pcall(function() rv=mk(num)(unpack(args)) end)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l=hi_lo(rv)
    print(string.format("  [%s] sys%d ret=0x%08X_%08X (%d)", tag, num, h, l, to_num(rv)))
    return to_num(rv)
end
local pid=to_num(mk(20)())
print("[0] pid=" .. tostring(pid) .. "  IPC_PRIVATE=0 IPC_CREAT=0x200 IPC_RMID=0")

-- A. semaphore
print("[A] semget")
local sem = call("semget priv", 221, uint64(0), uint64(1), uint64(0x1B6))
if sem==nil or sem<0 then
    sem = call("semget key", 221, uint64(0x1234), uint64(1), uint64(0x1B6))
    sem = call("semget key2", 221, uint64(0x1234), uint64(1), uint64(0x3B6))
end
print("    sem=" .. tostring(sem))
if sem and sem>=0 then
    local sb=memory.alloc(0x10) zero(sb,0x10)
    wd(sb,0) wd(sb+4,1) wd(sb+8,0)
    call("semop +1", 222, uint64(sem), uint64(sb), uint64(1))
    call("semop -1", 222, uint64(sem), uint64(sb), uint64(1))
    call("semctl rmid", 220, uint64(sem), uint64(0), uint64(0))
    call("semctl rmid 229", 229, uint64(sem), uint64(0), uint64(0))
end

-- B. message queue
print("[B] msgget")
local mq = call("msgget", 225, uint64(0), uint64(0x1B6))
print("    mq=" .. tostring(mq))
if mq and mq>=0 then
    local buf=memory.alloc(0x40) zero(buf,0x40)
    wd(buf,0x41424344) wd(buf+4,0x45464748)
    call("msgsnd", 226, uint64(mq), uint64(buf), uint64(8), uint64(0))
    local rbuf=memory.alloc(0x80) zero(rbuf,0x80)
    call("msgrcv", 227, uint64(mq), uint64(rbuf), uint64(0x40), uint64(0), uint64(0))
    call("msgctl rmid", 224, uint64(mq), uint64(0), uint64(0))
end

-- C. shared memory
print("[C] shmget")
local shm = call("shmget", 231, uint64(0), uint64(0x1000), uint64(0x1B6))
print("    shm=" .. tostring(shm))
if shm and shm>=0 then
    local p = call("shmat", 228, uint64(shm), uint64(0), uint64(0))
    print("    shmat ret=" .. tostring(p))
    if p and p>0 then
        pcall(function() memory.write_dword(p,0xDEAD973A) end)
        print(string.format("    [shm] wrote, read back 0x%08X", rd(p)))
        call("shmdt", 230, uint64(p))
    end
    call("shmctl rmid", 229, uint64(shm), uint64(0), uint64(0))
end

print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
