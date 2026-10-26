-- CRASH_CLASS: MODERATE
-- PROBE 711b: the whole syscall table with a proven SIGSYS shield.
--
-- Context: 711a showed that every number that used to kill (589, 590, 597, 631,
-- 650, 651, 661, 665, 668, 619, 652, 677, 678, 4095) returns -1 under a working
-- SIG_IGN on SIGSYS. The kill was therefore the nosys path, not a hostile
-- handler.
--
-- That makes a single-connection sweep of the whole table safe: an absent slot
-- returns -1 instead of killing. What remains possible is a hang, so this
-- prints a progress line every 50 numbers and prints every answer that is not
-- -1. Absence is invisible by design; presence is what we are looking for.

print("=== PROBE 711b: full table presence under the shield ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a=N(a)
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end

local sigact=mk(416)
local sa=memory.alloc(0x80)
local oldsa=memory.alloc(0x80)
for i=0,0x78,8 do wq(N(sa)+i,0) end
wq(N(sa)+0,1)
local ok,rv=pcall(function() return sigact(uint64(12),U(N(sa)),U(N(oldsa))) end)
print(string.format("[0] shield rv=%s", tostring(rv)))

local answers={}
for n=0,734 do
    local sc=mk(n)
    local ok2,r=pcall(function() return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    if ok2 then
        local v=N(r)
        -- -1 arrives as a 96-bit all-ones string, so compare the text
        local txt=tostring(r)
        if txt~="0xffffffffffffffffffffffff" and txt~="-1" then
            answers[#answers+1]=string.format("%d=%s",n,txt)
        end
    else
        answers[#answers+1]=string.format("%d=EXC",n)
    end
    if n%50==0 then print(string.format("    at %d",n)) end
end

print("[A] answers that are not -1:")
print("    "..table.concat(answers," "))
print(string.format("[Z] alive=%d", N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
