-- CRASH_CLASS: LOW
-- PROBE 903a: what memory.alloc actually returns. My to_num() turns an alloc handle
-- into 0 and every pointer derived from it becomes NULL, which would kill the child
-- at its first store. Measure instead of guessing.
print("=== PROBE 903a: alloc handle type ===")
local a = memory.alloc(64)
print("[A] type="..type(a).." tostring="..tostring(a))
local okn, n = pcall(function() return tonumber(a) end)
print("[B] tonumber ok="..tostring(okn).." val="..tostring(n))
local okm, m = pcall(function() return a:tonumber() end)
print("[C] :tonumber() ok="..tostring(okm).." val="..tostring(m))
local okh, h = pcall(function() return a.h end)
local okl, l = pcall(function() return a.l end)
print("[D] .h ok="..tostring(okh).." = "..tostring(h).."  .l ok="..tostring(okl).." = "..tostring(l))
local okw = pcall(function() memory.write_qword(a, 0x1122334455667788) end)
local okr, r = pcall(function() return memory.read_qword(a) end)
print("[E] write/read via handle ok="..tostring(okw).."/"..tostring(okr).." val="..tostring(r))
local okc, cnt = pcall(function() return #a end)
print("[F] #handle ok="..tostring(okc).." val="..tostring(cnt))
local okq = pcall(function() return memory.read_qword(a + 8) end)
print("[G] handle + 8 ok="..tostring(okq))
print("[H] uint64(handle) attempt:")
local oku, u = pcall(function() return uint64(a) end)
print("    ok="..tostring(oku).." val="..tostring(u))
