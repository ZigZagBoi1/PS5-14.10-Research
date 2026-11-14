-- CRASH_CLASS: SAFE  (one store instruction + ret; all writes go to our own allocated buffer)
-- PROBE 1188a: why did the ymm0 spill write nothing? Validates the fcall argument path against a known function
-- (memcpy) before re-testing the gadget, and prints pcall status for every call.
print("=== PROBE 1188a: fcall PATH VALIDATION ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local be = 0
pcall(function() be = N(eboot_base) end)
local P = memory.alloc(0x100); local B = N(P)
print("[A] eboot_base=" .. hexn(be) .. " buf=" .. hexn(B))
local function fill(v) for i=0,0x3C,4 do pcall(function() memory.write_dword(B+i, v) end) end end
local function show(tag)
  local o,buf = pcall(function() return memory.read_buffer(B, 32) end)
  if o and type(buf)=="string" and #buf==32 then
    print(tag .. " " .. (string.gsub(buf, ".", function(c) return string.format("%02x", string.byte(c)) end)))
  else print(tag .. " READ-FAIL") end
end
-- [T1] positive control: memcpy(dst=B, src=eboot, n=16, ...) through the same path the gadget uses
fill(0xC1)
local ok1, r1 = pcall(function() return native.fcall(libc_addrofs.memcpy, U(B), U(be), U(16), U(0), U(0), U(0)) end)
print("[T1] memcpy ok=" .. tostring(ok1) .. " ret=" .. tostring(r1))
show("[T1]")
-- [T2] the gadget exactly as 1187a called it (rsi = uint64 buffer)
fill(0xC2)
local ok2, r2 = pcall(function() return native.fcall_with_rax(be + 0xF7CB7, nil, nil, U(B), nil, nil, nil, nil) end)
print("[T2] gadget ok=" .. tostring(ok2) .. " ret=" .. tostring(r2))
show("[T2]")
-- [T3] same gadget, rsi passed as a plain number
fill(0xC3)
local ok3, r3 = pcall(function() return native.fcall_with_rax(be + 0xF7CB7, 0, 0, B, 0, 0, 0, 0) end)
print("[T3] gadget ok=" .. tostring(ok3) .. " ret=" .. tostring(r3))
show("[T3]")
-- [T4] the neighbouring instruction 0xF7CB4 (vmovups [rsi+0x18],ymm0) to prove we are entering where we think
fill(0xC4)
local ok4, r4 = pcall(function() return native.fcall_with_rax(be + 0xF7CB4, 0, 0, U(B), 0, 0, 0, 0) end)
print("[T4] gadget18 ok=" .. tostring(ok4) .. " ret=" .. tostring(r4))
show("[T4]")
print("[Z] alive")
print("=== DONE ===")
