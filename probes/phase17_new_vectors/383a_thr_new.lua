-- CRASH_CLASS: HIGH
-- PROBE 383a: is 455 a faulting handler, or a thread creator whose child dies at 0
--
-- 354c found that 455 (thr_new in the 13.60 table) terminates the process even
-- with SIGSYS ignored, and PR #99 records it as the only faulting handler in the
-- range. That reading is not the only one: a zeroed thr_param has start_func
-- NULL, so a working creator would start a thread at address 0 and the child's
-- SIGSEGV would take the process down exactly the same way.
--
-- This probe gives it a real struct: start_func is eboot's "mov [rdi],rax; ret",
-- arg points at a marker page, the thread's stack top holds a "jmp $" so the
-- child returns into an infinite loop instead of address 0, and TLS and rtprio
-- are left null. If the marker changes, 455 creates threads and the kill was the
-- child. A second call with param_size 0x100 tests whether the size is bounded,
-- which the FreeBSD source says it is; if the process survives that too, the
-- check is there.

print("=== PROBE 383a: thr_new ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function U(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function hi(a) return math.floor(a / 4294967296) end
local function lo(a) return a % 4294967296 end

-- eboot text base and size through 593
local info = memory.alloc(0x200)
for i = 0, 0x1F8, 4 do pcall(function() memory.write_dword(info + i, 0) end) end
local sc_info = make_syscall(593)
pcall(function() memory.write_dword(info, 0x160) end)  -- size field the query expects
pcall(function() sc_info(uint64(0), info) end)
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return 0 end
local tbase = rd(info + 0x10C) * 4294967296 + rd(info + 0x108)
local tsize = rd(info + 0x110)   -- a single dword; +0x114 is the protection
if tbase == 0 then print("[!] no eboot text base"); return end
print(string.format("eboot text base=0x%X reported_size=0x%X scanning=0x100000", tbase, tsize))

-- scan for the two gadgets
local buf = nil
pcall(function() buf = memory.read_buffer(U(hi(tbase), lo(tbase)), 0x100000) end)  -- first 1 MiB of text; both gadgets sit inside it
if not buf then print("[!] could not read eboot text"); return end
local write_g, loop_g = nil, nil
for i = 1, #buf - 4 do
    if not write_g and buf:byte(i) == 0x48 and buf:byte(i+1) == 0x89 and buf:byte(i+2) == 0x07 and buf:byte(i+3) == 0xC3 then
        write_g = tbase + i - 1
    end
    if not loop_g and buf:byte(i) == 0xEB and buf:byte(i+1) == 0xFE then
        loop_g = tbase + i - 1
    end
    if write_g and loop_g then break end
end
print(string.format("write gadget=0x%X loop gadget=0x%X", write_g or 0, loop_g or 0))
if not write_g or not loop_g then print("[!] gadget missing"); return end

-- marker page, stack page, struct
local mark = memory.alloc(0x1000)
local stack = memory.alloc(0x8000)
local param = memory.alloc(0x100)
for i = 0, 0xFFF, 8 do pcall(function() memory.write_qword(mark + i, uint64(0)) end) end
pcall(function() memory.write_qword(mark, U(0xAAAA0000, 0xAAAA0000)) end)
for i = 0, 0xFF, 8 do pcall(function() memory.write_qword(param + i, uint64(0)) end) end

local stacktop = stack + 0x8000 - 0x100
pcall(function() memory.write_qword(stacktop, U(hi(loop_g), lo(loop_g))) end)

local function field(off, addr) pcall(function() memory.write_qword(param + off, U(hi(addr), lo(addr))) end) end
field(0x00, loop_g)       -- start_func: spin forever, so the child cannot fault
field(0x08, mark)         -- arg
field(0x10, stack)        -- stack_base
field(0x18, 0x8000)       -- stack_size
field(0x20, 0)            -- tls_base
field(0x28, 0)            -- tls_size
field(0x30, 0)            -- rtp

local sc = make_syscall(455)
print("[A] 455(param, 0x38)")
local okA, retA = pcall(function() return sc(uint64(param), uint64(0x38), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("    ok=%s ret=%s", tostring(okA), tostring(retA)))
local m = safe_rq(mark)
if m then print(string.format("    marker=0x%X%08X", m.h or 0, to_num(m))) end

print("[B] 455(param, 0x100)  (size above any known sizeof)")
local okB, retB = pcall(function() return sc(uint64(param), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("    ok=%s ret=%s", tostring(okB), tostring(retB)))

print("[C] 455(NULL, 0) is the shape that killed 354c; skipped here")
print("")
print("=== 383a DONE ===")
