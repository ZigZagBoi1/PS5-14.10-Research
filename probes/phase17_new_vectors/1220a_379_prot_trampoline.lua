-- CRASH_CLASS: MODERATE
-- PROBE 1220a: syscall 379 (mtypeprotect) with a real argument 4, through the trampoline.
--
-- Until now every 379 sweep in this corpus passed prot in rcx, which never reached the kernel:
-- the stock stub is gettimeofday's bare "0f 05" and the kernel reads argument 4 from r10.
-- libkernel+0x3B7 is a proven "mov r10, rcx ; syscall" (probe 1218a differential test), so for
-- the first time prot is the value we choose.
--
-- 13.60 body 0xabbd80:
--   uap[0x00]=va, uap[0x08]=len, uap[0x10]=id (gate at 0x8ad833e0), uap[0x18]=prot
--   loose table (proc+0xc81 == 0): reject only bit 3 (test dl,8)
--   protbits = ((prot>>1)&0x141) | prot   -> bit1->bit0, bit7->bit6, bit9->bit8
--   vm_map_protect(vmspace, va&~0x3fff, end, id, protbits)
-- If PS5's execute bit is bit 9 (0x200) it lands on FreeBSD's PROT_EXEC (0x100) after the shift,
-- which is exactly the W^X wall this corpus has never crossed.

print("=== PROBE 1220a: 379 with a real prot ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local lk = N(libkernel_base)
local TR = lk + 0x3B7
print(string.format("[0] pid=%d trampoline=0x%X", N(mk(20)()), TR))

-- a RW region we own, via the GPU mmap the corpus uses for heap work
local region = 0
do
    local rv = mk(477)(uint64(0), uint64(0x8000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    region = N(rv)
    print(string.format("[0] mmap(0x8000) -> 0x%X err=%s", region, ES()))
end
if region == 0 or region > 0x7FFFFFFFFF then
    local b = memory.alloc(0x4000)
    local ok,v = pcall(function() return N(uint64(b)) end)
    if ok then region = v - (v % 0x4000) end
    print(string.format("[0] falling back to a heap buffer at 0x%X", region))
end

local probe = memory.alloc(0x40)
local function query(tag, va)
    for i=0,15 do wd(probe+i*4, 0xDEADBEEF) end
    local ok, rv = pcall(function() return mk(547)(uint64(va), uint64(probe)) end)
    local h,l = hilo(rv)
    print(string.format("    [547 %s] ret=0x%08X_%08X err=%s rec=%08X %08X %08X %08X %08X %08X",
        tag, h, l, ES(), rd(probe), rd(probe+4), rd(probe+8), rd(probe+12), rd(probe+16), rd(probe+20)))
end

query("before", region)

local prots = {0,1,2,3,4,5,6,7,8,0x10,0x40,0x100,0x200,0x300,0x400,0x800,0x1000,0x4000}
print("[A] 379(va=0x" .. string.format("%X", region) .. ", len=0x8000, id=0x0A, prot) through the trampoline")
for i = 1, #prots do
    local p = prots[i]
    local ok, rv = pcall(function() return native.fcall_with_rax(TR, 379, region, 0x8000, 0x0A, p, 0, 0) end)
    local h,l = hilo(rv)
    print(string.format("  prot=0x%04X ret=0x%08X_%08X err=%s", p, h, l, ES()))
    if p == 0x200 or p == 0x400 then query(string.format("after prot=0x%X", p), region) end
end

print("[B] same prot through id 0 and id 1 (gate control)")
for _, id in ipairs({0,1,0x0A}) do
    local ok, rv = pcall(function() return native.fcall_with_rax(TR, 379, region, 0x8000, id, 0x200, 0, 0) end)
    local h,l = hilo(rv)
    print(string.format("  id=0x%02X prot=0x200 ret=0x%08X_%08X err=%s", id, h, l, ES()))
end
query("final", region)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
