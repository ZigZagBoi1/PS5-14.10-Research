-- CRASH_CLASS: LOW
-- PROBE 1221a: does the STOCK loader stub deliver argument 4 after all?
--
-- docs/THREADING_ALIVE_14_10.md (upstream) describes the loader's syscall address as
--   mov rax, 116 ; mov r10, rcx ; syscall ; ret
-- and the loader takes gettimeofday_import + 7. If that shape is right, +7 is "mov r10, rcx",
-- not "0f 05", and argument 4 has always been delivered. That contradicts this session's
-- assumption, and 1211a already hints it: in one run mode 1 timed out while mode 0 returned
-- EINVAL, which cannot happen if the mode register is stale.
--
-- Decisive comparison: the same calls through syscall.pipe (stock) and through libkernel+0x3B7.
-- 379 is the ideal probe because its fourth argument is a protection mask whose effect is
-- visible in the error code (bit 3 rejected -> EINVAL, ordinary masks -> EACCES/EOPNOTSUPP).
print("=== PROBE 1221a: stock stub vs 0x3B7 trampoline ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local lk = N(libkernel_base)
local TR = lk + 0x3B7
print(string.format("[0] pid=%d stock=0x%X tramp=0x%X", N(mk(20)()), N(syscall.pipe.fn_addr), TR))

local buf = memory.alloc(0x4000)
local ba = 0
do local ok,v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
print(string.format("[0] buffer 0x%X", ba))

local ids = memory.alloc(16)
local out = memory.alloc(16)
local tb  = memory.alloc(8)
wd(ids,0) wd(ids+4,0) wd(tb,0)

print("[A] 379(va,len,id,prot) stock vs trampoline, identical arguments")
for _, p in ipairs({2, 8, 0x10, 0x200}) do
    wd(out,0xAAAAAAAA)
    local ok1, rv1 = pcall(function() return mk(379)(uint64(ba),uint64(0x1000),uint64(0x0A),uint64(p),uint64(0),uint64(0)) end)
    local e1 = ES()
    local ok2, rv2 = pcall(function() return native.fcall_with_rax(TR, 379, ba, 0x1000, 0x0A, p, 0, 0) end)
    local e2 = ES()
    local h1,l1 = hilo(rv1) local h2,l2 = hilo(rv2)
    print(string.format("  prot=0x%03X stock ret=0x%08X err=%-24s tramp ret=0x%08X err=%s",
        p, l1, e1, l2, e2))
end

print("[B] 663 stock vs trampoline, count 1 mode 0 (no guard) and count 2 mode 0 (guard)")
for _, n in ipairs({1,2}) do
    for _, mode in ipairs({0,1}) do
        wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA)
        local ok1 = pcall(function() return mk(663)(uint64(ids),uint64(n),uint64(out),uint64(mode),uint64(tb)) end)
        local e1, o1 = ES(), rd(out)
        wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA)
        local ok2 = pcall(function() return native.fcall_with_rax(TR, 663, ids, n, out, mode, tb, 0) end)
        local e2, o2 = ES(), rd(out)
        print(string.format("  n=%d mode=%d stock out=%08X err=%-22s | tramp out=%08X err=%s", n, mode, o1, e1, o2, e2))
    end
end
print("=== DONE ===")
