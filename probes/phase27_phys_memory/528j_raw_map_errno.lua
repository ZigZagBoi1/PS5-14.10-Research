-- CRASH_CLASS: LOW
-- PROBE 528j: Raw syscall 547/548 with errno capture
--
-- 528i confirmed: sys 547/548/628/477 all return -1 but don't kill.
-- The wrapper at libkernel+0x15020 kills (abort), the raw syscall doesn't.
-- We need to find the CORRECT argument layout.
--
-- FreeBSD syscall convention for mmap-family:
--   On error, carry flag set + errno in rax.
--   On success, carry clear + result in rax.
-- So rv=0xFFFFFFFF might be -EPERM(1), -EACCES(13), -EINVAL(22), etc.
--
-- Strategy: use SROP to call the syscall AND capture rflags carry bit.
-- Actually simpler: just read errno after the call via __error() TLS.
-- BUT we're using SROP which doesn't set errno. Instead, check the raw
-- return value more carefully — FreeBSD returns errno in rax on error
-- with carry flag set.
--
-- Actually, our SROP srop() returns the raw rax after sigreturn.
-- If carry was set, rax = errno (small positive number).
-- If carry was clear, rax = result.
-- The issue: sigreturn restores everything from the saved context,
-- so after the syscall, we're back in Lua context. The return value
-- we see IS the rax from the syscall.
--
-- Wait — our srop() does: getcontext, modify, sigreturn. After sigreturn,
-- the syscall executes, then we return to the getcontext save point with
-- rax = syscall result. So rv IS the raw syscall return.
--
-- rv = 0xFFFFFFFFFFFFFFFF = -1. On FreeBSD, this means errno was set.
-- We need to capture errno separately.
--
-- Plan: After each SROP syscall, use fcall to call __error() (returns &errno)
-- and read the value.

print("=== PROBE 528j: RAW MAP SYSCALLS WITH ERRNO ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- SROP setup
local MC = 0x40
local sc_gc = mk(421)
local sc_sr = mk(417)
local sctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(sctx)) end)
local rip_val = rq(N(sctx) + MC + 0xA0)
local rh, rl = get_hi_lo(rip_val)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(sctx)) end)
    wq(N(sctx) + MC + 0xA0, sc_addr)
    wq(N(sctx) + MC + 0x38, uint64(num))
    if a1 then wq(N(sctx) + MC + 0x08, a1) end
    if a2 then wq(N(sctx) + MC + 0x10, a2) end
    if a3 then wq(N(sctx) + MC + 0x18, a3) end
    if a4 then wq(N(sctx) + MC + 0x20, a4) end
    if a5 then wq(N(sctx) + MC + 0x28, a5) end
    if a6 then wq(N(sctx) + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(sctx)) end)
    if ok then return rv end
    return nil
end

-- Find __error in libkernel (returns pointer to errno)
-- libkernel GOT has __error; we can find it via sysarch or just use
-- the pattern: after a failing syscall, call __error() to get &errno.
--
-- Actually, simpler approach: FreeBSD syscall ABI.
-- On error: CF=1, rax=errno. On success: CF=0, rax=result.
-- Our SROP returns rax. If rv = -1, it means the Lua wrapper
-- converted it. Let's check: does srop() return the RAW rax
-- or does the Lua runtime process it?
--
-- From make_syscall behavior: it uses the native syscall stub which
-- checks CF and returns -errno on error, or result on success.
-- So rv = -1 could mean "errno 1" (EPERM) in the raw ABI.
--
-- Actually no. The stub at fn_addr does: syscall; jnc ok; neg rax; ok: ret
-- So on error (CF=1): rax = errno, then neg rax → rax = -errno.
-- On success (CF=0): rax = result, returned directly.
-- Then: ret, and the Lua side reads rax.
--
-- BUT with SROP, we don't go through the stub. We set rax=syscall_no,
-- and the kernel does the syscall directly from sigreturn.
-- After the syscall, it returns to our saved RIP (the getcontext save),
-- with rax = whatever the kernel put there.
--
-- FreeBSD kernel convention:
-- On error: sets carry flag in rflags, rax = errno number
-- On success: clears carry, rax = return value
-- Since sigreturn restores directly from kernel, rax = errno on error.
--
-- So rv=0xFFFFFFFFFFFFFFFF means the SROP returned -1 literally.
-- But wait, that's 64-bit -1 = 0xFFFF...FFFF. That doesn't match any
-- errno (they're small positive numbers like 1, 13, 22).
--
-- THIS MEANS: the Lua make_syscall wrapper IS processing the return.
-- The stub negates errno and returns -errno. So -1 means errno=1 (EPERM).
--
-- Let me re-examine: srop() calls sc_sr() which goes through make_syscall(417).
-- The sigreturn REPLACES the current context entirely. After it, we're at
-- the saved getcontext point. The return value of sc_gc (getcontext) is what
-- getcontext returns when restored — which is 0 normally, but with SROP
-- it returns to getcontext's save point with rax = syscall result.
--
-- Hmm, this is getting complex. Let me just test known-errno syscalls and
-- compare the return value to figure out the encoding.

print("[CALIBRATE] errno encoding test")

-- Test 1: close(-1) should return -1 with errno=EBADF(9)
local rv_close = srop(6, uint64(0xFFFFFFFF))
print("  close(-1): rv=" .. fmt(rv_close))

-- Test 2: getpid() should return pid (success)
local rv_pid = srop(20)
print("  getpid: rv=" .. fmt(rv_pid) .. " expected_pid=" .. pid)

-- Test 3: mmap with bad fd → EBADF(9)
local rv_mmap = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(0xBEEF), uint64(0))
print("  mmap(bad_fd): rv=" .. fmt(rv_mmap))

-- Test 4: kill(pid, 0) → should return 0 (success)
local rv_kill = srop(37, uint64(pid), uint64(0))
print("  kill(pid,0): rv=" .. fmt(rv_kill))

-- Test 5: read on invalid fd → EBADF
local rv_read = srop(3, uint64(0xBEEF), uint64(0), uint64(0))
print("  read(bad_fd): rv=" .. fmt(rv_read))

-- Now that we know the encoding, let's check what 547 actually returns
print("")
print("[A] sys 547 with errno analysis")

-- Get libkernel base for AllocateDirectMemory
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then
    for h = 0, 0x100 do
        local ib3 = memory.alloc(0x200)
        wd(N(ib3), 0x160)
        local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
        if ok3 and N(r3) == 0 then
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib3) + 8 + i)
                if b then local c = b % 256; if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") then
                lk_lo = rd(N(ib3) + 0x108) or 0
                lk_hi = rd(N(ib3) + 0x10C) or 0
                if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
                if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
                break
            end
        end
    end
end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local alloc_fn = lk_text + uint64(0x17EF0)

-- Allocate physical memory
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
if not ok_a or N(rv_a) ~= 0 then print("  ALLOC FAILED"); return end
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))

-- Open dmem0
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local ok_o, dmem_fd = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
end)
local fd = ok_o and N(dmem_fd) or -1
print("  dmem0 fd=" .. fd)

-- virtAddr pointer
local virt_buf = memory.alloc(8)

-- Test various shapes with errno
-- Shape: sys 547 probably has this signature from FreeBSD:
-- int mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
-- But Sony's MapDirectMemory is different. Let's try every permutation:

local tests = {
    -- FreeBSD mmap-like (maybe Sony re-used the ABI?)
    -- rdi=&virt, rsi=len, rdx=prot, r10=flags, r8=phys, r9=align
    {547, "ptr,len,prot,0,phys,align",
        nil, uint64(0x4000), uint64(3), uint64(0), phys_addr, uint64(0x4000)},

    -- Same with flags=0x412 (MAP_SHARED|MAP_FIXED|0x400 ?)
    {547, "ptr,len,prot,0x412,phys,align",
        nil, uint64(0x4000), uint64(3), uint64(0x412), phys_addr, uint64(0x4000)},

    -- Try with just addr=0 (not pointer) — maybe the kernel picks addr
    {547, "0,len,prot,0,phys,align",
        uint64(0), uint64(0x4000), uint64(3), uint64(0), phys_addr, uint64(0x4000)},

    -- With dmem0 fd somewhere
    {547, "0,len,prot,fd,phys,align",
        uint64(0), uint64(0x4000), uint64(3), uint64(fd), phys_addr, uint64(0x4000)},

    -- 548 variants
    {548, "ptr,len,0x33,0,phys,align",
        nil, uint64(0x4000), uint64(0x33), uint64(0), phys_addr, uint64(0x4000)},
    {548, "0,len,3,fd,phys,align",
        uint64(0), uint64(0x4000), uint64(3), uint64(fd), phys_addr, uint64(0x4000)},
    {548, "ptr,len,3,fd,phys,align",
        nil, uint64(0x4000), uint64(3), uint64(fd), phys_addr, uint64(0x4000)},

    -- Maybe the signature is different: (physAddr, len, prot, flags, &virtOut, align)
    {547, "phys,len,prot,0,&virt,align",
        phys_addr, uint64(0x4000), uint64(3), uint64(0), nil, uint64(0x4000)},

    -- Or: (&virtOut, len, prot, flags, physAddr, align) with r10=flags (syscall ABI)
    -- This is what we already tested. Let's try explicit dmem fd-based shape
    {547, "fd,&virt,len,prot,phys,align",
        uint64(fd), nil, uint64(0x4000), uint64(3), phys_addr, uint64(0x4000)},
}

for _, t in ipairs(tests) do
    if not alive() then print("  DIED"); break end
    wq(N(virt_buf), uint64(0))

    local sc_num = t[1]
    local label = t[2]
    local a1 = t[3] or uint64(N(virt_buf))
    local a2 = t[4] or uint64(N(virt_buf))
    local a3 = t[5]
    local a4 = t[6]
    local a5 = t[7] or uint64(N(virt_buf))
    local a6 = t[8]

    local rv = srop(sc_num, a1, a2, a3, a4, a5, a6)
    local rvn = rv and N(rv) or -999
    local va = rq(N(virt_buf))
    local va_str = fmt(va)

    -- Interpret rv
    local err_str = ""
    if rvn == -1 then err_str = "(generic -1)"
    elseif rvn < 0 and rvn > -256 then err_str = string.format("(errno=%d)", -rvn)
    elseif rvn == 1 then err_str = "(EPERM?)"
    elseif rvn == 9 then err_str = "(EBADF?)"
    elseif rvn == 13 then err_str = "(EACCES?)"
    elseif rvn == 22 then err_str = "(EINVAL?)"
    elseif rvn == 78 then err_str = "(ENOSYS?)"
    elseif rvn > 0 and rvn < 100 then err_str = string.format("(errno=%d?)", rvn)
    elseif rvn == 0 then err_str = "(SUCCESS)"
    end

    print(string.format("  %d %s: rv=%s %s va=%s",
        sc_num, label, fmt(rv), err_str, va_str))

    -- Check if rv looks like a mapped address
    if rv then
        local rvh, rvl = get_hi_lo(rv)
        if rvh < 0 then rvh = rvh + 0x100000000 end
        if rvl < 0 then rvl = rvl + 0x100000000 end
        if rvh ~= 0xFFFFFFFF and rvh ~= 0 and rvl > 0x1000 then
            print("  *** POSSIBLE MAPPED ADDRESS! ***")
            local v = rq(rvl)
            print("    [0]=" .. (v and fmt(v) or "FAULT"))
        end
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== 528j COMPLETE ===")
