-- CRASH_CLASS: LOW
-- PROBE 528k: Capture real errno from map syscalls
--
-- 528j: all map syscalls return -1 but we can't distinguish the errno.
-- The SROP stub (syscall;ret inside kernel) doesn't separate CF/errno.
--
-- Strategy: Use srop_ccall (main-thread SROP calling a C function) to call
-- a libkernel wrapper that DOES capture errno, or build a custom stub that
-- checks CF after syscall and stores errno.
--
-- Actually, simpler: build a tiny ROP chain in eboot that does:
--   pop rax; ret → 547
--   syscall; ret
--   (on return, if CF=1, rax=errno; if CF=0, rax=result)
-- Then save rax before and after. The issue is we can't read CF.
--
-- SIMPLEST APPROACH: find the errno address from main thread.
-- After a make_syscall() call, errno is set in TLS.
-- Use: sysarch(AMD64_GET_FSBASE) to get FS base, then read
-- the errno offset (typically %fs:0 → self, %fs:-8 or %fs:0x28 is errno
-- on FreeBSD).
--
-- Actually even simpler: call make_syscall directly (not SROP) for 547/548.
-- make_syscall goes through the stub which does syscall;ret with proper
-- errno handling. The Lua side should get back an error indication.
-- But 528i already showed -1 for all. The issue is Lua converts -errno to -1.
--
-- Let me try: call sys 547 via make_syscall, then immediately read errno
-- via __error() from libkernel.

print("=== PROBE 528k: MAP ERRNO CAPTURE ===")
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

-- Ignore signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Get libkernel base
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
print("libkernel=" .. fmt(lk_text))

-- Find __error function in libkernel
-- On FreeBSD, __error() returns a pointer to errno (int* __error(void))
-- It's typically at a known offset. Let's find it by scanning libkernel exports
-- via sys 649 (dlsym equivalent).
-- sys 649: dynlib_get_proc_param? No. Let me use native.fcall to call it.

-- Actually, let me try reading the TLS errno directly.
-- FreeBSD stores errno at TCB-relative offset. After sysarch(AMD64_GET_FSBASE),
-- the offset is typically implementation-specific.
--
-- More practical: just use make_syscall for 547 and check if the Lua layer
-- gives us more info via pcall error strings.

-- APPROACH: Build an SROP chain that:
-- 1. Does the target syscall
-- 2. On return, checks CF via a cmov or similar gadget
--
-- Actually, we don't need CF. On FreeBSD kernel return:
-- - Success: CF=0, rax=result
-- - Error: CF=1, rax=errno (positive number like 1,9,13,22)
--
-- But after sigreturn→syscall→return-to-getcontext, we get rax directly.
-- The issue in 528j was that rv=0xFFFFFFFFFFFFFFFF. That's suspicious
-- because errno should be a small positive number, not -1.
--
-- Wait... rv = -1 means rax = 0xFFFFFFFFFFFFFFFF. That's NOT a valid
-- errno. On FreeBSD, if CF=1 and rax=errno, errno would be like 1, 9, 22.
-- Getting rax=-1 after the kernel returns means either:
-- (a) The syscall number itself is nosys → returns ENOSYS(78) → but that
--     would be rax=78, not -1
-- (b) The Lua make_syscall stub negates errno → -EBADF = -(9) = -9, not -1
-- (c) Something in the return path converts the result
--
-- Hypothesis: make_syscall's stub does:
--   syscall
--   jnc .ok
--   neg rax        ; rax = -errno
--   .ok: ret
-- So on error: rv = -errno (negative). On success: rv = result.
-- But we measured close(-1) → rv = -1 = -1. That would mean errno=1 (EPERM).
-- And -1 as uint64 = 0xFFFFFFFFFFFFFFFF.
--
-- Let me test this hypothesis more carefully.

print("")
print("[CALIBRATE 2] errno via make_syscall")

-- close(-1) → EBADF(9) → should return -9
local sc_close = mk(6)
local ok1, rv1 = pcall(function() return sc_close(uint64(0xFFFFFFFF)) end)
print(string.format("  close(-1): ok=%s rv=%s rvN=%d", tostring(ok1), ok1 and fmt(rv1) or "crash", ok1 and N(rv1) or -999))

-- open nonexistent → ENOENT(2)
local badpath = memory.alloc(0x20)
wd(N(badpath), 0x2F)  -- "/"
wd(N(badpath)+1, 0x6E) -- "n"
wd(N(badpath)+2, 0x6F) -- "o"
wd(N(badpath)+3, 0x70) -- "p"
wd(N(badpath)+4, 0x65) -- "e"
wd(N(badpath)+5, 0x00)
local sc_open = mk(5)
local ok2, rv2 = pcall(function() return sc_open(uint64(N(badpath)), uint64(0), uint64(0)) end)
print(string.format("  open(/nope): ok=%s rv=%s rvN=%d", tostring(ok2), ok2 and fmt(rv2) or "crash", ok2 and N(rv2) or -999))

-- write to bad fd → EBADF(9)
local sc_write = mk(4)
local ok3, rv3 = pcall(function() return sc_write(uint64(0xBEEF), uint64(0), uint64(0)) end)
print(string.format("  write(bad_fd): ok=%s rv=%s rvN=%d", tostring(ok3), ok3 and fmt(rv3) or "crash", ok3 and N(rv3) or -999))

-- getpid → success
local sc_pid = mk(20)
local ok4, rv4 = pcall(function() return sc_pid() end)
print(string.format("  getpid: ok=%s rv=%s rvN=%d", tostring(ok4), ok4 and fmt(rv4) or "crash", ok4 and N(rv4) or -999))

-- Now test 547 via make_syscall (not SROP)
print("")
print("[B] sys 547 via make_syscall")

local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local alloc_fn = lk_text + uint64(0x17EF0)
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
if not ok_a or N(rv_a) ~= 0 then print("  ALLOC FAILED"); return end
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))

local devpath2 = memory.alloc(0x20)
local dname2 = "/dev/dmem0"
for i = 1, #dname2 do wd(N(devpath2) + i - 1, string.byte(dname2, i)) end
wd(N(devpath2) + #dname2, 0)
local ok_o2, dmem_fd2 = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath2)), uint64(2), uint64(0))
end)
local fd = ok_o2 and N(dmem_fd2) or -1
print("  dmem0 fd=" .. fd)

local virt_buf = memory.alloc(8)

-- Test 547 with make_syscall to get real errno via stub negation
local sc_547 = mk(547)
local shapes = {
    {"&virt,len,prot,0,phys,align",
        uint64(N(virt_buf)), uint64(0x4000), uint64(3), uint64(0), phys_addr, uint64(0x4000)},
    {"0,len,prot,0,phys,align",
        uint64(0), uint64(0x4000), uint64(3), uint64(0), phys_addr, uint64(0x4000)},
    {"&virt,len,prot,1,phys,align",
        uint64(N(virt_buf)), uint64(0x4000), uint64(3), uint64(1), phys_addr, uint64(0x4000)},
    {"&virt,len,0x33,0,phys,align",
        uint64(N(virt_buf)), uint64(0x4000), uint64(0x33), uint64(0), phys_addr, uint64(0x4000)},
}

local errno_names = {
    [1]="EPERM", [2]="ENOENT", [9]="EBADF", [12]="ENOMEM",
    [13]="EACCES", [14]="EFAULT", [22]="EINVAL", [35]="EAGAIN",
    [45]="ENOTSUP", [78]="ENOSYS"
}

for _, shape in ipairs(shapes) do
    if not alive() then break end
    wq(N(virt_buf), uint64(0))
    local ok5, rv5 = pcall(function()
        return sc_547(shape[2], shape[3], shape[4], shape[5], shape[6], shape[7])
    end)
    local rvn = ok5 and N(rv5) or -999
    local errno_guess = -1
    if rvn < 0 and rvn > -256 then errno_guess = -rvn end
    local ename = errno_names[errno_guess] or "?"
    local va = rq(N(virt_buf))
    print(string.format("  547 %s: rv=%d errno=%d(%s) va=%s",
        shape[1], rvn, errno_guess, ename, fmt(va)))
end

-- Test 548
print("")
print("[C] sys 548 via make_syscall")
local sc_548 = mk(548)
for _, shape in ipairs(shapes) do
    if not alive() then break end
    wq(N(virt_buf), uint64(0))
    local ok6, rv6 = pcall(function()
        return sc_548(shape[2], shape[3], shape[4], shape[5], shape[6], shape[7])
    end)
    local rvn = ok6 and N(rv6) or -999
    local errno_guess = -1
    if rvn < 0 and rvn > -256 then errno_guess = -rvn end
    local ename = errno_names[errno_guess] or "?"
    local va = rq(N(virt_buf))
    print(string.format("  548 %s: rv=%d errno=%d(%s) va=%s",
        shape[1], rvn, errno_guess, ename, fmt(va)))
end

-- Test 628
print("")
print("[D] sys 628 via make_syscall")
local sc_628 = mk(628)
local shapes_628 = {
    {"0,len,prot,MAP_SHARED,fd,phys",
        uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), phys_addr},
    {"0,len,prot,0x40,fd,phys",
        uint64(0), uint64(0x4000), uint64(3), uint64(0x40), uint64(fd), phys_addr},
    {"0,len,prot,0,-1,phys",
        uint64(0), uint64(0x4000), uint64(3), uint64(0), uint64(0xFFFFFFFF), phys_addr},
}
for _, shape in ipairs(shapes_628) do
    if not alive() then break end
    local ok7, rv7 = pcall(function()
        return sc_628(shape[2], shape[3], shape[4], shape[5], shape[6], shape[7])
    end)
    local rvn = ok7 and N(rv7) or -999
    local errno_guess = -1
    if rvn < 0 and rvn > -256 then errno_guess = -rvn end
    local ename = errno_names[errno_guess] or "?"
    print(string.format("  628 %s: rv=%d errno=%d(%s)",
        shape[1], rvn, errno_guess, ename))
end

-- Additional: Try sys 477 (mmap) with dmem0
print("")
print("[E] sys 477 with dmem0 fd")
local sc_477 = mk(477)
local shapes_477 = {
    {"0,len,RW,SHARED,fd,phys",
        uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), phys_addr},
    {"0,len,RW,SHARED,fd,0",
        uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0)},
    {"0,len,RW,PRIV,fd,0",
        uint64(0), uint64(0x4000), uint64(3), uint64(2), uint64(fd), uint64(0)},
}
for _, shape in ipairs(shapes_477) do
    if not alive() then break end
    local ok8, rv8 = pcall(function()
        return sc_477(shape[2], shape[3], shape[4], shape[5], shape[6], shape[7])
    end)
    local rvn = ok8 and N(rv8) or -999
    local errno_guess = -1
    if rvn < 0 and rvn > -256 then errno_guess = -rvn end
    local ename = errno_names[errno_guess] or "?"
    print(string.format("  477 %s: rv=%d errno=%d(%s)",
        shape[1], rvn, errno_guess, ename))
    -- Check if rv is a mapped address
    if ok8 and rv8 then
        local rvh, rvl = get_hi_lo(rv8)
        if rvh < 0 then rvh = rvh + 0x100000000 end
        if rvl < 0 then rvl = rvl + 0x100000000 end
        if rvh ~= 0xFFFFFFFF and (rvh ~= 0 or rvl > 0x10000) then
            print(string.format("    *** MAPPED at %s ***", fmt(rv8)))
            local v = rq(rvl)
            print("    [0]=" .. (v and fmt(v) or "FAULT"))
        end
    end
end

if fd >= 0 then
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
end

print("")
print("alive=" .. tostring(alive()))
print("=== 528k COMPLETE ===")
