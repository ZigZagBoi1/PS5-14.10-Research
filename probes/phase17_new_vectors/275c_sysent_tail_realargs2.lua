-- CRASH_CLASS: MODERATE (all 677-734 survived with SIGSYS ignore in 275b)
-- PROBE 275c: High-value sysent tail with real arguments
--
-- 275b proved 677-734 all exist but return -1 with zero args.
-- This probe tries real argument patterns for the most interesting targets:
-- A: mmap2(725) — alternative mmap, test with standard mmap args
-- B: pipe2(687) — proper buffer + flags
-- C: procctl(689) — FreeBSD process control with subcommands
-- D: virtual_query_by_pid(728) — might leak kernel info
-- E: ioreq(715) — I/O request with cmd patterns
-- F: Beyond 734 — does the table extend further?

print("=== PROBE 275c: SYSENT TAIL REAL ARGS ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Install SIGSYS(12), SIGSEGV(11), SIGBUS(10), SIGPIPE(13) ignore
local sc_sigaction = mk(416)
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end
for _, sig in ipairs({12, 11, 10, 13}) do
    wq(N(act), uint64(1)); wd(N(act) + 8, 0)
    pcall(function() sc_sigaction(uint64(sig), act, uint64(0), uint64(0), uint64(0), uint64(0)) end)
end
print("signals: SIGSYS+SIGSEGV+SIGBUS+SIGPIPE ignored")

local function try(num, label, a1, a2, a3, a4, a5, a6)
    if not alive() then return nil, nil end
    local sc = mk(num)
    local ok, rv = pcall(function()
        return sc(a1 or uint64(0), a2 or uint64(0), a3 or uint64(0),
                  a4 or uint64(0), a5 or uint64(0), a6 or uint64(0))
    end)
    print(string.format("  %-4d %-30s ok=%-5s ret=%s", num, label, tostring(ok), fmt(rv)))
    return ok, rv
end

-- [A] mmap2(725) — alternative mmap
-- Try standard mmap args: addr=0, len=0x4000, prot=RW(3), flags=ANON|PRIVATE(0x1002), fd=-1, offset=0
-- Also try with prot=RWX(7) — maybe different privilege check than regular mmap
print("")
print("[A] mmap2(725) with mmap-like args")
try(725, "RW anon", uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
try(725, "RWX anon", uint64(0), uint64(0x4000), uint64(7), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
try(725, "RX anon", uint64(0), uint64(0x4000), uint64(5), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
-- Try with cmd=1 in arg1 (Sony often uses first arg as subcmd)
try(725, "cmd=1", uint64(1), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
try(725, "cmd=0x10", uint64(0x10), uint64(0x4000), uint64(3), uint64(0), uint64(0), uint64(0))

if not alive() then print("DIED in A!") return end

-- [B] pipe2(687) — proper buffer + O_CLOEXEC flag
print("")
print("[B] pipe2(687)")
local pbuf = memory.alloc(16)
for off = 0, 12, 4 do wd(N(pbuf) + off, 0) end
try(687, "flags=0", uint64(N(pbuf)), uint64(0))
local fd0 = rd(N(pbuf))
local fd1 = rd(N(pbuf) + 4)
print(string.format("    fds: %d, %d", fd0 or -99, fd1 or -99))
if fd0 and fd0 > 0 then pcall(function() mk(6)(uint64(fd0)) end) end
if fd1 and fd1 > 0 then pcall(function() mk(6)(uint64(fd1)) end) end

-- O_CLOEXEC = 0x100000 on FreeBSD, O_NONBLOCK = 0x4
for off = 0, 12, 4 do wd(N(pbuf) + off, 0) end
try(687, "flags=O_CLOEXEC", uint64(N(pbuf)), uint64(0x100000))
fd0 = rd(N(pbuf)); fd1 = rd(N(pbuf) + 4)
print(string.format("    fds: %d, %d", fd0 or -99, fd1 or -99))

if not alive() then print("DIED in B!") return end

-- [C] procctl(689)
-- FreeBSD: procctl(idtype, id, cmd, data)
-- PROC_REAP_STATUS=2, PROC_TRACE_CTL=7, PROC_ASLR_CTL=13
print("")
print("[C] procctl(689)")
local pbuf2 = memory.alloc(0x100)
for off = 0, 0xFC, 4 do wd(N(pbuf2) + off, 0) end
-- P_PID=0, our pid
try(689, "REAP_STATUS", uint64(0), uint64(pid), uint64(2), uint64(N(pbuf2)))
try(689, "TRACE_CTL_get", uint64(0), uint64(pid), uint64(7), uint64(N(pbuf2)))
try(689, "ASLR_CTL", uint64(0), uint64(pid), uint64(13), uint64(N(pbuf2)))
-- Try self-targeting with idtype P_PID=0
try(689, "TRACE_STATUS", uint64(0), uint64(pid), uint64(8), uint64(N(pbuf2)))

if not alive() then print("DIED in C!") return end

-- [D] virtual_query_by_pid(728)
-- Likely: virtual_query_by_pid(pid, addr, info_buf, info_size)
print("")
print("[D] virtual_query_by_pid(728)")
local vbuf = memory.alloc(0x200)
for off = 0, 0x1FC, 4 do wd(N(vbuf) + off, 0) end
-- Query our own process at address 0 (start of address space)
try(728, "self,addr=0", uint64(pid), uint64(0), uint64(N(vbuf)), uint64(0x200))
local vb0 = rq(N(vbuf))
if vb0 and N(vb0) ~= 0 then print("    buf[0]=" .. fmt(vb0)) end
-- Also try with address = eboot text
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
for off = 0, 0x1FC, 4 do wd(N(vbuf) + off, 0) end
try(728, "self,addr=eboot", uint64(pid), eboot, uint64(N(vbuf)), uint64(0x200))
vb0 = rq(N(vbuf))
if vb0 and N(vb0) ~= 0 then print("    buf[0]=" .. fmt(vb0)) end
-- Try different arg orders (might be addr, pid, buf, size)
for off = 0, 0x1FC, 4 do wd(N(vbuf) + off, 0) end
try(728, "addr=0,pid,buf", uint64(0), uint64(pid), uint64(N(vbuf)), uint64(0x200))
-- Try with size header pattern (Sony convention: first dword = struct size)
wd(N(vbuf), 0x200)
try(728, "self,0,vhdr", uint64(pid), uint64(0), uint64(N(vbuf)), uint64(0x200))

if not alive() then print("DIED in D!") return end

-- [E] ioreq(715)
print("")
print("[E] ioreq(715)")
local ibuf = memory.alloc(0x100)
for off = 0, 0xFC, 4 do wd(N(ibuf) + off, 0) end
try(715, "cmd=0", uint64(0), uint64(N(ibuf)), uint64(0x100))
try(715, "cmd=1", uint64(1), uint64(N(ibuf)), uint64(0x100))
try(715, "cmd=0x10", uint64(0x10), uint64(N(ibuf)), uint64(0x100))

if not alive() then print("DIED in E!") return end

-- [F] Beyond 734: does table extend further?
print("")
print("[F] Beyond 734")
for num = 735, 750 do
    if not alive() then print("  DIED at " .. num) break end
    local sc = mk(num)
    local ok, rv = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local status = "?"
    if not ok then status = "pcall_fail"
    elseif rv == nil then status = "nil"
    else
        local v = N(rv)
        if v == 0xFFFFFFFF or v == -1 then status = "-1"
        elseif v == 0 then status = "0"
        else status = fmt(rv)
        end
    end
    print(string.format("  %-4d %s", num, status))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 275c COMPLETE ===")
