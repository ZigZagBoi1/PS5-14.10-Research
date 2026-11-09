-- CRASH_CLASS: LOW
-- PROBE 396i: MINIMAL setsockopt test — exact copy of 50f pattern
--
-- 50f's getsockopt WORKED. Copy its exact pattern to verify the
-- mechanism still works. If it fails here, something changed in the loader.

print("=== PROBE 396i: minimal sockopt ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- EXACT copy from 50f: sigaction
local sa = memory.alloc(0x40)
for i = 0, 0x3F, 4 do wd(N(sa) + i, 0) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- EXACT copy from 50f: socket with IPPROTO_TCP=6 as 3rd arg
local sc_socket = mk(97)
local ok_s, fd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(6))
end)
fd = ok_s and N(fd) or -999
print("fd=" .. fd)

-- EXACT copy from 50f: getsockopt
local val = memory.alloc(256)
local vlen = memory.alloc(16)

-- Test 1: getsockopt(TCP_NODELAY) — 50f showed this returns 0
wd(N(vlen), 256)
for i = 0, 60, 4 do wd(N(val) + i, 0) end
local ok1, rv1 = pcall(function()
    return mk(118)(uint64(fd), uint64(6), uint64(1), val, vlen)
end)
local v1 = rd(N(val)) or 0
local l1 = rd(N(vlen)) or 0
print(string.format("getsockopt(TCP_NODELAY)=%d val=%d len=%d",
    ok1 and N(rv1) or -999, v1, l1))

-- Test 2: setsockopt(TCP_NODELAY=1)
wd(N(val), 1)
local ok2, rv2 = pcall(function()
    return mk(105)(uint64(fd), uint64(6), uint64(1), val, uint64(4))
end)
print(string.format("setsockopt(TCP_NODELAY)=%d", ok2 and N(rv2) or -999))

-- Test 3: Verify sysctl with EXACT working pattern (kinfo_proc)
print("")
print("-- sysctl kinfo_proc --")
local mib = memory.alloc(16)
wd(N(mib), 1)       -- CTL_KERN
wd(N(mib) + 4, 14)  -- KERN_PROC
wd(N(mib) + 8, 1)   -- KERN_PROC_PID
wd(N(mib) + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
pcall(function() memory.write_qword(oldlenp, uint64(0x800)) end)
local ok3, rv3 = pcall(function()
    return mk(202)(uint64(N(mib)), uint64(4), uint64(N(outbuf)),
        uint64(N(oldlenp)), uint64(0), uint64(0))
end)
local sc_ret = ok3 and N(rv3) or -999
local sc_len = rd(N(oldlenp)) or 0
local ki_pid_off = 0x2E4  -- ki_pid offset in kinfo_proc
local ki_pid = rd(N(outbuf) + ki_pid_off) or 0
print(string.format("sysctl(kinfo_proc)=%d len=%d ki_pid=%d", sc_ret, sc_len, ki_pid))

-- Test 4: Also verify with dynlib_get_info (2-arg, known working)
print("")
print("-- dynlib_get_info --")
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=%X_%08X", eb_hi, eb_lo))

-- Test 5: Print buffer addresses to verify they're sane
print("")
print("-- addresses --")
print(string.format("val_addr=%s (N=%s)", tostring(val), tostring(N(val))))
print(string.format("vlen_addr=%s (N=%s)", tostring(vlen), tostring(N(vlen))))
print(string.format("mib_addr=%s (N=%s)", tostring(mib), tostring(N(mib))))
print(string.format("outbuf_addr=%s (N=%s)", tostring(outbuf), tostring(N(outbuf))))
print(string.format("type(val)=%s type(N(val))=%s", type(val), type(N(val))))

-- Test 6: Verify uint64() wrapping doesn't change the value
local raw_addr = N(val)
local wrapped = uint64(raw_addr)
local unwrapped = N(wrapped)
print(string.format("raw=%s wrapped=%s unwrapped=%s same=%s",
    tostring(raw_addr), tostring(wrapped), tostring(unwrapped),
    tostring(raw_addr == unwrapped)))

print("")
print("canary=" .. (N(native.fcall_with_rax(stub, 20)) == pid and "OK" or "FAIL"))
print("=== 396i COMPLETE ===")
