-- CRASH_CLASS: LOW
-- PROBE 93a4: SO_SNDBUF simple verification
--
-- Core question: after filling a socket buffer and shrinking SO_SNDBUF to 1,
-- does the kernel allow MORE data to be written (MSG_DONTWAIT)?
-- This is a single-thread test — no child needed.

print("=== PROBE 93a4: SO_SNDBUF simple verify ===")
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
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local setval = memory.alloc(4)
local optval = memory.alloc(8)
local optlen = memory.alloc(8)
local buf = memory.alloc(0x4000)
for i = 0, 0x3FFC, 4 do wd(N(buf) + i, 0x41414141) end

for trial = 1, 10 do
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1
    if r ~= 0 then print("socketpair fail"); break end

    -- Set SO_SNDBUF = 65536
    wd(N(setval), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

    -- Read back
    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
    local sb_before = rd(N(optval)) or 0

    -- Fill with sendto(fd, buf, 4096, MSG_DONTWAIT, 0, 0) until full
    local filled = 0
    for fill = 1, 30 do
        local sr = sgn(mk(133)(uint64(fW), uint64(N(buf)), uint64(4096), uint64(0x80), uint64(0), uint64(0)))
        if sr > 0 then filled = filled + sr else break end
    end

    -- Shrink SO_SNDBUF to 1
    wd(N(setval), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
    local sb_after = rd(N(optval)) or 0

    -- Try writing MORE data with MSG_DONTWAIT
    local extra1 = sgn(mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80), uint64(0), uint64(0)))
    local extra2 = sgn(mk(133)(uint64(fW), uint64(N(buf)), uint64(1), uint64(0x80), uint64(0), uint64(0)))

    -- Drain from read side and count
    local drained = 0
    local dbuf = memory.alloc(0x4000)
    for d = 1, 30 do
        local dr = sgn(mk(3)(uint64(fR), dbuf, uint64(0x4000)))
        if dr > 0 then drained = drained + dr else break end
    end

    -- Try writing AFTER drain with tiny sndbuf
    local post_drain = sgn(mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80), uint64(0), uint64(0)))

    print(string.format("  t%d: sb=%d->%d fill=%d extra64=%d extra1=%d drain=%d post64=%d",
        trial, sb_before, sb_after, filled, extra1, extra2, drained, post_drain))

    if extra1 > 0 then
        print("    *** WRITE ACCEPTED PAST HIWAT ***")
    end
    if post_drain > 0 then
        print("    *** POST-DRAIN WRITE OK (expected with tiny hiwat) ***")
    end

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
    if not alive() then print("  *** DEAD ***"); break end
end

-- [B] Stress: 100 fill+shrink+close cycles without draining
print("")
print("[B] STRESS — 100 fill+shrink+close (no drain)")
local ok_count = 0
for trial = 1, 100 do
    if not alive() then print(string.format("  DEAD at trial %d", trial)); break end
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    if r ~= 0 then break end
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1

    wd(N(setval), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    for fill = 1, 20 do
        local sr = sgn(mk(133)(uint64(fW), uint64(N(buf)), uint64(4096), uint64(0x80), uint64(0), uint64(0)))
        if sr <= 0 then break end
    end
    wd(N(setval), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
    ok_count = ok_count + 1
end
print(string.format("  completed: %d/100  alive: %s", ok_count, alive() and "YES" or "NO"))

if not alive() then
    print("*** KERNEL PANIC — CLOSING OVERFULL SOCKET CORRUPTS KERNEL ***")
end

print("")
print("=== 93a4 COMPLETE ===")
