-- CRASH_CLASS: LOW
-- PROBE 93a8: SO_SNDBUF fill+shrink — no big buffer init

print("=== PROBE 93a8 ===")

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

print("A: pid")
local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("pid=" .. pid_val)

-- Use a tiny buffer, no init needed (send whatever is in heap)
local buf = memory.alloc(256)
local sv = memory.alloc(4)
local ov = memory.alloc(4)
local ol = memory.alloc(4)
print("B: alloc done")

-- socketpair
local sp = memory.alloc(8)
wd(N(sp), 0); wd(N(sp)+4, 0)
local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
local fW = rd(N(sp)) or -1
local fR = rd(N(sp)+4) or -1
print("C: sp=" .. r .. " W=" .. fW .. " R=" .. fR)

-- SO_SNDBUF = 65536
wd(N(sv), 65536)
sgn(mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)))
wd(N(ov), 0); wd(N(ol), 4)
sgn(mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol))
print("D: sndbuf=" .. (rd(N(ov)) or -1))

-- Fill: send 256B chunks with MSG_DONTWAIT
print("E: filling")
local filled = 0
for i = 1, 300 do
    local ok2, ret = pcall(function()
        return mk(133)(uint64(fW), uint64(N(buf)), uint64(256), uint64(0x80))
    end)
    if not ok2 then print("  pcall fail at " .. i); break end
    local v = sgn(ret)
    if v <= 0 then print("  blocked at i=" .. i .. " filled=" .. filled); break end
    filled = filled + v
end
print("F: filled=" .. filled)

-- Shrink
wd(N(sv), 1)
pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
wd(N(ov), 0); wd(N(ol), 4)
pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
local sb = rd(N(ov)) or -1
print("G: sndbuf=" .. sb)

-- Extra write with MSG_DONTWAIT
local ok3, ret3 = pcall(function()
    return mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80))
end)
local extra = ok3 and sgn(ret3) or -999
print("H: extra64=" .. extra)
if extra > 0 then print("*** WRITE PAST HIWAT ***") end

-- Drain
local dbuf = memory.alloc(0x1000)
local drained = 0
for d = 1, 100 do
    local ok4, dr = pcall(function() return mk(3)(uint64(fR), dbuf, uint64(0x1000)) end)
    if not ok4 then break end
    local dv = sgn(dr)
    if dv <= 0 then break end
    drained = drained + dv
end
print("I: drained=" .. drained)

-- Post-drain write
local ok5, ret5 = pcall(function()
    return mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80))
end)
local post = ok5 and sgn(ret5) or -999
print("J: post_write=" .. post)

pcall(function() mk(6)(uint64(fW)) end)
pcall(function() mk(6)(uint64(fR)) end)

print("")
print("filled=" .. filled .. " sb=" .. sb .. " extra=" .. extra .. " drain=" .. drained .. " post=" .. post)
print("=== 93a8 COMPLETE ===")
