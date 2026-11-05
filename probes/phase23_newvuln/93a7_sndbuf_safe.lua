-- CRASH_CLASS: LOW
-- PROBE 93a7: SO_SNDBUF fill+shrink — safe version with pcall

print("=== PROBE 93a7 ===")

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

print("A")
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Ignore SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)
print("B")

local sv = memory.alloc(4)
local ov = memory.alloc(4)
local ol = memory.alloc(4)

-- Use a small fill buffer — just 256 bytes, avoid big alloc
local buf = memory.alloc(256)
for i = 0, 252, 4 do wd(N(buf) + i, 0x41414141) end
print("C")

-- socketpair
local sp = memory.alloc(8)
wd(N(sp), 0); wd(N(sp) + 4, 0)
local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
local fW = rd(N(sp)) or -1
local fR = rd(N(sp) + 4) or -1
print("sp r=" .. r .. " fW=" .. fW .. " fR=" .. fR)

-- set sndbuf=65536
wd(N(sv), 65536)
local sr = sgn(mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)))
print("set=" .. sr)

-- read back
wd(N(ov), 0); wd(N(ol), 4)
sgn(mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol))
print("sndbuf=" .. (rd(N(ov)) or -1))

-- fill with small chunks, 4 args, pcall each
print("FILL:")
local filled = 0
for i = 1, 300 do
    local ok2, ret = pcall(function()
        return mk(133)(uint64(fW), uint64(N(buf)), uint64(256), uint64(0x80))
    end)
    local v = ok2 and sgn(ret) or -999
    if v <= 0 then
        print("  stop at i=" .. i .. " ret=" .. v .. " filled=" .. filled)
        break
    end
    filled = filled + v
    if i <= 3 or i % 50 == 0 then
        print("  i=" .. i .. " +=" .. v .. " total=" .. filled)
    end
end
print("filled=" .. filled)

-- shrink to 1
wd(N(sv), 1)
pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
wd(N(ov), 0); wd(N(ol), 4)
pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
local post_sb = rd(N(ov)) or -1
print("sndbuf_after=" .. post_sb)

-- try more writes with MSG_DONTWAIT
local e1_ok, e1_r = pcall(function()
    return mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80))
end)
local e1 = e1_ok and sgn(e1_r) or -999
print("extra64=" .. e1)

-- drain
local dbuf = memory.alloc(0x1000)
local drained = 0
for d = 1, 100 do
    local dok, dr = pcall(function()
        return mk(3)(uint64(fR), dbuf, uint64(0x1000))
    end)
    local dv = dok and sgn(dr) or -999
    if dv <= 0 then break end
    drained = drained + dv
end
print("drained=" .. drained)

-- post-drain write
local p1_ok, p1_r = pcall(function()
    return mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80))
end)
local p1 = p1_ok and sgn(p1_r) or -999
print("post_drain_write64=" .. p1)

pcall(function() mk(6)(uint64(fW)) end)
pcall(function() mk(6)(uint64(fR)) end)

print("")
print("SUMMARY: filled=" .. filled .. " sb=" .. post_sb .. " extra=" .. e1 .. " drained=" .. drained .. " post=" .. p1)
if e1 > 0 then print("*** WRITE PAST HIWAT ***") end
if p1 > 0 and post_sb < 64 then print("*** POST-DRAIN WRITE WITH TINY HIWAT ***") end
print("=== 93a7 COMPLETE ===")
