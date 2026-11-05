-- CRASH_CLASS: LOW
-- PROBE 93a5: minimal sndbuf test

print("=== PROBE 93a5 ===")

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

print("step1")
local sp = memory.alloc(8)
wd(N(sp), 0); wd(N(sp) + 4, 0)
local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
local fW = rd(N(sp)) or -1
local fR = rd(N(sp) + 4) or -1
print("socketpair: r=" .. r .. " fW=" .. fW .. " fR=" .. fR)

print("step2: setsockopt")
local sv = memory.alloc(4)
wd(N(sv), 65536)
local sr = sgn(mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)))
print("setsockopt ret=" .. sr)

print("step3: getsockopt")
local ov = memory.alloc(4)
local ol = memory.alloc(4)
wd(N(ov), 0); wd(N(ol), 4)
local gr = sgn(mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol))
print("getsockopt ret=" .. gr .. " val=" .. (rd(N(ov)) or -1))

print("step4: write 64B with MSG_DONTWAIT")
local buf = memory.alloc(256)
for i = 0, 252, 4 do wd(N(buf) + i, 0x41414141) end
local wr = sgn(mk(133)(uint64(fW), uint64(N(buf)), uint64(64), uint64(0x80), uint64(0), uint64(0)))
print("sendto(64, DONTWAIT) = " .. wr)

print("step5: write 4096B")
local buf2 = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(buf2) + i, 0x42424242) end
local wr2 = sgn(mk(133)(uint64(fW), uint64(N(buf2)), uint64(4096), uint64(0x80), uint64(0), uint64(0)))
print("sendto(4096, DONTWAIT) = " .. wr2)

print("step6: use write(4) instead")
local wr3 = sgn(mk(4)(uint64(fW), uint64(N(buf2)), uint64(4096)))
print("write(4096) = " .. wr3)

print("step7: cleanup")
pcall(function() mk(6)(uint64(fW)) end)
pcall(function() mk(6)(uint64(fR)) end)

print("=== 93a5 COMPLETE ===")
