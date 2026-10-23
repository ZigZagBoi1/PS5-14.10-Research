-- CRASH_CLASS: LOW
-- PROBE 56j: Test untested syscalls 530, 531, 537
--
-- These are the PR #72 gap. All three are obs_{} (nosys) in the 13.60 CSV.
-- 532 (regmgr_call) is already fully tested (305a-309a) — skip it.
-- 537 has a 13.60 contract note: "unimplemented syscall path with signal-related side effect"
-- which is interesting even if it's nosys.
--
-- Strategy: ignore SIGSYS first so nosys doesn't kill us, then call each
-- with zeros and with real pointer args. Check for any non-trivial behavior.

print("=== PROBE 56j: UNTESTED 530/531/537 ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- ============ SECTION A: Ignore SIGSYS (signal 12) ============
print("--- A: Ignore SIGSYS ---")

local sc416 = mk(416)
local sa_buf = memory.alloc(32)
wq(sa_buf, uint64(1))
for i = 8, 28, 4 do wd(N(sa_buf) + i, 0) end
local ok, ret = pcall(function()
    return sc416(uint64(12), uint64(N(sa_buf)), uint64(0))
end)
print("  sigaction(12,SIG_IGN): ok=" .. tostring(ok) .. " ret=" .. tostring(ret and N(ret)))
if not alive() then print("DEAD after sigaction"); return end

-- ============ SECTION B: sys 530 with zeros ============
print("")
print("--- B: sys 530 (zeros) ---")

local sc530 = mk(530)
ok, ret = pcall(function()
    return sc530(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local r530z = ok and N(ret) or -999
print("  530(0,0,0,0,0,0): ok=" .. tostring(ok) .. " ret=" .. r530z)
if not alive() then print("DEAD after 530(zeros)"); return end

-- ============ SECTION C: sys 531 with zeros ============
print("")
print("--- C: sys 531 (zeros) ---")

local sc531 = mk(531)
ok, ret = pcall(function()
    return sc531(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local r531z = ok and N(ret) or -999
print("  531(0,0,0,0,0,0): ok=" .. tostring(ok) .. " ret=" .. r531z)
if not alive() then print("DEAD after 531(zeros)"); return end

-- ============ SECTION D: sys 537 with zeros ============
print("")
print("--- D: sys 537 (zeros) ---")

local sc537 = mk(537)
ok, ret = pcall(function()
    return sc537(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local r537z = ok and N(ret) or -999
print("  537(0,0,0,0,0,0): ok=" .. tostring(ok) .. " ret=" .. r537z)
if not alive() then print("DEAD after 537(zeros)"); return end

-- ============ SECTION E: sys 530 with real pointers ============
print("")
print("--- E: sys 530 with pointer args ---")

local buf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(buf) + i, 0) end

local outbuf = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do wd(N(outbuf) + i, 0) end

-- Try as (cmd, inbuf, insize, outbuf, outsize, ...)
local shapes530 = {
    {name="(buf,0x10,out,0x100,0,0)", a={uint64(N(buf)),uint64(0x10),uint64(N(outbuf)),uint64(0x100),uint64(0),uint64(0)}},
    {name="(0,buf,0x10,out,0x100,0)", a={uint64(0),uint64(N(buf)),uint64(0x10),uint64(N(outbuf)),uint64(0x100),uint64(0)}},
    {name="(1,buf,0x10,out,0x100,0)", a={uint64(1),uint64(N(buf)),uint64(0x10),uint64(N(outbuf)),uint64(0x100),uint64(0)}},
    {name="(buf,0x100,0,0,0,0)",      a={uint64(N(buf)),uint64(0x100),uint64(0),uint64(0),uint64(0),uint64(0)}},
}

for _, shape in ipairs(shapes530) do
    for i = 0, 0x1FC, 4 do wd(N(outbuf) + i, 0) end
    ok, ret = pcall(function()
        return sc530(shape.a[1], shape.a[2], shape.a[3], shape.a[4], shape.a[5], shape.a[6])
    end)
    local rv = ok and N(ret) or -999
    print("  530" .. shape.name .. ": ret=" .. rv)
    if not alive() then print("DEAD"); return end

    if rv == 0 or (rv ~= -1 and rv ~= -999) then
        print("  *** NON-TRIVIAL RETURN ***")
        local any_nonzero = false
        for off = 0, 0x3C, 4 do
            local d = rd(N(outbuf) + off)
            if d and d ~= 0 then
                any_nonzero = true
                print(string.format("    out+%02X: 0x%08X", off, d))
            end
        end
        for off = 0, 0x78, 8 do
            local q = rq(N(outbuf) + off)
            if q and is_kptr(q) then
                print(string.format("    *** KPTR at out+%02X: %s ***", off, fmt(q)))
            end
        end
        if not any_nonzero then print("    (output buffer still zero)") end
    end
end

-- ============ SECTION F: sys 531 with real pointers ============
print("")
print("--- F: sys 531 with pointer args ---")

local shapes531 = {
    {name="(buf,0x10,out,0x100,0,0)", a={uint64(N(buf)),uint64(0x10),uint64(N(outbuf)),uint64(0x100),uint64(0),uint64(0)}},
    {name="(0,buf,0x10,out,0x100,0)", a={uint64(0),uint64(N(buf)),uint64(0x10),uint64(N(outbuf)),uint64(0x100),uint64(0)}},
    {name="(1,buf,0x10,out,0x100,0)", a={uint64(1),uint64(N(buf)),uint64(0x10),uint64(N(outbuf)),uint64(0x100),uint64(0)}},
}

for _, shape in ipairs(shapes531) do
    for i = 0, 0x1FC, 4 do wd(N(outbuf) + i, 0) end
    ok, ret = pcall(function()
        return sc531(shape.a[1], shape.a[2], shape.a[3], shape.a[4], shape.a[5], shape.a[6])
    end)
    local rv = ok and N(ret) or -999
    print("  531" .. shape.name .. ": ret=" .. rv)
    if not alive() then print("DEAD"); return end

    if rv == 0 or (rv ~= -1 and rv ~= -999) then
        print("  *** NON-TRIVIAL RETURN ***")
        local any_nonzero = false
        for off = 0, 0x3C, 4 do
            local d = rd(N(outbuf) + off)
            if d and d ~= 0 then
                any_nonzero = true
                print(string.format("    out+%02X: 0x%08X", off, d))
            end
        end
        if not any_nonzero then print("    (output buffer still zero)") end
    end
end

-- ============ SECTION G: sys 537 with args ============
-- 13.60 contract: "unimplemented syscall path with signal-related side effect"
-- 0 args in 13.60. Try with signals, pids, etc.
print("")
print("--- G: sys 537 with args ---")

local shapes537 = {
    {name="(pid,0,0,0,0,0)",   a={uint64(pid),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)}},
    {name="(0,pid,0,0,0,0)",   a={uint64(0),uint64(pid),uint64(0),uint64(0),uint64(0),uint64(0)}},
    {name="(1,0,0,0,0,0)",     a={uint64(1),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)}},
    {name="(9,pid,0,0,0,0)",   a={uint64(9),uint64(pid),uint64(0),uint64(0),uint64(0),uint64(0)}},
    {name="(buf,0x40,0,0,0,0)",a={uint64(N(buf)),uint64(0x40),uint64(0),uint64(0),uint64(0),uint64(0)}},
}

for _, shape in ipairs(shapes537) do
    ok, ret = pcall(function()
        return sc537(shape.a[1], shape.a[2], shape.a[3], shape.a[4], shape.a[5], shape.a[6])
    end)
    local rv = ok and N(ret) or -999
    print("  537" .. shape.name .. ": ret=" .. rv)
    if not alive() then print("DEAD"); return end
end

-- ============ SECTION H: sys 624 delta check ============
-- Use sys 624 to see if any of these caused VM ops
print("")
print("--- H: sys 624 delta for each syscall ---")

local sc624 = mk(624)

local function get_624()
    local ok2, v = pcall(function() return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok2 then return N(v) end
    return -1
end

local base = get_624()
print("  624 baseline: " .. base)

-- 530 with zeros
pcall(function() sc530(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local d530 = get_624() - base
print("  after 530(zeros): delta=" .. d530)

base = get_624()
pcall(function() sc531(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local d531 = get_624() - base
print("  after 531(zeros): delta=" .. d531)

base = get_624()
pcall(function() sc537(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local d537 = get_624() - base
print("  after 537(zeros): delta=" .. d537)

-- ============ DONE ============
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56j COMPLETE ===")
