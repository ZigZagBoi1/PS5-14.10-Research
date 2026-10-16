-- 14.10 Probe 42a: ktimer deep dive (new attack surface from probe 38)
-- ktimer_create WORKS (timerid 3 returned). POSIX timers are kernel
-- objects with alloc/arm/disarm/delete lifecycle and signal delivery.
-- Historically buggy in BSD: itimerspec validation, clock id handling,
-- timer id reuse, overrun counting. No threads needed for any of this.

print("=== 42a: KTIMER DEEP ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_ktimer_create = 235,
    sc_ktimer_settime = 236,
    sc_ktimer_gettime = 238,
    sc_ktimer_delete = 237,
    sc_ktimer_getoverrun = 239,
    sc_sigaction = 416,
})

local sevp = memory.alloc(64)
local tid = memory.alloc(8)
local its = memory.alloc(16)   -- itimerspec: 2x timespec = 4 qwords
local its2 = memory.alloc(16)

local function report(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then
        print(tag .. ": PCALL ERR")
    elseif rv == nil then
        print(tag .. ": nil")
    else
        local okn, n = pcall(function() return rv:tonumber() end)
        print(tag .. ": rv=" .. (okn and tostring(n) or tostring(rv)))
    end
end

local function zero(b, n) for i = 0, n - 1, 8 do memory.write_qword(b + i, 0) end end

-- ---------------------------------------------------------------
-- PART 1: clock id sweep (0..15) — which clocks does the sandbox allow?
-- ---------------------------------------------------------------
print("")
print("--- PART 1: clock id sweep ---")
local clock_ok = {}
for clk = 0, 15 do
    zero(sevp, 64)                        -- sigev_notify = 0 (SIGEV_NONE)
    memory.write_qword(tid, 0xFFFFFFFFFFFFFFFF)
    local ok, rv = pcall(function()
        return syscall.sc_ktimer_create(clk, sevp, tid)
    end)
    local r = ok and rv:tonumber() or -999
    local id = memory.read_dword(tid):tonumber()
    print(string.format("clock %2d: rv=%d timerid=%d", clk, r, id))
    if r == 0 then
        table.insert(clock_ok, { clk = clk, id = id })
    end
end
print("usable clocks: " .. #clock_ok)

-- ---------------------------------------------------------------
-- PART 2: itimerspec validation games on the first working timer
-- ---------------------------------------------------------------
print("")
print("--- PART 2: itimerspec validation ---")
if #clock_ok == 0 then
    print("no working timer — skipping")
else
    local t = clock_ok[1].id

    -- normal arm: 1s one-shot
    zero(its, 16)
    memory.write_qword(its + 8, 1)        -- it_value.tv_sec = 1
    report("settime(1s oneshot)", function()
        return syscall.sc_ktimer_settime(t, 0, its, its2)
    end)
    report("gettime", function() return syscall.sc_ktimer_gettime(t, its2) end)
    print(string.format("  remaining: sec=%d nsec=%d",
        memory.read_qword(its2 + 8):tonumber(), memory.read_qword(its2):tonumber()))

    -- nsec > 1e9 (validation bug check)
    zero(its, 16)
    memory.write_qword(its + 8, 0)        -- sec = 0
    memory.write_qword(its, 0xFFFFFFFF)   -- nsec = 4G (invalid, >1e9)
    report("settime(nsec=4G)", function()
        return syscall.sc_ktimer_settime(t, 0, its, its2)
    end)

    -- negative nsec
    zero(its, 16)
    memory.write_qword(its, 0xFFFFFFFFFFFFFFFF)  -- nsec = -1
    memory.write_qword(its + 8, 1)
    report("settime(nsec=-1)", function()
        return syscall.sc_ktimer_settime(t, 0, its, its2)
    end)

    -- huge interval (wrap games)
    zero(its, 16)
    memory.write_qword(its + 8, 0x7FFFFFFFFFFFFFFF)  -- it_value sec = huge
    report("settime(sec=2^63-1)", function()
        return syscall.sc_ktimer_settime(t, 0, its, its2)
    end)

    -- disarm
    zero(its, 16)
    report("disarm", function() return syscall.sc_ktimer_settime(t, 0, its, its2) end)
end

-- ---------------------------------------------------------------
-- PART 3: timer id abuse
-- ---------------------------------------------------------------
print("")
print("--- PART 3: id abuse ---")
report("gettime(id=0)", function() return syscall.sc_ktimer_gettime(0, its2) end)
report("gettime(id=-1)", function() return syscall.sc_ktimer_gettime(-1, its2) end)
report("gettime(id=0x7fffffff)", function() return syscall.sc_ktimer_gettime(0x7FFFFFFF, its2) end)
report("delete(id=0)", function() return syscall.sc_ktimer_delete(0) end)
report("delete(id=-1)", function() return syscall.sc_ktimer_delete(-1) end)

-- delete a real timer twice (double-delete / id reuse)
if #clock_ok > 0 then
    local t = clock_ok[1].id
    report("delete(real) #1", function() return syscall.sc_ktimer_delete(t) end)
    report("delete(real) #2", function() return syscall.sc_ktimer_delete(t) end)
    -- create again: do we get the same id back?
    zero(sevp, 64)
    memory.write_qword(tid, 0xFFFFFFFF)
    report("create after delete", function() return syscall.sc_ktimer_create(0, sevp, tid) end)
    print("  new timerid: " .. memory.read_dword(tid):tonumber())
end

-- ---------------------------------------------------------------
-- PART 4: exhaustion — how many timers can we create?
-- ---------------------------------------------------------------
print("")
print("--- PART 4: create exhaustion (cap at 64) ---")
local made = 0
for i = 1, 64 do
    zero(sevp, 64)
    memory.write_qword(tid, 0xFFFFFFFF)
    local ok, rv = pcall(function() return syscall.sc_ktimer_create(0, sevp, tid) end)
    if not ok or rv:tonumber() ~= 0 then
        print("stopped at i=" .. i .. " rv=" .. (ok and rv:tonumber() or -999))
        break
    end
    made = made + 1
end
print("timers created: " .. made)

-- ---------------------------------------------------------------
-- PART 5: getoverrun
-- ---------------------------------------------------------------
print("")
print("--- PART 5: getoverrun ---")
report("getoverrun(id=0)", function() return syscall.sc_ktimer_getoverrun(0) end)
if #clock_ok > 1 then
    report("getoverrun(real)", function() return syscall.sc_ktimer_getoverrun(clock_ok[2].id) end)
end

print("=== 42a DONE ===")
