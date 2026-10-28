-- CRASH_CLASS: LOW
-- PROBE 553d: Deep investigation of libkernel functions (D+E from 553c)
--
-- 553c Sections D/E were cut off by 0x1CE80 binary output.
-- This probe: Sony error funcs with real args + getter deep dump.
-- 0x1CE80 tested LAST (or skipped).

print("=== PROBE 553d: Deep libkernel investigation ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid
end

local sa_buf = memory.alloc(0x20)
pcall(function() memory.write_qword(N(sa_buf), uint64(1)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

local outbuf = memory.alloc(0x200)

-- ============ A: lk+0x02E10 getter full dump ============
print("")
print("=== A: lk+0x02E10 getter deep dump ===")
if alive() then
    local fn = lk + uint64(0x02E10)
    local ok_e, rv_e = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    if ok_e and rv_e and alive() then
        local rv_off = N(rv_e) - N(lk)
        print(string.format("  ptr: %s (lk+0x%X)", fmt(rv_e), rv_off))
        for i = 0, 0xF8, 8 do
            local v = rq(N(rv_e) + i)
            if v then
                print(string.format("    [+0x%02X]: %s", i, fmt(v)))
            end
        end
    end
end

-- ============ B: lk+0x153C0 investigation ============
print("")
print("=== B: lk+0x153C0 (returned ~5M value) ===")
if alive() then
    local fn = lk + uint64(0x153C0)

    -- Call with different args
    local tests = {
        {args = {0, 0, 0, 0, 0, 0}, desc = "zeros"},
        {args = {1, 0, 0, 0, 0, 0}, desc = "arg1=1"},
        {args = {0, 1, 0, 0, 0, 0}, desc = "arg2=1"},
    }

    for _, t in ipairs(tests) do
        if not alive() then break end
        local a = t.args
        local ok_t, rv_t = pcall(function()
            return native.fcall_with_rax(fn, 0,
                uint64(a[1]), uint64(a[2]), uint64(a[3]),
                uint64(a[4]), uint64(a[5]), uint64(a[6]))
        end)
        if alive() then
            print(string.format("  %s: %s", t.desc, ok_t and fmt(rv_t) or "crash"))
        else
            print(string.format("  %s: KILLED", t.desc))
        end
    end

    -- Call twice quickly to see if return value changes (timer?)
    if alive() then
        local ok1, r1 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                uint64(0), uint64(0), uint64(0),
                uint64(0), uint64(0), uint64(0))
        end)
        local ok2, r2 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                uint64(0), uint64(0), uint64(0),
                uint64(0), uint64(0), uint64(0))
        end)
        if ok1 and ok2 then
            print(string.format("  quick pair: %s then %s %s",
                fmt(r1), fmt(r2),
                fmt(r1) == fmt(r2) and "(SAME)" or "(DIFFERENT — counter/timer)"))
        end
    end
end

-- ============ C: Sony error funcs with real args ============
print("")
print("=== C: Error funcs with real args ===")

-- 0x1CDA0 returned EINVAL/EFAULT. Try various patterns.
if alive() then
    local fn = lk + uint64(0x1CDA0)
    local tests = {
        -- (pid, 0, buf, size) — could be process query
        {a = {pid, 0, N(outbuf), 0x100, 0, 0}, d = "(pid,0,buf,0x100)"},
        -- (0, pid, buf, size) — alternate pid position
        {a = {0, pid, N(outbuf), 0x100, 0, 0}, d = "(0,pid,buf,0x100)"},
        -- (1, 0, 0, 0) — simple flag
        {a = {1, 0, 0, 0, 0, 0}, d = "(1,0,0,0)"},
        -- (buf, size) — simple buffer
        {a = {N(outbuf), 0x100, 0, 0, 0, 0}, d = "(buf,0x100)"},
    }
    print("  0x1CDA0:")
    for _, t in ipairs(tests) do
        if not alive() then break end
        for i = 0, 0x7C, 4 do wd(N(outbuf) + i, 0) end
        local ok_t, rv_t = pcall(function()
            return native.fcall_with_rax(fn, 0,
                uint64(t.a[1]), uint64(t.a[2]), uint64(t.a[3]),
                uint64(t.a[4]), uint64(t.a[5]), uint64(t.a[6]))
        end)
        if alive() then
            local rvs = ok_t and fmt(rv_t) or "crash"
            -- Check if buffer was written
            local buf_written = false
            for i = 0, 0x3C, 8 do
                local v = rq(N(outbuf) + i)
                if v then
                    local h, l = get_hi_lo(v)
                    if h < 0 then h = h + 0x100000000 end
                    if l < 0 then l = l + 0x100000000 end
                    if h ~= 0 or l ~= 0 then buf_written = true end
                end
            end
            print(string.format("    %s: %s %s", t.d, rvs,
                buf_written and "DATA!" or ""))
        end
    end
end

-- 0x16BB0 — try mmap-like args
if alive() then
    local fn = lk + uint64(0x16BB0)
    local tests = {
        {a = {0, 0x4000, 3, 0, 0, 0}, d = "(0,0x4000,3,0,0,0)"},
        {a = {0, 0x4000, 1, 0x1002, 0xFFFFFFFF, 0}, d = "(0,0x4000,1,MAP_ANON,-1,0)"},
        {a = {N(outbuf), 0x100, 0, 0, 0, 0}, d = "(buf,0x100)"},
    }
    print("  0x16BB0:")
    for _, t in ipairs(tests) do
        if not alive() then break end
        local ok_t, rv_t = pcall(function()
            return native.fcall_with_rax(fn, 0,
                uint64(t.a[1]), uint64(t.a[2]), uint64(t.a[3]),
                uint64(t.a[4]), uint64(t.a[5]), uint64(t.a[6]))
        end)
        if alive() then
            print(string.format("    %s: %s", t.d, ok_t and fmt(rv_t) or "crash"))
        end
    end
end

-- ============ D: ReleaseDirectMemory lifecycle ============
print("")
print("=== D: Release lifecycle: alloc → release → mmap still works? ===")
if alive() then
    local alloc_fn = lk + uint64(0x17EF0)
    local release_fn = lk + uint64(0x18360)
    local sc_mmap = mk(477)
    local sc_munmap = mk(73)

    -- Open dmem0
    local devpath = memory.alloc(32)
    local path = "/dev/dmem0"
    for i = 1, #path do wd(N(devpath) + i - 1, string.byte(path, i)) end
    wd(N(devpath) + #path, 0)
    local ok_o, fd_raw = pcall(function()
        return mk(5)(uint64(N(devpath)), uint64(2), uint64(0))
    end)
    local dmem_fd = ok_o and N(fd_raw) or -1
    print(string.format("  dmem0 fd: %d", dmem_fd))

    -- Allocate
    local phys_out = memory.alloc(16)
    wq(N(phys_out), uint64(0))
    local ok_a, rv_a = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64("0x150000000"),
            uint64(0x4000), uint64(0x4000),
            uint64(0), uint64(N(phys_out)))
    end)
    local phys = rq(N(phys_out))
    print(string.format("  alloc: rv=%d phys=%s", ok_a and N(rv_a) or -1, fmt(phys)))

    -- mmap the allocated physical address
    if ok_a and N(rv_a) == 0 and phys then
        local ok_m, map = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(dmem_fd), phys)
        end)
        if ok_m and map then
            local map_base = N(map)
            print(string.format("  mmap: %s", fmt(map)))

            -- Write marker
            wq(map_base, uint64("0xDEADBEEFCAFEBABE"))
            local check1 = rq(map_base)
            print(string.format("  write+read: %s", fmt(check1)))

            -- Release the physical memory
            local ok_r, rv_r = pcall(function()
                return native.fcall_with_rax(release_fn, 0,
                    phys, uint64(0x4000),
                    uint64(0), uint64(0), uint64(0), uint64(0))
            end)
            print(string.format("  release: rv=%d", ok_r and N(rv_r) or -1))

            -- Can we still read through the mmap?
            if alive() then
                local check2 = rq(map_base)
                if check2 then
                    print(string.format("  post-release read: %s %s",
                        fmt(check2),
                        fmt(check2) == fmt(check1) and "(MARKER INTACT)" or "(CHANGED!)"))
                else
                    print("  post-release read: FAILED (unmapped)")
                end
            end

            pcall(function() sc_munmap(map, uint64(0x4000)) end)
        end
    end
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
