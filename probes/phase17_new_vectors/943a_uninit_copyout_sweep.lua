-- CRASH_CLASS: MODERATE
-- PROBE 943a: uninitialised-copyout sweep over the Sony syscalls we never read
--
-- Context: every copy-length audit so far looked at copyin (what the kernel
-- takes). The other direction has never been swept: a handler that copies a
-- fixed-size struct out of its own stack or heap without initialising all of it
-- returns kernel residue.  Poison-diff is the only way to see it: fill the
-- buffer with 0xA5, call, and count how many bytes the kernel left alone.
-- Untouched bytes inside a struct the kernel claims to fill = uninitialised
-- kernel memory, and a qword in 0xFFFF8xxx range there is a KASLR leak.
--
-- 587/592/593/649/674 were already dumped whole; 935a's sweep died before
-- reaching the rest.  This probe covers the ones never read: 596, 606, 640,
-- 649, 572, 563-566, 606 and the resource queries 671/585.
--
-- Each syscall is tried with three argument shapes; the process is sampled
-- with a getpid canary after every call so one lethal number ends the sweep
-- with a location instead of a silent truncation.

print("=== PROBE 943a: UNINITIALISED COPYOUT SWEEP ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return nil end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return nil end
    return to_num(rv)
end

local SIZE = 0x200
local buf = memory.alloc(SIZE)
local pid = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
print("[0] pid=" .. tostring(pid))

local function poison()
    for i = 0, SIZE - 1 do wb(buf + i, 0xA5) end
end

-- how many bytes stayed 0xA5, and any pointer-shaped qword
local function analyse(tag, ret)
    local untouched, ptrs, samples = 0, 0, {}
    for i = 0, SIZE - 1 do
        if rd(buf + i) == 0xA5 then untouched = untouched + 1 end
    end
    for i = 0, SIZE - 8, 8 do
        local lo, hi = rd(buf + i), rd(buf + i + 4)
        if lo and hi then
            -- big-endian qword as the loader sees it: lo is the low dword
            if hi >= 0xFFFF8000 then
                ptrs = ptrs + 1
                if #samples < 4 then
                    samples[#samples + 1] = string.format("+0x%X=%08X%08X", i, hi, lo)
                end
            end
        end
    end
    print(string.format("  %-28s ret=%-12s untouched=%3d/%d ptrs=%d %s",
        tag, tostring(ret), untouched, SIZE, ptrs, table.concat(samples, " ")))
    return untouched, ptrs
end

local CANDIDATES = { 596, 606, 640, 649, 572, 563, 564, 565, 566, 671, 585, 648 }
local SHAPES = {
    { name = "buf,size", f = function(sc) return sc(uint64(buf), uint64(SIZE)) end },
    { name = "buf",      f = function(sc) return sc(uint64(buf)) end },
    { name = "0,buf,size", f = function(sc) return sc(uint64(0), uint64(buf), uint64(SIZE)) end },
}

local worst_untouched, ptr_hits = 0, 0

for _, n in ipairs(CANDIDATES) do
    local sc = mk(n)
    print(string.format("[%d]", n))
    for _, sh in ipairs(SHAPES) do
        poison()
        local ret = call(sh.f, sc)
        local u, p = analyse(sh.name, ret)
        if ret == nil then
            print("  PCALL-FAIL (survived)")
        end
        if u > worst_untouched then worst_untouched = u end
        ptr_hits = ptr_hits + p
    end
    local canary = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    if canary ~= pid then
        print(string.format("[!] canary changed after %d: %s", n, tostring(canary)))
        break
    end
end

print("")
print(string.format("[Z] worst_untouched=%d/%d pointer_shaped_total=%d", worst_untouched, SIZE, ptr_hits))
print("=== PROBE 943a COMPLETE ===")
