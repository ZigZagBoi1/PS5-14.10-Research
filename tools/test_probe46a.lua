-- tools/test_probe46a.lua
--
-- Offline regression harness for
--   probes/phase11_network_attacks/46a_sony_syscall_deep.lua
--
-- The probe is loaded UNMODIFIED (loadfile + setfenv) and executed inside an
-- isolated Lua 5.1 sandbox that provides:
--   * an in-memory byte store for memory.alloc/read_*/write_*
--   * a syscall shim that records/replays nothing on its own: it only calls the
--     per-case handler, which MAY mutate the sandbox memory at the real
--     invocation (no expected results are echoed)
--   * uint64/bit32/syscall.getpid minimum compatibility
--   * captured print output
--
-- Cases assert on diagnostics actually emitted by the probe.
--
-- Expected result: on the ORIGINAL probe this harness FAILS because the
-- sentinel-only check_modified flags untouched zero-filled buffers as
-- "modified" (557 pattern3 struct and the 620 struct), and because a write
-- just past the checked range is still attributed to it. Once both zero-baseline
-- callers pass an explicit zero baseline it must PASS. Sentinel-backed buffers
-- must never warn; a genuinely injected dword change inside the checked range
-- must always warn.
--
-- Run from the repository root:  lua tools/test_probe46a.lua
-- (or lupa.lua51.execute on the same file from the same CWD)

local PROBE = "probes/phase11_network_attacks/46a_sony_syscall_deep.lua"
local PID = 1000
local PTR_MIN = 0x10000000 -- allocator base; any higher arg is a pointer

local assertions, failures = 0, 0
local function check(name, cond)
    assertions = assertions + 1
    if not cond then
        failures = failures + 1
        print("FAIL: " .. name)
    end
end

local function contains(out, needle)
    for _, line in ipairs(out) do
        if string.find(line, needle, 1, true) then return true end
    end
    return false
end

-- ---------------------------------------------------------------- memory ----
local function new_mem()
    local bytes = {}
    local next_base = PTR_MIN

    local function rd(addr, n)
        local v = 0
        for i = n - 1, 0, -1 do
            v = v * 256 + (bytes[addr + i] or 0)
        end
        return v
    end
    local function wr(addr, val, n)
        val = val % (2 ^ (8 * n))
        for i = 0, n - 1 do
            bytes[addr + i] = val % 256
            val = math.floor(val / 256)
        end
    end

    local mem = {
        alloc = function(size)
            local base = next_base
            next_base = next_base + 0x10000
            return base
        end,
        read_byte = function(addr) return bytes[addr] or 0 end,
        write_byte = function(addr, val) bytes[addr] = val % 256 end,
        read_dword = function(addr) return rd(addr, 4) end,
        write_dword = function(addr, val) wr(addr, val, 4) end,
        read_qword = function(addr)
            local l, h = rd(addr, 4), rd(addr + 4, 4)
            return {
                h = h,
                l = l,
                tonumber = function() return h * 4294967296 + l end,
            }
        end,
        write_qword = function(addr, val)
            wr(addr, val, 8)
        end,
    }
    return mem
end

-- --------------------------------------------------------------- sandbox ----
local function run_sandbox(handler)
    local mem = new_mem()
    local out = {}

    local function argnum(v)
        if type(v) == "table" and v.tonumber then return v:tonumber() end
        return tonumber(v) or 0
    end

    local pipe = {}
    setmetatable(pipe, {
        __call = function(self, ...)
            local args = {}
            for i = 1, select("#", ...) do
                args[i] = argnum((select(i, ...)))
            end
            return handler(self.syscall_no, args, mem)
        end,
    })

    local function u64(v)
        v = tonumber(v) or 0
        return {
            tonumber = function() return v end,
            h = math.floor(v / 4294967296) % 4294967296,
            l = v % 4294967296,
        }
    end

    local function band(a, b)
        local r, p = 0, 1
        for _ = 1, 32 do
            if math.floor(a / p) % 2 == 1 and math.floor(b / p) % 2 == 1 then
                r = r + p
            end
            p = p * 2
        end
        return r
    end

    local env = {}
    env.print = function(...)
        local parts = {}
        for i = 1, select("#", ...) do
            parts[i] = tostring((select(i, ...)))
        end
        out[#out + 1] = table.concat(parts, "\t")
    end
    env.syscall = {
        pipe = pipe,
        getpid = function()
            return { tonumber = function() return PID end }
        end,
    }
    env.memory = mem
    env.uint64 = u64
    env.bit32 = {
        band = band,
        rshift = function(a, n) return math.floor(a / 2 ^ n) % 4294967296 end,
    }
    setmetatable(env, { __index = _G })

    local chunk, lerr = loadfile(PROBE)
    if not chunk then error("cannot load probe: " .. tostring(lerr)) end
    setfenv(chunk, env)
    local ok, rerr = pcall(chunk)
    if not ok then error("probe execution failed: " .. tostring(rerr)) end
    return out
end

-- Invocation predicates: identify the consumer-visible patterns by the
-- arguments the probe actually passes.
--   zero-baseline pattern3: 557(0, st)   -> struct checked at st+4, len 0x50
--   sentinel buffer:        557(pid, buf)-> buffer checked at buf, len 0x100
--   620 struct:             620(st)      -> struct checked at st+4, len 0x50
local function is_zero_struct(sc_no, args)
    return sc_no == 557 and #args == 2 and args[1] == 0 and args[2] >= PTR_MIN
end
local function is_sentinel_buf(sc_no, args)
    return sc_no == 557 and #args == 2 and args[1] == PID and args[2] >= PTR_MIN
end
local function is_620_struct(sc_no, args)
    return sc_no == 620 and #args == 1 and args[1] >= PTR_MIN
end

-- ------------------------------------------------------------- test cases ---
local ZERO_WARN = "struct modified after offset 4!"

-- 1) No syscall writes at all: neither unchanged zero-baseline struct (557
--    pattern3 and the 620 struct) nor the untouched sentinel buffers may be
--    reported as modified.
local out = run_sandbox(function() return -1 end)
check("nowrite: zero-baseline pattern3 not reported", not contains(out, ZERO_WARN))
check("nowrite: 620 zero struct not reported", not contains(out, "620 struct:"))
check("nowrite: sentinel buffers not reported", not contains(out, "BUFFER MODIFIED"))

-- 2) A real dword change inside the sentinel buffer's checked range must warn.
out = run_sandbox(function(sc_no, args, mem)
    if is_sentinel_buf(sc_no, args) then mem.write_dword(args[2], 0xCAFEBABE) end
    return -1
end)
check("sentinel inject: first checked dword detected",
    contains(out, "*** BUFFER MODIFIED (pid,buf)! ***"))

-- 3) A real dword change at the first checked offset of the zero-baseline
--    struct must warn.
out = run_sandbox(function(sc_no, args, mem)
    if is_zero_struct(sc_no, args) then mem.write_dword(args[2] + 4, 0x12345678) end
    return -1
end)
check("zero inject first offset: detected", contains(out, ZERO_WARN))

-- 4) A change one dword past the last checked offset (st+0x54) is outside the
--    range [st+4, st+0x50] and must NOT warn.
out = run_sandbox(function(sc_no, args, mem)
    if is_zero_struct(sc_no, args) then mem.write_dword(args[2] + 4 + 0x50, 0x12345678) end
    return -1
end)
check("zero inject just outside range: not reported", not contains(out, ZERO_WARN))

-- 5) A real dword change at the last checked offset (st+0x50) must warn.
out = run_sandbox(function(sc_no, args, mem)
    if is_zero_struct(sc_no, args) then mem.write_dword(args[2] + 4 + 0x4C, 0x12345678) end
    return -1
end)
check("zero inject last offset: detected", contains(out, ZERO_WARN))

-- 6) A real dword change at the first checked offset of the 620 zero-baseline
--    struct must emit the actual dump.
out = run_sandbox(function(sc_no, args, mem)
    if is_620_struct(sc_no, args) then mem.write_dword(args[1] + 4, 0x12345678) end
    return -1
end)
check("620 inject first offset: dump detected", contains(out, "620 struct:"))

-- ------------------------------------------------------------------ report --
print(string.format("test_probe46a: %d assertions, %d failures", assertions, failures))
if failures > 0 then
    error(string.format("probe46a regression: %d/%d assertion(s) failed", failures, assertions))
end
print("test_probe46a: OK")
