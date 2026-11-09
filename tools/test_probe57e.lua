-- tools/test_probe57e.lua
--
-- Offline regression harness for
--   probes/phase15_native_sysent/57e_kldsym_hardened.lua
--
-- The probe is loaded UNMODIFIED (loadfile + setfenv) and executed inside an
-- isolated Lua 5.1 sandbox that provides:
--   * an in-memory byte store for memory.alloc/read_*/write_*; the allocator
--     starts at 0x10000000 and advances 0x10000 per call, so it never returns 0
--   * a syscall shim (metatable __call, numeric argument coercion, syscall.pipe,
--     syscall.getpid) keyed by syscall number: 20 = getpid, 337 = kldsym. The
--     shim itself replays nothing; the per-case handler decides the response and
--     MAY mutate sandbox memory at the real invocation
--   * uint64/bit32/syscall.getpid minimum compatibility plus a _G fallback
--   * captured print output
--
-- The cases assert on diagnostics actually emitted by the probe (echo rows,
-- errno names, RESOLVED verdicts, SUMMARY counts, section/DONE markers), and on
-- the invocation shape (337 arity, cmd, size field, name pointer, symbol bytes)
-- the shim observed. No expected probe output is fed back to the probe: the
-- handler only writes what a kernel response would write.
--
-- Sections covered:
--   [A] setup: banner, PID echo
--   [B] fileid=0: six symbols, echo row then lookup
--   [C] fileid=1: the same six symbols, echo row then lookup
--   [D] SUMMARY counters and DONE marker
--
-- Expected result: PASS on the committed probe. It fails if the single-byte
-- string path, the per-call echo row, the kernel-band verdict, the errno
-- decoding, the refused/unverified counters, or the section/DONE markers
-- regress.
--
-- Run from the repository root:  lua tools/test_probe57e.lua
-- (or lupa.lua51.execute on the same file from the same CWD)

local PROBE = "probes/phase15_native_sysent/57e_kldsym_hardened.lua"
local PID = 1000
local PTR_MIN = 0x10000000 -- allocator base; any higher arg is a pointer
local SYSCALL_KLD = 337
local SYSCALL_GETPID = 20
local LOOKUP_SIZE = 0x20

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

local function count(out, needle)
    local n = 0
    for _, line in ipairs(out) do
        if string.find(line, needle, 1, true) then n = n + 1 end
    end
    return n
end

local function same_list(a, b)
    if #a ~= #b then return false end
    for i = 1, #a do
        if a[i] ~= b[i] then return false end
    end
    return true
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
    -- The probe hands uint64 tables to write_qword (+0x08 name pointer), so a
    -- table carrying :tonumber() is accepted alongside plain numbers.
    local function asnum(v)
        if type(v) == "table" and v.tonumber then return v:tonumber() end
        return tonumber(v) or 0
    end
    local function wr(addr, val, n)
        val = asnum(val) % (2 ^ (8 * n))
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

local function read_cstr(mem, addr, max)
    local parts = {}
    for i = 0, (max or 64) - 1 do
        local b = mem.read_byte(addr + i)
        if b == 0 then break end
        parts[#parts + 1] = string.char(b)
    end
    return table.concat(parts)
end

-- --------------------------------------------------------------- sandbox ----
-- `setup`, when supplied, runs after the environment is built and before the
-- probe chunk: cases use it to make a memory primitive fail.
local function run_sandbox(handler, setup)
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
        bor = function(a, b) return a + b - band(a, b) end,
        bxor = function(a, b) return a + b - 2 * band(a, b) end,
        rshift = function(a, n) return math.floor(a / 2 ^ n) % 4294967296 end,
        lshift = function(a, n) return (a * 2 ^ n) % 4294967296 end,
    }
    setmetatable(env, { __index = _G })

    if setup then setup(env, mem) end

    local chunk, lerr = loadfile(PROBE)
    if not chunk then error("cannot load probe: " .. tostring(lerr)) end
    setfenv(chunk, env)
    local ok, rerr = pcall(chunk)
    if not ok then error("probe execution failed: " .. tostring(rerr)) end
    return out
end

-- ------------------------------------------------------------ observation ---
local obs = { calls = {} }

-- ------------------------------------------------------------- handlers -----
-- Symbols the probe looks up, in probe order, in both sections.
local SYMBOLS = {
    "prison0",
    "allproc",
    "kernel_pmap",
    "copyout",
    "copyin",
    "sysent",
}
local KERN_HI = 0xFFFF8000
local KERN_LO = 0xDEADBEEF
local SYM_SIZE = 0x40

-- Every handler records the invocation shape, reading the lookup struct the
-- probe built at the pointer it passed. +0x00 = size, +0x08 = name pointer.
local function record_call(args, mem)
    local rec = {
        nargs = #args,
        fileid = args[1] or 0,
        cmd = args[2] or 0,
        lookup = args[3] or 0,
    }
    rec.size = mem.read_dword(rec.lookup)
    rec.name_ptr = mem.read_dword(rec.lookup + 0x08)
    rec.name = read_cstr(mem, rec.name_ptr)
    obs.calls[#obs.calls + 1] = rec
    return rec
end

-- Writes a kernel-band qword pair at +0x10/+0x18 using dwords so no value
-- above 2^53 is ever handed to the float-backed store.
local function write_kernel_value(mem, lookup, hi, lo, sh, sl)
    mem.write_dword(lookup + 0x10, lo)
    mem.write_dword(lookup + 0x14, hi)
    mem.write_dword(lookup + 0x18, sl)
    mem.write_dword(lookup + 0x1C, sh)
end

-- case 1: fid=0 resolves every symbol, fid=1 is refused ENOENT.
local function handler_upstream(sc_no, args, mem)
    if sc_no == SYSCALL_GETPID then return PID end
    if sc_no ~= SYSCALL_KLD then return -1 end
    local rec = record_call(args, mem)
    if rec.fileid == 0 then
        write_kernel_value(mem, rec.lookup, KERN_HI, KERN_LO, 0, SYM_SIZE)
        return 0
    end
    return -2
end

-- case 2: every call refused, cycling EINVAL / EPERM / unmapped errno.
local function handler_refused(sc_no, args, mem)
    if sc_no == SYSCALL_GETPID then return PID end
    if sc_no ~= SYSCALL_KLD then return -1 end
    record_call(args, mem)
    local n = #obs.calls
    if n % 3 == 1 then return -22 end -- EINVAL
    if n % 3 == 2 then return -1 end -- EPERM
    return -999 -- no errno.h entry
end

-- case 3: success, but the value is the all-ones sentinel.
local function handler_sentinel(sc_no, args, mem)
    if sc_no == SYSCALL_GETPID then return PID end
    if sc_no ~= SYSCALL_KLD then return -1 end
    local rec = record_call(args, mem)
    write_kernel_value(mem, rec.lookup, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF)
    return 0
end

-- case 4: the call raises inside pcall.
local function handler_raise(sc_no, args, mem)
    if sc_no == SYSCALL_GETPID then return PID end
    if sc_no ~= SYSCALL_KLD then return -1 end
    record_call(args, mem)
    error("kldsym call raised in sandbox")
end

local function reset_obs() obs.calls = {} end

-- Expected name/fid sequence: both sections walk the same symbol table.
local EXPECTED_SEQ = {}
for _, fid in ipairs({ 0, 1 }) do
    for _, sym in ipairs(SYMBOLS) do
        EXPECTED_SEQ[#EXPECTED_SEQ + 1] = sym .. ":" .. fid
    end
end

local function observed_seq()
    local seq = {}
    for i, rec in ipairs(obs.calls) do
        seq[i] = rec.name .. ":" .. rec.fileid
    end
    return seq
end

-- ------------------------------------------ case 1: fid=0 resolves, fid=1 no --
reset_obs()
local out = run_sandbox(handler_upstream)

check("setup: banner emitted",
    contains(out, "=== PROBE 57e: HARDENED kldsym(337) ==="))
check("setup: [A] section header", contains(out, "[A] Setup"))
check("setup: PID echoed", contains(out, "PID: " .. PID))

check("shape: twelve 337 invocations (6 symbols x 2 fileids)",
    #obs.calls == 12)
check("shape: every 337 invocation passes three arguments",
    #obs.calls == 12 and (function()
        for _, c in ipairs(obs.calls) do if c.nargs ~= 3 then return false end end
        return true
    end)())
check("shape: cmd=KLDSYM_LOOKUP (1) on every invocation",
    (function()
        for _, c in ipairs(obs.calls) do if c.cmd ~= 1 then return false end end
        return #obs.calls == 12
    end)())
check("shape: lookup struct size field is 0x20 on every invocation",
    (function()
        for _, c in ipairs(obs.calls) do
            if c.size ~= LOOKUP_SIZE then return false end
        end
        return #obs.calls == 12
    end)())
check("shape: lookup pointer is an allocator pointer on every invocation",
    (function()
        for _, c in ipairs(obs.calls) do
            if c.lookup < PTR_MIN then return false end
        end
        return #obs.calls == 12
    end)())
check("shape: name pointer is an allocator pointer on every invocation",
    (function()
        for _, c in ipairs(obs.calls) do
            if c.name_ptr < PTR_MIN then return false end
        end
        return #obs.calls == 12
    end)())
check("shape: kernel received the six symbol names in probe order, both fileids",
    same_list(observed_seq(), EXPECTED_SEQ))

check("echo: prison0 fid=0 attributes the row to cmd=1/version=0x20 and its first dword",
    contains(out, "  [prison0 fid=0] echo: cmd=1 version=0x20 sym[0:4]=73697270"))
check("echo: sysent fid=1 attributes its own row",
    contains(out, "  [sysent fid=1] echo: cmd=1 version=0x20 sym[0:4]=65737973"))
check("echo: one row per invocation (12)", count(out, "] echo: cmd=1") == 12)

check("lookup: fid=0 prison0 prints RESOLVED with the kernel-band value",
    contains(out, "  [prison0 fid=0] RESOLVED: 0xFFFF8000_DEADBEEF "
        .. "size=0x00000000_00000040 *** KASLR DEFEATED ***"))
check("lookup: all six fid=0 symbols print KASLR DEFEATED",
    count(out, "*** KASLR DEFEATED ***") == 6)
check("lookup: no sentinel verdict on the in-band case",
    not contains(out, "outside kernel band"))

check("refused: fid=1 decodes ENOENT from rv=-2",
    contains(out, "  [prison0 fid=1] refused: rv=-2 (ENOENT)"))
check("refused: all six fid=1 symbols are refused",
    count(out, "refused: rv=-2 (ENOENT)") == 6)
check("refused: no RESOLVED row for fileid=1",
    not contains(out, "[prison0 fid=1] RESOLVED"))

check("section B: fileid=0 header", contains(out, "[B] fileid=0"))
check("section C: fileid=1 header", contains(out, "[C] fileid=1"))
check("section B: COMPLETE marker", contains(out, "[B] COMPLETE"))
check("section C: COMPLETE marker", contains(out, "[C] COMPLETE"))
check("summary: resolved=6 refused=6 unverified=0",
    contains(out, "[D] SUMMARY: resolved=6 refused=6 unverified=0"))
check("section D: COMPLETE marker", contains(out, "[D] COMPLETE"))
check("probe: DONE marker emitted", contains(out, "=== 57e DONE ==="))

-- -------------------------------------- case 2: every call refused, errnos ---
reset_obs()
out = run_sandbox(handler_refused)

check("refused2: EINVAL row emitted", contains(out, "refused: rv=-22 (EINVAL)"))
check("refused2: EPERM row emitted", contains(out, "refused: rv=-1 (EPERM)"))
check("refused2: unmapped errno falls back to the numeric form",
    contains(out, "refused: rv=-999 (errno 999)"))
check("refused2: twelve refusals, four of each shape",
    count(out, "refused: rv=-22 (EINVAL)") == 4
    and count(out, "refused: rv=-1 (EPERM)") == 4
    and count(out, "refused: rv=-999 (errno 999)") == 4)
check("refused2: summary counts all twelve refusals",
    contains(out, "[D] SUMMARY: resolved=0 refused=12 unverified=0"))
check("refused2: no RESOLVED or sentinel verdict",
    not contains(out, "RESOLVED") and not contains(out, "outside kernel band"))
check("refused2: echo rows still precede every refusal",
    count(out, "] echo: cmd=1") == 12)
check("refused2: completion and DONE markers",
    contains(out, "[B] COMPLETE") and contains(out, "[C] COMPLETE")
    and contains(out, "[D] COMPLETE") and contains(out, "=== 57e DONE ==="))

-- ----------------------------- case 3: string path unverifiable -> skipped ---
-- write_byte raises, so write_str_verified() returns nil for every symbol: no
-- echo row, no syscall, and the SUMMARY must attribute all twelve to unverified.
reset_obs()
out = run_sandbox(handler_upstream, function(env, mem)
    mem.write_byte = function() error("write_byte denied by sandbox") end
end)

check("unverified: prison0 fid=0 reported as skipped",
    contains(out, "  [prison0 fid=0] STRING WRITE UNVERIFIED"))
check("unverified: sysent fid=1 reported as skipped",
    contains(out, "  [sysent fid=1] STRING WRITE UNVERIFIED"))
check("unverified: twelve skip rows", count(out, "STRING WRITE UNVERIFIED") == 12)
check("unverified: no echo row reaches the kernel",
    not contains(out, "] echo: cmd=1") and #obs.calls == 0)
check("unverified: summary counts all twelve",
    contains(out, "[D] SUMMARY: resolved=0 refused=0 unverified=12"))
check("unverified: completion and DONE markers",
    contains(out, "[B] COMPLETE") and contains(out, "[C] COMPLETE")
    and contains(out, "[D] COMPLETE") and contains(out, "=== 57e DONE ==="))

-- ------------------------------- case 4: the call raises inside the pcall ---
reset_obs()
out = run_sandbox(handler_raise)

check("pcallfail: raised call reported per symbol",
    contains(out, "  [prison0 fid=0] PCALL-FAIL (call raised)"))
check("pcallfail: twelve PCALL-FAIL rows", count(out, "PCALL-FAIL") == 12)
check("pcallfail: no verdict is attributed to a raised call",
    not contains(out, "RESOLVED") and not contains(out, "refused:"))
check("pcallfail: summary stays all-zero",
    contains(out, "[D] SUMMARY: resolved=0 refused=0 unverified=0"))
check("pcallfail: probe still completes and prints DONE",
    contains(out, "[B] COMPLETE") and contains(out, "[C] COMPLETE")
    and contains(out, "[D] COMPLETE") and contains(out, "=== 57e DONE ==="))

-- ------------------------ case 5: ret=0 with the all-ones sentinel value ----
reset_obs()
out = run_sandbox(handler_sentinel)

check("sentinel: all-ones value does not print as KASLR DEFEATED",
    not contains(out, "*** KASLR DEFEATED ***"))
check("sentinel: value reported outside the kernel band",
    contains(out, "  [prison0 fid=0] ret=0 but value=0xFFFFFFFF_FFFFFFFF "
        .. "outside kernel band (sentinel?)"))
check("sentinel: twelve out-of-band verdicts",
    count(out, "outside kernel band (sentinel?)") == 12)
check("sentinel: summary counts no resolution",
    contains(out, "[D] SUMMARY: resolved=0 refused=0 unverified=0"))
check("sentinel: echo rows still emitted",
    count(out, "] echo: cmd=1") == 12)
check("sentinel: completion and DONE markers",
    contains(out, "[B] COMPLETE") and contains(out, "[C] COMPLETE")
    and contains(out, "[D] COMPLETE") and contains(out, "=== 57e DONE ==="))

-- ------------------------------------------------------------------ report --
print(string.format("test_probe57e: %d assertions, %d failures", assertions, failures))
if failures > 0 then
    error(string.format("probe57e regression: %d/%d assertion(s) failed", failures, assertions))
end
print("test_probe57e: OK")
