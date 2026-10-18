-- tools/test_probe56l.lua
--
-- Offline regression harness for
--   probes/phase14_final_push/56l_corrected_mib_probe.lua
--
-- The probe is loaded UNMODIFIED (loadfile + setfenv) and executed inside an
-- isolated Lua 5.1 sandbox that provides:
--   * an in-memory byte store for memory.alloc/read_*/write_*; the allocator
--     starts at 0x10000000 and advances 0x10000 per call, so it never returns 0
--   * a syscall shim (metatable __call, numeric argument coercion, syscall.pipe,
--     syscall.getpid) that records/replays nothing on its own: it only calls the
--     per-case handler, which MAY mutate the sandbox memory at the real
--     invocation (no expected probe output is echoed back)
--   * uint64/bit32/syscall.getpid minimum compatibility plus a _G fallback
--   * captured print output
--
-- The cases assert on diagnostics actually emitted by the probe, and on the
-- invocation shape (sysctl 202 arity/pointers) the shim observed.
--
-- Sections covered:
--   [A] setup: banner, PID echo
--   [B] TCP pcblist {4,2,6,11}: size query, data read, kernel-band qword scan
--   [C] kstack {1,14,15,pid}: size query, 1096-byte record parse (tid/state/trace)
--   [D] ktimer differential: 237-as-settime then 236-as-delete on fresh timers,
--       each followed by the agreed gettime (238)
--
-- Expected result: PASS on the committed probe. It fails if the corrected MIB
-- leaves, the kernel-band qword scan, the kinfo_kstack record parse, the
-- ktimer verdict decision, or the section/DONE markers regress. The MIB echoes
-- are read back from the probe's own MIB buffer, not from a handler constant:
-- the handler also records the leaves it sees at the probe-supplied pointer.
--
-- Run from the repository root:  lua tools/test_probe56l.lua
-- (or lupa.lua51.execute on the same file from the same CWD)

local PROBE = "probes/phase14_final_push/56l_corrected_mib_probe.lua"
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
        bor = function(a, b) return a + b - band(a, b) end,
        bxor = function(a, b) return a + b - 2 * band(a, b) end,
        rshift = function(a, n) return math.floor(a / 2 ^ n) % 4294967296 end,
        lshift = function(a, n) return (a * 2 ^ n) % 4294967296 end,
    }
    setmetatable(env, { __index = _G })

    local chunk, lerr = loadfile(PROBE)
    if not chunk then error("cannot load probe: " .. tostring(lerr)) end
    setfenv(chunk, env)
    local ok, rerr = pcall(chunk)
    if not ok then error("probe execution failed: " .. tostring(rerr)) end
    return out
end

-- ------------------------------------------------------- case-1 handler -----
-- Upstream-shaped kernel responses for probe 56l:
--   * 202 size query (old == 0): write the leaf's byte length into oldlenp
--   * 202 data call (old == outbuf): fill outbuf, write the produced length
--   * pcblist {4,2,6,11}: one kernel-band qword at +0x08, an adjacent
--     non-kernel qword at +0x10 that the probe must ignore
--   * kstack {1,14,15,pid}: one 1096-byte record, tid=4242, state=0, trace "abc"
--   * 235 create / 237 4-arg settime / 236 1-arg delete / 238 gettime
local PCB_WORDS = { 4, 2, 6, 11 }
local KST_WORDS = { 1, 14, 15, PID }
local PCB_BYTES = 24
local KST_BYTES = 1096
local KST_TID = 4242
local KST_TRACE = "abc"
local KERN_HI = 0xFFFF8000 -- is_kptr() accepts h in [0xFFFF8000, 0xFFFFFFFF)
local KERN_LO = 0xDEADBEEF
local OTHER_HI = 1 -- non-kernel band
local OTHER_LO = 0x11111111

local obs = { sysctl = {} }
local timers = { next_id = 7 }

local function leaves_at(mem, mib, n)
    local leaves = {}
    for i = 1, n do leaves[i] = mem.read_dword(mib + (i - 1) * 4) end
    return leaves
end

local function handler_upstream(sc_no, args, mem)
    local t = timers

    if sc_no == 20 then -- getpid(); the probe reads its PID through 20
        return PID
    elseif sc_no == 202 then
        local leaves = leaves_at(mem, args[1], args[2])
        obs.sysctl[#obs.sysctl + 1] = {
            nargs = #args,
            leaves = leaves,
            old = args[3],
            oldlenp = args[4],
            tail_zero = args[5] == 0 and args[6] == 0,
        }

        local needed = 0
        if same_list(leaves, PCB_WORDS) then needed = PCB_BYTES
        elseif same_list(leaves, KST_WORDS) then needed = KST_BYTES end

        if args[3] == 0 then -- size query
            mem.write_dword(args[4], needed)
            mem.write_dword(args[4] + 4, 0)
            return 0
        end

        if needed == PCB_BYTES then -- data call: pcblist
            mem.write_dword(args[3] + 0x08, KERN_LO)
            mem.write_dword(args[3] + 0x0C, KERN_HI)
            mem.write_dword(args[3] + 0x10, OTHER_LO)
            mem.write_dword(args[3] + 0x14, OTHER_HI)
        elseif needed == KST_BYTES then -- data call: kstack
            mem.write_dword(args[3], KST_TID)
            mem.write_dword(args[3] + 4, 0) -- state 0 = STACKOK
            for i = 1, #KST_TRACE do
                mem.write_byte(args[3] + 8 + (i - 1), string.byte(KST_TRACE, i))
            end
            mem.write_byte(args[3] + 8 + #KST_TRACE, 0) -- NUL terminates trace
        end
        mem.write_dword(args[4], needed)
        mem.write_dword(args[4] + 4, 0)
        return 0
    elseif sc_no == 235 then -- ktimer_create(clk, sevp, tidp)
        local id = t.next_id
        t.next_id = id + 1
        t[id] = { alive = true, armed = false }
        mem.write_dword(args[3], id)
        mem.write_dword(args[3] + 4, 0)
        return 0
    elseif sc_no == 237 then -- settime-shaped: 4 args
        local id = args[1]
        if #args == 4 and t[id] and t[id].alive then
            t[id].armed = true
            return 0
        end
        return -1
    elseif sc_no == 236 then -- delete-shaped: 1 arg
        local id = args[1]
        if #args == 1 and t[id] and t[id].alive then
            t[id].alive = false
            return 0
        end
        return -1
    elseif sc_no == 238 then -- gettime(id, its)
        local id = args[1]
        if t[id] and t[id].alive and t[id].armed then
            mem.write_dword(args[2] + 8, 1) -- it_value.tv_sec, remaining
            mem.write_dword(args[2] + 12, 0)
            return 0
        end
        return -1
    end
    return -1
end

-- ---------------------------------------------------------- case 1: full ----
local out = run_sandbox(handler_upstream)

check("setup: banner emitted",
    contains(out, "=== PROBE 56l: CORRECTED MIB RETEST + KTIMER DIFFERENTIAL ==="))
check("setup: PID echoed", contains(out, "PID: " .. PID))

local n_sysctl = #obs.sysctl
local six_args, zero_tail, alloc_oldlenp = n_sysctl == 4, true, true
local size_calls, data_calls, data_ptr_ok = 0, 0, true
for _, c in ipairs(obs.sysctl) do
    if c.nargs ~= 6 then six_args = false end
    if not c.tail_zero then zero_tail = false end
    if c.oldlenp < PTR_MIN then alloc_oldlenp = false end
    if c.old == 0 then
        size_calls = size_calls + 1
    else
        data_calls = data_calls + 1
        if c.old < PTR_MIN then data_ptr_ok = false end
    end
end
check("sysctl shape: four 202 invocations with six arguments each", six_args)
check("sysctl shape: trailing (0,0) args on every invocation", zero_tail)
check("sysctl shape: oldlenp is an allocator pointer on every call", alloc_oldlenp)
check("sysctl shape: 2 size queries (old=0) + 2 data calls (outbuf ptr)",
    size_calls == 2 and data_calls == 2 and data_ptr_ok)

check("mib: handler observed {4,2,6,11} in the probe's own buffer",
    same_list(obs.sysctl[1] and obs.sysctl[1].leaves or {}, PCB_WORDS))
check("mib: handler observed {1,14,15," .. PID .. "} in the probe's own buffer",
    same_list(obs.sysctl[3] and obs.sysctl[3].leaves or {}, KST_WORDS))

-- [B] pcblist
check("mib echo: pcblist query echoes {4,2,6,11}", contains(out, "MIB sent: {4,2,6,11}"))
check("sysctl: pcblist size query mutated oldlenp",
    contains(out, "size query ret=0 needed=" .. PCB_BYTES))
check("sysctl: pcblist data call reports got via oldlenp",
    contains(out, "data ret=0 got=" .. PCB_BYTES))
check("pcblist: kernel-band qword counted",
    contains(out, "pcblist kernel-band qwords: 1 in " .. PCB_BYTES .. " bytes"))
check("pcblist: kernel-band qword echoed at +0x0008",
    contains(out, "+0x0008: 0xFFFF8000_DEADBEEF KPTR!"))
check("pcblist: adjacent non-kernel qword (+0x0010) ignored", not contains(out, "+0x0010:"))
check("section B: COMPLETE marker", contains(out, "[B] COMPLETE"))

-- [C] kstack
check("mib echo: kstack query echoes {1,14,15," .. PID .. "}",
    contains(out, "MIB sent: {1,14,15," .. PID .. "}"))
check("sysctl: kstack size query mutated oldlenp",
    contains(out, "size query ret=0 needed=" .. KST_BYTES))
check("sysctl: kstack data call reports got via oldlenp",
    contains(out, "data ret=0 got=" .. KST_BYTES))
check("kstack: record count derived from 1096-byte records",
    contains(out, "records: ~1 (" .. KST_BYTES .. " bytes / " .. KST_BYTES .. ")"))
check("kstack: record[0] parses tid=4242, state=0(STACKOK), trace \"abc\"",
    contains(out, "record[0]: tid=4242 state=0(STACKOK) tracelen~" .. #KST_TRACE))
check("section C: COMPLETE marker", contains(out, "[C] COMPLETE"))

-- [D] ktimer differential
check("ktimer D1: fresh timer created", contains(out, "D1 create: rv=0 id=7"))
check("ktimer D1: 4-arg 237 arms the fresh timer",
    contains(out, "D1: 237=SETTIME — 4-arg call armed the timer"))
check("ktimer D1: upstream-consistent note emitted",
    contains(out, "(consistent with upstream 237=ktimer_settime)"))
check("ktimer D1: gettime reports remaining_sec>0",
    contains(out, "D1 gettime: rv=0 remaining_sec=1"))
check("ktimer D2: fresh timer created", contains(out, "D2 create: rv=0 id=8"))
check("ktimer D2: 1-arg 236 deletes the fresh timer",
    contains(out, "D2: 236=DELETE — 1-arg call removed the timer"))
check("ktimer D2: gettime returns nonzero after the delete",
    contains(out, "D2 gettime: rv=-1"))
check("ktimer D2: upstream-consistent note emitted",
    contains(out, "(consistent with upstream 236=ktimer_delete)"))
check("section D: COMPLETE marker", contains(out, "[D] COMPLETE"))
check("probe: DONE marker emitted", contains(out, "=== 56l DONE ==="))

-- ----------------------------------------------- case 2: no handler writes --
-- Every syscall only returns -1 and never touches sandbox memory: no size, no
-- data, no timer. The probe must still echo its MIBs, complete every section,
-- and reach only the INCONCLUSIVE ktimer verdicts.
out = run_sandbox(function(sc_no)
    if sc_no == 20 then return PID end
    return -1
end)

check("nowrite: setup banner emitted",
    contains(out, "=== PROBE 56l: CORRECTED MIB RETEST + KTIMER DIFFERENTIAL ==="))
check("nowrite: pcblist MIB still echoed", contains(out, "MIB sent: {4,2,6,11}"))
check("nowrite: kstack MIB still echoed",
    contains(out, "MIB sent: {1,14,15," .. PID .. "}"))
check("nowrite: refused paths reported",
    contains(out, "no data (refused or size query failed)"))
check("nowrite: section markers B, C and D", contains(out, "[B] COMPLETE")
    and contains(out, "[C] COMPLETE") and contains(out, "[D] COMPLETE"))
check("nowrite: DONE marker emitted", contains(out, "=== 56l DONE ==="))
check("nowrite: only INCONCLUSIVE ktimer verdicts",
    contains(out, "D1: INCONCLUSIVE") and contains(out, "D2: INCONCLUSIVE"))
check("nowrite: no upstream-shaped ktimer verdict",
    not contains(out, "237=SETTIME") and not contains(out, "236=DELETE"))

-- ----------------------------------------- case 3: zero-length responses ----
-- Every syscall reports success but produces no bytes and no timer state: the
-- probe must take its EMPTY branches and attribute them to the echoed MIB,
-- and the D1 verdict must stay INCONCLUSIVE.
out = run_sandbox(function(sc_no)
    if sc_no == 20 then return PID end
    return 0
end)

check("empty: pcblist EMPTY signature reported",
    contains(out, "EMPTY: ret=0 len=0 — same signature as 56i3's leaf-35 false negative;"))
check("empty: pcblist EMPTY attributed to {4,2,6,11}",
    contains(out, "attributes this result to {4,2,6,11}"))
check("empty: kstack EMPTY still echoes its MIB",
    contains(out, "MIB sent: {1,14,15," .. PID .. "}"))
check("empty: kstack EMPTY attributed to {1,14,15}",
    contains(out, "attributes this to {1,14,15}"))
check("empty: D1 verdict stays INCONCLUSIVE", contains(out, "D1: INCONCLUSIVE"))
check("empty: D2 keeps the 42a-labelled verdict",
    contains(out, "D2: 236=SETTIME-4ARG"))
check("empty: completion and DONE markers",
    contains(out, "[B] COMPLETE") and contains(out, "[C] COMPLETE")
    and contains(out, "[D] COMPLETE") and contains(out, "=== 56l DONE ==="))

-- ----------------------------------- case 4: failed differential calls -----
-- Create succeeds but both differential calls fail, and gettime also fails
-- (the raw shape 42a's capture already shows for gettime on 14.10): the
-- probe must report INCONCLUSIVE rather than attribute a removal to a
-- call whose own printed return says it failed. Guards the r237/r236
-- return checks in the D1/D2 DELETE branches.
out = run_sandbox(function(sc_no)
    if sc_no == 20 then return PID end
    if sc_no == 235 then return 0 end
    return -1
end)

check("failcall: D1 call failure printed", contains(out, "D1 237(id,0,its,its2): rv=-1"))
check("failcall: D1 verdict INCONCLUSIVE, not DELETE",
    contains(out, "D1: INCONCLUSIVE") and not contains(out, "237=DELETE"))
check("failcall: D2 call failure printed", contains(out, "D2 236(id): rv=-1"))
check("failcall: D2 verdict INCONCLUSIVE, not DELETE",
    contains(out, "D2: INCONCLUSIVE") and not contains(out, "236=DELETE"))
check("failcall: completion and DONE markers",
    contains(out, "[D] COMPLETE") and contains(out, "=== 56l DONE ==="))
-- ------------------------------------------------------------------ report --
print(string.format("test_probe56l: %d assertions, %d failures", assertions, failures))
if failures > 0 then
    error(string.format("probe56l regression: %d/%d assertion(s) failed", failures, assertions))
end
print("test_probe56l: OK")
