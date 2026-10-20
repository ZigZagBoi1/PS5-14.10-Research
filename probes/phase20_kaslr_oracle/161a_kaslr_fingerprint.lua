-- CRASH_CLASS: LOW
-- PROBE 161a: KASLR multi-event fingerprint
-- Measures instructions, cycles, branch mispredictions for 6 syscalls
-- 20 samples each. Compare across boots to detect KASLR slide.

print("=== PROBE 161a: KASLR FINGERPRINT ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_lo(val)
    if type(val) == "table" and val.l then return val.l end
    return to_num(val)
end

local sc563 = make_syscall(563)
local sc564 = make_syscall(564)
local sc565 = make_syscall(565)
local sc566 = make_syscall(566)
local sc567 = make_syscall(567)
local sc432 = make_syscall(432)
local sc20  = make_syscall(20)

local tid_buf = memory.alloc(8)
memory.write_qword(tid_buf, uint64(0))
pcall(function() sc432(uint64(tid_buf)) end)
local our_tid = to_num(memory.read_dword(tid_buf))
print("TID: " .. our_tid)

local out = memory.alloc(16)

-- Sanity: enable PMU, count 10 getpid
pcall(function() sc564(uint64(0)) end)
pcall(function() sc565(uint64(0), uint64(0), uint64(0xC0)) end)
pcall(function() sc563(uint64(0)) end)
pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
for i = 1, 10 do pcall(function() sc20() end) end
memory.write_qword(out, uint64(0))
pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
local sanity = get_lo(memory.read_qword(out))
print("Sanity: " .. sanity .. " insn for 10x getpid")
if sanity == 0 then
    print("PMU NOT COUNTING - trying alternate setup")
    -- Try: configure on all 6 counters
    for idx = 0, 5 do
        pcall(function() sc565(uint64(0), uint64(idx), uint64(0xC0)) end)
    end
    pcall(function() sc563(uint64(0)) end)
    pcall(function() sc566(uint64(0), uint64(0xFFFFFFFF), uint64(0)) end)
    for i = 1, 10 do pcall(function() sc20() end) end
    for idx = 0, 5 do
        memory.write_qword(out, uint64(0))
        pcall(function() sc567(uint64(our_tid), uint64(idx), uint64(out)) end)
        local v = get_lo(memory.read_qword(out))
        print("  counter[" .. idx .. "] = " .. v)
    end
    print("=== PROBE 161a ABORTED ===")
    return
end
print("")

-- Events: 0xC0=instructions, 0x76=cycles, 0xC3=branch mispred
local events = {
    {0xC0, "insn"},
    {0x76, "cycles"},
    {0xC3, "br_miss"},
}

local targets = {
    {20,  "getpid",  function(sc) sc(uint64(0)) end},
    {202, "sysctl",  function(sc)
        local mib = memory.alloc(8)
        memory.write_dword(mib, 1)
        memory.write_dword(mib + 4, 37)
        sc(uint64(mib), uint64(2), uint64(0), uint64(0), uint64(0), uint64(0))
    end},
    {477, "mmap",    function(sc)
        sc(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end},
    {42,  "pipe",    function(sc) local pb = memory.alloc(16); sc(uint64(pb)) end},
    {97,  "socket",  function(sc) sc(uint64(2), uint64(2), uint64(0)) end},
    {624, "vmctr",   function(sc) sc() end},
}

local SAMPLES = 20
local all_fp = {}

for _, ev in ipairs(events) do
    local ev_code, ev_name = ev[1], ev[2]
    print("--- " .. ev_name .. " ---")

    pcall(function() sc564(uint64(0)) end)
    pcall(function() sc565(uint64(0), uint64(0), uint64(ev_code)) end)
    pcall(function() sc563(uint64(0)) end)

    for i = 1, 5 do pcall(function() sc20() end) end

    for _, tgt in ipairs(targets) do
        local sc_num, sc_name, sc_call = tgt[1], tgt[2], tgt[3]
        local sc_fn = make_syscall(sc_num)
        local counts = {}

        for s = 1, SAMPLES do
            pcall(function() sc566(uint64(0), uint64(0), uint64(0)) end)
            pcall(function() sc_call(sc_fn) end)
            memory.write_qword(out, uint64(0))
            pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
            counts[s] = get_lo(memory.read_qword(out))
        end

        local sorted = {}
        for i = 1, SAMPLES do sorted[i] = counts[i] end
        table.sort(sorted)
        local median = sorted[math.ceil(SAMPLES / 2)]
        local p25 = sorted[math.ceil(SAMPLES * 0.25)]
        local p75 = sorted[math.ceil(SAMPLES * 0.75)]
        local iqr = p75 - p25
        local jitter_pct = median > 0 and ((sorted[SAMPLES] - sorted[1]) / median * 100) or 0

        print(string.format("  %-8s med=%9d iqr=%6d jit=%.2f%%", sc_name, median, iqr, jitter_pct))

        if not all_fp[ev_name] then all_fp[ev_name] = {} end
        all_fp[ev_name][sc_name] = median
    end
    print("")
end

pcall(function() sc564(uint64(0)) end)

print("=== FINGERPRINT ===")
for _, ev in ipairs(events) do
    local parts = {}
    for _, tgt in ipairs(targets) do
        local m = all_fp[ev[2]] and all_fp[ev[2]][tgt[2]] or 0
        parts[#parts + 1] = tgt[2] .. "=" .. m
    end
    print("FP_" .. ev[2] .. ": " .. table.concat(parts, " | "))
end

print("")
print("=== PROBE 161a COMPLETE ===")
