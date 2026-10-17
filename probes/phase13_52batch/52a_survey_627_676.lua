-- CRASH_CLASS: MODERATE
-- PROBE 52a: Complete Sony syscall survey 627-676 (3 arg-pattern passes)
--
-- Context: 51a surveyed 532-~626 but the run was cut short (51c result file
-- ends right after 625/626, so 627-676 mostly never got results). 51b deep-
-- tested a handful in this range (640: ret=0 empty buffer; 628/648/652/676:
-- ret=-1). This probe completes the survey for the second half of the Sony
-- range using THREE arg-patterns per number, sequenced from safest to
-- riskiest so a crash pinpoints both the number AND the argument pattern:
--   PASS A: all-zero args (six uint64(0) slots)
--   PASS B: arg1 = allocated+zeroed 0x100 buffer, arg2 = 0x100 (len)
--   PASS C: six allocated+zeroed 0x100 buffers, one per arg slot
-- Every call is wrapped in pcall and a progress line is printed BEFORE the
-- call so the last output line identifies the killer if the process dies.
-- errno capture is not established yet (see 52d), so we print the raw ret
-- and classify it: SUCCESS / DENIED(-1) / positive errno-like / kernel-ptr.

print("=== PROBE 52a: SONY SYSCALL SURVEY 627-676 ===")
print("")

-- Standard helpers (ALWAYS include these)
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
-- uint64 for addresses >32-bit (CLAUDE.md rule: string.format hi/lo form)
local function mkaddr(addr)
    if type(addr) == "table" and addr.h then return addr end
    local n = to_num(addr)
    if n <= 0 then return uint64(0) end
    if n < 4294967296 then
        return uint64(string.format("0x%X%08X", 0, n))
    end
    local hi = math.floor(n / 4294967296)
    local lo = n - hi * 4294967296
    return uint64(string.format("0x%X%08X", hi, lo))
end

local function hexdump(addr, len)
    local parts = {}
    for i = 0, len - 4, 4 do
        local v = safe_rd(addr + i)
        if v then
            table.insert(parts, string.format("%08X", v))
        else
            table.insert(parts, "????????")
        end
    end
    return table.concat(parts, " ")
end

local function scan_for_kptrs(addr, len)
    local found = {}
    for i = 0, len - 8, 8 do
        local val = safe_rq(addr + i)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                table.insert(found, {i, h, l})
            end
        end
    end
    return found
end

local sc_getpid = make_syscall(20)
local ok_pid, pid_ret = pcall(function() return sc_getpid() end)
local pid = ok_pid and to_num(pid_ret) or 0
print("PID: " .. pid)
print("Range: 627-676 (50 numbers), 3 passes each = 150 calls")

-- Allocated + zeroed buffers
local Z = uint64(0)
local bufB = memory.alloc(0x100)          -- PASS B output buffer
for i = 0, 0xFC, 4 do safe_wd(bufB + i, 0) end
local ptrs = {}                            -- PASS C: six 0x100 buffers
for i = 1, 6 do
    ptrs[i] = memory.alloc(0x100)
    for j = 0, 0xFC, 4 do safe_wd(ptrs[i] + j, 0) end
end

-- Snapshot first 0x40 bytes of a buffer (dwords) for change detection
local function snapshot(addr)
    local t = {}
    for i = 0, 0x3C, 4 do t[#t + 1] = safe_rd(addr + i) end
    return t
end

local function diff_report(addr, snap, label)
    -- compare current content vs snapshot; print hexdump of first 0x40
    -- bytes + kernel-ptr scan if anything changed
    local changed = false
    for i = 0, 0x3C, 4 do
        local v = safe_rd(addr + i)
        if v ~= snap[(i / 4) + 1] then changed = true end
    end
    if changed then
        print("    " .. label .. " CHANGED: " .. hexdump(addr, 0x40))
        local kptrs = scan_for_kptrs(addr, 0x100)
        if #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("    !!! KPTR %s+%02X = %08X_%08X",
                    label, kp[1], kp[2], kp[3]))
            end
        end
    end
    return changed
end

-- Build the argument vector for a given pass
local function call_pattern(sc, pat, buf)
    if pat == 1 then
        return sc(Z, Z, Z, Z, Z, Z)
    elseif pat == 2 then
        return sc(mkaddr(buf), uint64(0x100), Z, Z, Z, Z)
    else
        return sc(mkaddr(ptrs[1]), mkaddr(ptrs[2]), mkaddr(ptrs[3]),
                  mkaddr(ptrs[4]), mkaddr(ptrs[5]), mkaddr(ptrs[6]))
    end
end

local nums = {}
for n = 627, 676 do nums[#nums + 1] = n end

-- per-number best record: {num, group, pass, ret_h, ret_l, note}
local records = {}

-- Groups from 51a table layout (approximate, for labeling only)
local function group_of(num)
    if num <= 626 then return "proc"
    elseif num <= 641 then return "io"
    elseif num <= 660 then return "misc"
    elseif num <= 670 then return "dev"
    end
    return "misc"
end

local pass_names = { "A(all-zero)", "B(buf+len)", "C(6-pointers)" }

for pass = 1, 3 do
    print("")
    print("--- PASS " .. pass .. " " .. pass_names[pass] .. " ---")
    for _, num in ipairs(nums) do
        -- PROGRESS FIRST: if the process dies, this line names the culprit
        print(string.format("  P%d num=%d calling now...", pass, num))

        local sc = make_syscall(num)
        local ok, ret

        if pass == 1 then
            ok, ret = pcall(function() return call_pattern(sc, 1, bufB) end)
        elseif pass == 2 then
            for i = 0, 0xFC, 4 do safe_wd(bufB + i, 0) end
            local snap = snapshot(bufB)
            ok, ret = pcall(function() return call_pattern(sc, 2, bufB) end)
            if ok then diff_report(bufB, snap, "bufB") end
        else
            local snaps = {}
            for i = 1, 6 do snaps[i] = snapshot(ptrs[i]) end
            ok, ret = pcall(function() return call_pattern(sc, 3, bufB) end)
            if ok then
                for i = 1, 6 do
                    diff_report(ptrs[i], snaps[i], "ptr" .. i)
                end
            end
        end

        local h, l = 0, 0
        local tag = " [PCALL-FAIL]"
        if ok then
            h, l = get_hi_lo(ret)
            if h == 0 and l == 0 then
                tag = " [SUCCESS]"
            elseif h == 0xFFFFFFFF and l == 0xFFFFFFFF then
                tag = " [-1 DENIED]"
            elseif h == 0 then
                tag = " [+errno-like?]"
            elseif h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                tag = " [KERNEL PTR!!!]"
            elseif h >= 0x80000000 then
                tag = " [hi-set/sony-err?]"
            end
        else
            ret = nil
        end

        print(string.format("  P%d num=%d ret=%s%s",
            pass, num,
            ok and string.format("0x%08X_%08X", h, l) or tostring(ret),
            tag))

        -- record best (non -1) result per number
        local rv_ok = ok and not (h == 0xFFFFFFFF and l == 0xFFFFFFFF)
        if rv_ok then
            local rec = records[num]
            if not rec then
                records[num] = {num, group_of(num), pass, h, l, tag}
            end
        end
    end
end

print("")
print("=== SUMMARY: NON-(-1) RESULTS ===")
local count = 0
for _, num in ipairs(nums) do
    local rec = records[num]
    if rec then
        count = count + 1
        print(string.format("  [%s] %d: pass=%s ret=0x%08X_%08X %s",
            rec[2], rec[1], pass_names[rec[3]], rec[4], rec[5], rec[6]))
    end
end
print(string.format("Accessible in 627-676: %d / 50", count))

-- repeat...until true + break used instead of goto (Lua 5.1 constraint)
-- demonstrated here as the sanctioned early-exit idiom:
do
    local n_access = count
    repeat
        if n_access == 0 then
            print("  NOTE: all -1 — second half of Sony range likely stubbed")
            break
        end
        print("  NOTE: accessible numbers found — deep-dive in 52c/next batch")
        break
    until true
end

print("")
print("=== PROBE 52a COMPLETE ===")
