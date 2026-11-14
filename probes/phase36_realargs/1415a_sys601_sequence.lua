-- CRASH_CLASS: LOW
-- PROBE 1415a: does any 601 command create the state that 0x12 reports ENOENT about?
--
-- prior art:
--   results/phase36_realargs/1401a_sys601_cmd12_errno_20261109_151911.txt
--     0x12(0, NULL) = EFAULT, 0x12(mapped, *) = EINVAL, so arg1 must be null.
--   results/phase36_realargs/1404a_sys601_cmd12_index_20261109_152525.txt
--     with arg1 = 0 the answer is EFAULT on an all-zero destination page and ENOENT on a
--     page holding any other pattern; a repeat interleaved with 0x0A (EPERM) is stable, so
--     errno is fresh.
--   results/phase36_realargs/1405a_sys601_cmd12_field_20261109_152556.txt
--     the field that flips the answer is the qword at arg2+0x08; +0x00 has no effect.
--   results/phase36_realargs/1406a_sys601_cmd12_qword8_20261109_152629.txt
--     arg2+0x08 is a scalar key, never dereferenced: every kernel VA, every user page and
--     every small integer gives the same ENOENT.
--   results/phase36_realargs/1408a_sys601_producer_map_20261109_152747.txt
--     no reachable command writes to arg2; only 0x00, 0x0E and 0x1A write anything.
--   13.60 body: results/kernel_handlers/asm/sys_601_deep.asm - 0x12 does
--     copyin(arg1, &stack, 0x20), then gates on bit 0x400 of [proc+0x528], then stores
--     qword0 -> proc+0x578 and qword1 -> proc+0x580. The 14.10 body copies from arg1 too
--     but never reaches the store.
--   docs/MDBG_601_COMMAND_MAP_14_10.md
--
-- Reading: EFAULT when the key is zero and ENOENT when it is not is the signature of a
-- lookup - the syscall refuses to read a null key, and then fails to find the object. If that
-- is right, some other command in the same interface has to create the object, and running it
-- should change 0x12's answer from ENOENT to success in the same connection.
--
-- Method: baseline, then for each harmless command C: run C with (zero page in, canary page
-- out), then re-run 0x12 and print the answer. A single flip is visible as a step change;
-- state persists for the rest of the connection, so the first line that differs is the one
-- that matters. Only commands measured non-lethal are included (0x03/0x04/0x08/0x0C/0x1B/
-- 0x1C/0x11 are excluded - each kills the process).

print("=== PROBE 1415a: 601 SEQUENCE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end

local pid = sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", pid))

local sc477 = mk(477)
local function mmap_pages(n)
    local va = N(sc477(uint64(0), uint64(0x1000 * n), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end

local IN = mmap_pages(2)
local OUT = mmap_pages(2)
local KEYP = mmap_pages(2)
print(string.format("[0] IN=0x%X OUT=0x%X KEYP=0x%X", IN or 0, OUT or 0, KEYP or 0))
if not (IN and OUT and KEYP) then print("[!] mmap failed: " .. es()) return end

local function zero(va, n) for off = 0, n - 4, 4 do pcall(function() memory.write_dword(va + off, 0) end) end end
local function fill(va, n, v) for off = 0, n - 4, 4 do pcall(function() memory.write_dword(va + off, v) end) end end

local sc601 = mk(601)
local function c601(cmd, a1, a2)
    local ok, rv = pcall(function() return sc601(uint64(cmd), uint64(a1 or 0), uint64(a2 or 0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return "EXC" end
    return sg(rv)
end

-- the 0x12 probe: arg1 null, arg2 a page whose qword at +8 is a nonzero key
local function probe12(tag)
    zero(OUT, 0x1000)
    fill(OUT + 0x20, 0x100, 0x5A5A5A5A)
    -- the key lives in the page arg2 points at, at +0x08
    pcall(function() memory.write_dword(KEYP + 0x08, pid) end)
    pcall(function() memory.write_dword(KEYP + 0x0C, 0) end)
    local rv = c601(0x12, 0, KEYP)
    local ch = 0
    for off = 0, 0x3F, 4 do
        local v = rd(OUT + off)
        if v ~= nil and v ~= 0 then ch = ch + 1 end
    end
    print(string.format("  %-10s 0x12 -> rv=%s errno=%s", tag, tostring(rv), es()))
end

print("")
print("[A] baseline")
probe12("baseline")

print("")
print("[B] for each command C: run C, then re-run 0x12")
local CMDS = {0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0D,
              0x0E, 0x0F, 0x10, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A}
for _, c in ipairs(CMDS) do
    zero(IN, 0x1000)
    zero(OUT, 0x1000)
    fill(OUT, 0x100, 0xA5A5A5A5)
    local rv = c601(c, IN, OUT)
    print(string.format("  C=0x%02X -> rv=%s errno=%s out0=%s", c, tostring(rv), es(), hex4(rd(OUT))))
    probe12(string.format("after %02X", c))
end

print("")
print("[C] the same sequence with C given a null first argument")
for _, c in ipairs({0x00, 0x0E, 0x13, 0x14, 0x19, 0x1A}) do
    local rv = c601(c, 0, OUT)
    print(string.format("  C=0x%02X(0,OUT) -> rv=%s errno=%s", c, tostring(rv), es()))
    probe12(string.format("after %02X", c))
end

print("")
print("=== 1415a DONE ===")
