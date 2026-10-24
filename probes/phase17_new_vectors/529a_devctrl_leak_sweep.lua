-- CRASH_CLASS: HIGH
-- PROBE 529a: syscall 601 command sweep looking for kernel pointers
--
-- Context: 601 is the largest handler in the table (body 0xca0630) and its
-- first instruction compares the command against 0x27, so it dispatches 40
-- commands. 55d sampled about ten of them. This probe calls every command
-- with a page of 0x41 as the input and a zeroed page as the output, then
-- scans the output for qwords that look like kernel virtual addresses
-- (0xFFFF8xxx_xxxxxxxx .. 0xFFFFFxxx_xxxxxxxx, excluding all-ones sentinels).
-- Output is printed per command, so a killing command still leaves prior
-- results in the capture.

print("=== PROBE 529a: 601 COMMAND LEAK SWEEP ===")
print("")
-- 0x03 and 0x04 each killed the game process; the jump table sits at
-- 0x1a51160, outside this capture, so the valid commands cannot be read
-- statically. These are the commands 55d saw return cleanly.
local SAFE = {0x00, 0x07, 0x09, 0x0d, 0x13, 0x14, 0x19}
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local sc = mk(601)
local IN = memory.alloc(0x1000)
local OUT = memory.alloc(0x1000)
local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
local function alive() return N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) == pid_val end

local function fill_in()
    for i = 0, 0xFFC, 4 do wd(N(IN) + i, 0x41414141) end
end
local function clear_out()
    for i = 0, 0xFFC, 8 do wq(N(OUT) + i, uint64(0)) end
end
local function scan()
    local hits = {}
    for i = 0, 0xFF8, 8 do
        local v = rq(N(OUT) + i)
        if v then
            local hi, lo = get_hi_lo(v)
            if hi >= 0xFFFF8000 and hi <= 0xFFFFF000 then
                hits[#hits + 1] = string.format("+%03X=%08X%08X", i, hi, lo)
            end
        end
    end
    return hits
end

for idx = 1, #SAFE do
    local cmd = SAFE[idx]
    fill_in(); clear_out()
    local ret = -999
    pcall(function() ret = N(sc(uint64(cmd), uint64(N(IN)), uint64(N(OUT)), uint64(0), uint64(0), uint64(0))) end)
    local h = scan()
    local line = string.format("cmd %02X ret=%d", cmd, ret)
    if #h > 0 then line = line .. " KERN " .. table.concat(h, " ") end
    print(line)
    if not alive() then print("!! process gone"); break end
end
print("=== DONE ===")
