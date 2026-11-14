-- CRASH_CLASS: LOW
-- PROBE 1464a: sys 601 commands that return 0 -- dump the WHOLE buffer, not the first two dwords
--
-- Context:
--   1461a and 1462a measured 601 commands 0x00, 0x0D, 0x13, 0x14 and 0x19 returning 0, and every
--   report so far only ever printed the first two dwords of the output buffer (0x00 leaves
--   00000100 00000000 there, which reads like a size field followed by nothing).  A command that
--   fills a 0x100-byte structure would look identical if only the head is printed.
--
--   This probe zeroes a 0x200 buffer, calls the command with the buffer in arg1 (and in a second
--   pass in arg2, because the two shapes have produced different errnos elsewhere), and prints every
--   dword that is not zero together with its offset.  A 0xFFFF8xxx or 0xFFFFFFFF_ pattern anywhere
--   in the output would be the first kernel pointer this project has seen from a syscall.
--
--   0x11, 0x12, 0x1B, 0x1C and 0x03/0x04/0x08/0x0C are excluded: they kill or park.
--
-- -- prior art:
--   results/phase36_realargs/1462a_sys601_cmd12_name_20261109_175525.txt
--   results/phase36_realargs/1461a_sys601_matrix_tail_20261109_175346.txt
--   results/phase36_realargs/1383a_601_command_matrix_*.txt (0x00 -> 00000100 00000000)
--   docs/MDBG_601_COMMAND_MAP_14_10.md

print("=== PROBE 1464a: SYS 601 FULL BUFFER DUMP ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc601 = mk(601)
local bufa = as_addr(memory.alloc(0x400))
local SIZE = 0x200

local function zero()
    for o = 0, 0x3F8, 8 do wq(bufa + o, 0) end
end

local function dump(tag)
    local n, out = 0, {}
    for o = 0, SIZE - 4, 4 do
        local v = rd(bufa + o)
        local hi = rd(bufa + o + 4)
        if v ~= 0 or (hi and hi ~= 0) then
            n = n + 1
            if n <= 24 then out[#out + 1] = string.format("+%03X=%08X%08X", o, hi or 0, v) end
        end
    end
    if n == 0 then print(string.format("[%s] buffer untouched", tag))
    else print(string.format("[%s] %d non-zero dwords: %s", tag, n, table.concat(out, " "))) end
end

local function call(cmd, a1, a2, a3)
    local ok, rv = pcall(function() return sc601(uint64(cmd), uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0)) end)
    if not ok then return nil end
    return to_num(rv)
end

local CMDS = { 0x00, 0x0D, 0x13, 0x14, 0x19 }
for i = 1, #CMDS do
    local cmd = CMDS[i]
    zero()
    local rv = call(cmd, bufa, 0, SIZE)
    if rv == nil then
        print(string.format("[%02X] EXC", cmd))
    else
        if rv == -1 then print(string.format("[%02X] A: rv=-1 errno=%s", cmd, es()))
        else print(string.format("[%02X] A: rv=%d", cmd, rv)) end
        dump(string.format("%02X-A", cmd))
    end
end
print("")

for i = 1, #CMDS do
    local cmd = CMDS[i]
    zero()
    local rv = call(cmd, 0, bufa, SIZE)
    if rv == nil then
        print(string.format("[%02X] EXC", cmd))
    else
        if rv == -1 then print(string.format("[%02X] B: rv=-1 errno=%s", cmd, es()))
        else print(string.format("[%02X] B: rv=%d", cmd, rv)) end
        dump(string.format("%02X-B", cmd))
    end
end

print("")
print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1464a COMPLETE ===")
