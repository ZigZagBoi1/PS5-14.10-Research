-- CRASH_CLASS: MODERATE
-- PROBE 1461a: complete the sys 601 command matrix, 0x0D-0x27
--
-- Context:
--   601 is the only dispatcher on 14.10 whose 13.60 body shows a caller struct being copied into
--   process slots (docs/dumps_13.60/kernel_text.bin VA 0xffffffff8b661542: qword0 -> proc+0x578,
--   qword1 -> proc+0x580, qword2 -> +0x588, qword3 -> +0x590) and a second site that copies 0x480
--   bytes OUT of proc+0x578 and then frees it (VA 0xffffffff8b661b2c).  Finding the command numbers
--   for those two halves is the point of this sweep.
--
--   Measured so far on 14.10 (results/phase36_realargs/1383a, results/phase35_dead_end_reruns/1355a,
--   results/phase36_realargs/1460a):
--     0x00 rv=0 writes 0x100        0x01 EINVAL (EFAULT on null)
--     0x02 0x05 0x06 ENOSYS         0x07 0x09 0x0B rv=0 no write
--     0x0A EPERM                    0x0C parks forever
--     0x03 0x04 kill (55d)          0x08 0x1B kill (1192a/1193a skip table, 1355a)
--     0x11 EINVAL always, kills on a zero page in 1400a when arg2 is the page
--     0x12 EINVAL for every arg1/arg2 arrangement including the 13.60 magic
--   Everything from 0x0D up except those is untested.
--
--   Each call is printed BEFORE it is made, so a kill names itself, and the sweep runs in ascending
--   order so the most commands are covered before any death.  0x03, 0x04, 0x08, 0x0C and 0x1B are
--   skipped on that prior evidence.
--
-- -- prior art:
--   results/phase36_realargs/1383a_601_command_matrix_*.txt (the rows above)
--   results/phase36_realargs/1460a_sys601_magic_tag_20261109_175209.txt
--   results/phase36_realargs/1400a_sys601_cmd11_struct_20261109_144119.txt (0x11 kills)
--   probes/phase17_new_vectors/1192a_601_dispatcher_command.lua:33 (kill skip table)
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt (0x1B death)
--   docs/MDBG_601_COMMAND_MAP_14_10.md

print("=== PROBE 1461a: SYS 601 COMMAND MATRIX 0x0D-0x27 ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end) if ok then return to_num(v) end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc601 = mk(601)
local buf = memory.alloc(0x800)
local BUF = as_addr(buf)
local SENT = 0xA5A5A5A5

local function fill()
    for o = 0, 0x7FC, 4 do pcall(function() memory.write_dword(uint64(BUF + o), SENT) end) end
end
local function changed()
    local n = 0
    for o = 0, 0x7F8, 4 do
        local v = rd(BUF + o)
        if v ~= SENT then n = n + 1 end
    end
    return n
end
local function dump(n)
    local out = {}
    for i = 0, math.min(n, 8) - 1 do out[#out + 1] = string.format("%08X", rd(BUF + i * 4) or 0) end
    return table.concat(out, " ")
end

-- 0x11 is lethal whenever arg2 is a mapped page (1400a killed on a zero page, 1393a got EFAULT
-- only for a kernel arg2, and 1461a-v1 died at 0x11 with arg2 = a mapped user page): skip it.
local SKIP = { [0x03] = true, [0x04] = true, [0x08] = true, [0x0C] = true, [0x11] = true, [0x1B] = true }

for cmd = 0x0D, 0x27 do
    if not SKIP[cmd] then
        fill()
        print(string.format("[%02X] 601(0x%02X, 0, buf, 0x100) ...", cmd, cmd))
        local ok, rv = pcall(function() return sc601(uint64(cmd), uint64(0), uint64(BUF), uint64(0x100), uint64(0), uint64(0)) end)
        if not ok then
            print(string.format("[%02X] EXC %s", cmd, tostring(rv)))
        else
            local r = to_num(rv)
            if r == -1 then print(string.format("[%02X] rv=-1 errno=%s", cmd, es()))
            else print(string.format("[%02X] rv=%d", cmd, r)) end
            local n = changed()
            if n > 0 then print(string.format("[%02X] changed=%d head=%s", cmd, n, dump(n))) end
        end
    end
end

-- second pass: the same commands with the struct pointer in arg1, in case a command reads it there
print("")
print("[P2] arg1 = buf, arg2 = 0x100")
for cmd = 0x0D, 0x27 do
    if not SKIP[cmd] then
        fill()
        print(string.format("[%02X] 601(0x%02X, buf, 0x100) ...", cmd, cmd))
        local ok, rv = pcall(function() return sc601(uint64(cmd), uint64(BUF), uint64(0x100), uint64(0), uint64(0), uint64(0)) end)
        if not ok then
            print(string.format("[%02X] EXC %s", cmd, tostring(rv)))
        else
            local r = to_num(rv)
            if r == -1 then print(string.format("[%02X] rv=-1 errno=%s", cmd, es()))
            else print(string.format("[%02X] rv=%d", cmd, r)) end
            local n = changed()
            if n > 0 then print(string.format("[%02X] changed=%d head=%s", cmd, n, dump(n))) end
        end
    end
end

print("")
print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1461a COMPLETE ===")
