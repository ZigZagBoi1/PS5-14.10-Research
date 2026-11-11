-- CRASH_CLASS: MODERATE -- excluded the six known-lethal 601 codes; everything else is cheap.
-- PROBE 1383b: 601 command x argument-shape matrix, part 2 - 0x0C/0x1B excluded
-- Part 1 (results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt) reached 0x0B
-- and then BLOCKED forever inside 0x0C (IDLE_TIMEOUT, connection still open, no kill). Damage ran
-- out of time before 0x0D, so this part starts there. Measured in part 1: 0x00 arg1 = the output
-- buffer (rv=0, writes 0x100 and 0); 0x01 copies 16 bytes in from arg1 and answers EINVAL(22) for
-- our bytes / EFAULT(14) for null; 0x02, 0x05, 0x06 are ENOSYS(78) on 14.10 even though the 13.60
-- map gives 0x05 a 0xb8-byte leak; 0x07 and 0x09 return 0; 0x0A is EPERM(1); 0x0B returns 0.
--
-- 1355a (results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt) called
-- 601(0x12, 0, struct) twice with struct = a mapped 0x20-byte block and got rv=-1 both times,
-- while the 13.60 body (results/kernel_handlers/asm/sys_601_deep.asm, block at ca0de6) says the
-- 0x12 branch copyins 0x20 bytes from arg2, sets bit 24 of [proc+0x528], stores qword0/qword1
-- into [proc+0x578]/[proc+0x580] and never checks a credential. The 13.60 jump table is at
-- 0x1a51160 and is not in any dumped region, so which block 14.10 dispatches 0x12 to is unknown.
--
-- Two entry gates are visible in the 13.60 text: `ca06de: test r12,r12 / jne exit` returns
-- ENOENT(0x16) when arg2 is non-null, and `test BYTE PTR [r8+0x529],0x1 / je exit` returns
-- EPERM(1) - i.e. -1 - when a process flag is clear. errno is therefore the only thing that
-- distinguishes "wrong argument slot" from "gate refused", and 1355a never printed it.
--
-- This probe prints rv AND the error string for every command 0x00-0x1A under four shapes
-- (null/null, arg1=B, arg2=B, both=B), with a 0xA5 canary over the first 0x40 bytes of B.
-- It also sends the 13.60 hardcoded verifier bytes {0xCD,0x41} to command 0x0C in both slots,
-- because the analysis calls that a "backdoor" and a success there may be what unlocks the
-- process-control branches that currently answer ENOENT.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--   probes/phase17_new_vectors/1194b_601_arg2_write_leak.lua (the errno idiom and skip list)
--   probes/phase17_new_vectors/1192a_601_dispatcher_command.lua (the lethal set)
--   results/kernel_handlers/analysis/sys_601_deep.md (command map, 0x0C "backdoor")
--   results/kernel_handlers/asm/sys_601_deep.asm (ca0630 entry, ca06de gates, ca0de6 store)

print("=== PROBE 1383b: 601 COMMAND x SHAPE MATRIX PART 2 ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hx(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end

local A = mk(20)
print(string.format("[0] pid=%d", N(A(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))))

local BLOB = memory.alloc(0x200)
local B = N(BLOB)
local PAINT = string.rep(string.char(0xA5), 0x200)
local sc = mk(601)

local SKIP = {[0x03]=true, [0x04]=true, [0x08]=true, [0x0C]=true, [0x1B]=true, [0x27]=true}

local function call(cmd, a1, a2, tag)
    pcall(function() memory.write_buffer(BLOB, PAINT) end)
    local ok, rv = pcall(function()
        return sc(uint64(cmd), uint64(a1), uint64(a2), uint64(0), uint64(0), uint64(0))
    end)
    local r = ok and N(rv) or -99999
    local e = es()
    local changed, first = 0, ""
    for i = 0, 71 do
        local v = rd(B + i * 4)
        if v ~= 0xA5A5A5A5 then
            changed = changed + 1
            if #first < 200 then first = first .. " " .. hx(v) end
        end
    end
    print(string.format("  %-22s rv=%-6s errno=%-22s wrote=%d%s", tag, tostring(r), ok and e or "EXC",
        changed, first ~= "" and ("[" .. first .. "]") or ""))
end

print("[A] shapes: 0/0, arg1=B, arg2=B, both=B")
for cmd = 0x0D, 0x1A do
    if not SKIP[cmd] then
        call(cmd, 0, 0, string.format("0x%02X 0/0", cmd))
        call(cmd, B, 0, string.format("0x%02X a1", cmd))
        call(cmd, 0, B, string.format("0x%02X a2", cmd))
        call(cmd, B, B, string.format("0x%02X a1a2", cmd))
    end
end

print("[C] after the verifier: does 0x12 change its answer?")
call(0x12, 0, B, "0x12 a2 post-0x0C")
call(0x00, 0, 0, "0x00 control")

print("=== PROBE 1383b COMPLETE ===")
