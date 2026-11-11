-- CRASH_CLASS: HIGH -- syscall 601 command 0x03 is expected to terminate the process. That is the
-- measurement, not a side effect: the run exists to put one printed line in front of the call so the
-- kill is observed rather than inferred from a loop's start index. Expect one relaunch afterward.
-- PROBE 1549a: 601 cmd 0x03 with a pre-printed call, so the death is attributed
--
-- WHY THIS IS WORTH A CONSOLE LIFE.
--   docs/DEAD_ENDS.md has recorded "601 commands 0x03 and 0x04 terminate the process" since 2026-10-22.
--   The two halves of that bullet are carried very differently:
--     * 0x04 is MEASURED. 1341d calls `601(0x04, ...)` from a child thread and prints
--       `[B] 601 cmd 0x04 from a child -- if the next 3 lines are missing, the death was process-wide`
--       immediately before it; the capture then ends in the loader's fault dump. That is a pre-printed
--       kill and it also shows the death is process-wide, not confined to the child.
--     * 0x03 is INFERRED. 323a loops from 0x03 and prints one line per command, after both argument
--       shapes; its capture shows `cmd 0x00`, `cmd 0x01`, `cmd 0x02` and then stops. The only thing
--       naming 0x03 as the dying command is the loop's order. 324a starts at 0x04, and 1383a/1383b
--       start above 0x0B, so nothing else reaches 0x03 with a line in front of it.
--   This probe gives 0x03 what 1341d already gave 0x04, which is the only shape the ledger treats as
--   a measurement (1541a, 1542a, 1543a are all pre-printed-call-then-EOF).
--
-- WHAT EACH OUTCOME MEANS.
--   1. `[A] CALL ...` printed, then nothing, and 9026 refuses connections afterwards -> 0x03 kills on
--      the documented shape and the row stops being an inference. This is the expected outcome.
--   2. `[A]` returns a value -> 0x03 is NOT a killer, so 323a died somewhere else in its 0x03
--      iteration (its fill loop, say) and the DEAD_ENDS bullet is wrong for 0x03. That is the more
--      interesting result and the row must be split. `[B]` and `[C]` then probe further.
--
-- WHY THE SHAPE IS `(cmd, page, 0x100)`.
--   323a's first iteration is exactly `sc(0x03, page, 0x100)` with `page` a 0x1000 heap buffer, and it
--   tries `(0, page)` as a second shape. Reproducing the shape is the point: a different shape would
--   leave open that 323a died on its arguments rather than on the command.
--
-- Prior art:
--   results/phase17_new_vectors/323a_sys601_sweep_20261022_122329.txt (prints 0x00-0x02, then stops)
--   results/phase35_dead_end_reruns/1341d_sys601_cmd04_child_20261109_100048.txt (0x04, pre-printed, process-wide)
--   results/phase17_new_vectors/322a_sys601_commands_20261022_122315.txt (0x05-0x14 measured, none lethal)
--   results/phase36_realargs/1538b_sys601_length_owner_sweep_20261110_154233.txt (0x00-0x26 swept, 0x03/0x04/0x1B in its SKIP list)
--   results/phase36_realargs/1541a_sys601_cmd1b_name_gate_20261110_161109.txt (the pre-print kill shape)
--   docs/MDBG_601_COMMAND_MAP_14_10.md, docs/DEAD_ENDS.md
--
-- WHAT THIS CANNOT SHOW. One command, one shape. It says nothing about 0x04 (already carried by 1341d)
-- and nothing about why the command is lethal -- only 601's own 13.60 body could answer that, and its
-- dispatch table is outside every dump.
--
-- RUN NOTE (2026-11-10). Sent once as `1549a_sys601_cmd03_printed_20261110_181253.txt`: pid 249,
-- `[A] CALL 601(0x03, 310A439E0, 100)` printed and then EOF, and 9026 answered CONNECTION_REFUSED
-- afterwards, so 0x03 kills and the [B]/[C]/[D] branch was never exercised. Review1549a later found
-- that those liveness rungs passed `arg2 = NULL` to cmd 0x00, which answers -1 on a healthy kernel --
-- the shape is now `(0x00, PAGE, 0)`, which 1538b measured as `rv = 0` with 0x100 written. The kill
-- row above is unaffected: it comes from [A] alone.
--
-- THIS PROBE DOES NOT WRITE TO THE PAGE. Every rung only passes a mapped pointer; if a command copies
-- into it, the value is printed, and no kernel address appears anywhere in the run.

print("=== PROBE 1549a: 601 cmd 0x03, pre-printed, one shape ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function es() local ok, s = pcall(function() return get_error_string() end) if ok and type(s) == "string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIG_IGN on the signals a refused call can raise. This cannot catch a deliberate termination -- a
-- kernel kill never returns to Lua -- but it costs nothing and removes one alternative explanation.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local sig_ok = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local ok, r = pcall(function() return N(mk(416)(uint64(s), uint64(N(sa)), uint64(0))) end)
    if ok and r == 0 then sig_ok = sig_ok + 1 end
end
print(string.format("[0] SIG_IGN accepted on %d/10 signals", sig_ok))

local sc = mk(601)
local PAGE = memory.alloc(0x1000)
local SENT = 0xB5B6B800
pcall(function() memory.write_dword(PAGE, SENT) end)
for i = 4, 0xFFC, 4 do pcall(function() memory.write_dword(PAGE + i, 0xB1B2B3B4) end) end
print(string.format("[0] page=%X first=%08X", N(PAGE), N(memory.read_dword(PAGE))))

local function peek()
    local a, b = 0, 0
    pcall(function() a = N(memory.read_dword(PAGE)) end)
    pcall(function() b = N(memory.read_dword(PAGE + 4)) end)
    return a, b
end

local function call(tag, a1, a2, a3)
    -- printed BEFORE the call: a kernel kill never returns, so this line is the whole attribution.
    print(string.format("  [%s] CALL 601(0x%02X, %X, %X)", tag, a1, a2, a3))
    local ok, rv = pcall(function() return sc(uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0), uint64(0)) end)
    if not ok then
        -- A pcall failure is a Lua-level error, not a kernel kill: a kill never reaches this branch.
        print(string.format("  [%s] pcall raised, no kernel answer", tag))
        return -999
    end
    local r = N(rv)
    local e = 0
    if r == -1 then e = es() end
    local d0, d1 = peek()
    print(string.format("  [%s] returned %d (%s) page=%08X %08X", tag, r, tostring(e), d0, d1))
    return r
end

print("[A] the 323a shape: cmd 0x03, pointer in arg2, 0x100 in arg3")
local a = call("A", 0x03, N(PAGE), 0x100)
if a == -999 then
    print("  [A] did not reach the kernel; this run answers nothing about 0x03")
    print(string.format("=== PROBE 1549a VOID pid=%s ===", tostring(PID)))
    return
end
print("  [A] 0x03 survived the documented shape; the DEAD_ENDS bullet is wrong for 0x03, and")
print("      323a must have died somewhere else inside its 0x03 iteration")

print("[B] liveness: 601(0x00, PAGE, 0) must still answer 0 with 0x100 in the page")
local b = call("B", 0x00, N(PAGE), 0)
print("[C] the mirrored shape: cmd 0x03 with the pointer in arg3")
local c = call("C", 0x03, 0, N(PAGE))
print("[D] one more liveness after both 0x03 shapes")
local d = call("D", 0x00, N(PAGE), 0)

print("")
print(string.format("[E] 0x03 arg2-pointer=%d  arg3-pointer=%d", a, c))
if b == 0 and d == 0 then
    print("  both 0x03 shapes returned and the process kept answering: 0x03 is not a killer here")
else
    print("  a liveness call failed after 0x03, so the 0x03 answers above are not trustworthy")
end
print(string.format("=== PROBE 1549a COMPLETE pid=%s ===", tostring(PID)))
