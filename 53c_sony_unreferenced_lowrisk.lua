-- CRASH_CLASS: MODERATE
-- PROBE 53c: conservative zero-argument survey of unreferenced Sony slots
--
-- Context: The dump lists Sony/private syscall slots that have no probe yet.
-- This first pass uses zero arguments only, fences every call with a canary,
-- and stops after the first abnormal result. Do not combine with pointer-rich
-- structures until a slot survives this baseline on an isolated connection.

print("=== PROBE 53c: SONY UNREFERENCED LOW-RISK ===")
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
local function call0(num)
    local sc = make_syscall(num)
    local t0 = os.clock()
    local ok, ret = pcall(function() return sc() end)
    local dt = os.clock() - t0
    print(string.format("  syscall=%d ok=%s ret=%d (0x%X) cpu_time=%.6f", num, tostring(ok), to_num(ret), to_num(ret), dt))
    return ok
end

-- Slots absent from the current probe references, selected before the known
-- destructive/high-risk cluster 661-675. One connection may still be killed
-- by Sony's handler; record the last printed syscall and rerun it alone.
local candidates = {533, 534, 535, 536, 540, 541, 543, 545, 546, 551,
    553, 554, 555, 556, 558, 567, 587, 598, 602, 603, 604, 610, 611,
    613, 615, 619, 623, 625, 626, 627, 630, 635, 636, 638, 639, 641,
    642, 649, 653, 654, 655, 656, 657, 658, 659, 660}
local i = 1
while i <= #candidates do
    print("--- candidate " .. tostring(i) .. "/" .. tostring(#candidates) .. " ---")
    local ok = call0(candidates[i])
    if not ok then
        print("  abnormal Lua result; stop and isolate this syscall")
        break
    end
    i = i + 1
end
print("=== 53c COMPLETE ===")
