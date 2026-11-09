-- CRASH_CLASS: HIGH
-- PROBE 536a: sys 625 has never been called
--
-- Context: results/kernel_handlers/analysis says sys 625 is narg=4
-- (command, domain, index, value), writes the caller's 64-bit value to
-- 0xc0010231 / 0xc0010240 / 0xc0010188 + 2*index, accepts (command-1) <= 22,
-- and reads no credential in its root. Probes 54a2 and 54k called 626 and 567
-- (RDMSR) instead; 625 itself has no capture anywhere in the repository.
--
-- Everything here uses value 0, the least destructive value available, and
-- commands outside 1..22 to see the rejection shape first.

print("=== PROBE 536a: SYS 625 ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local sc625 = mk(625)

local function call(tag, cmd, dom, idx, val)
    local ret = -999
    pcall(function()
        ret = N(sc625(uint64(cmd), uint64(dom), uint64(idx), uint64(val)))
    end)
    print(string.format("%s cmd=%08X dom=%X idx=%X val=%X ret=%d", tag, cmd, dom, idx, val, ret))
end

call("invalid", 0, 0, 0, 0)
call("invalid", 23, 0, 0, 0)
call("invalid", 0xFFFFFFFF, 0, 0, 0)
for c = 1, 22 do call("zero", c, 0, 0, 0) end
call("zero", 1, 1, 0, 0)
call("zero", 1, 2, 0, 0)
call("zero", 1, 3, 0, 0)
call("zero", 1, 0, 1, 0)
call("zero", 1, 0, 22, 0)
print("=== DONE ===")
