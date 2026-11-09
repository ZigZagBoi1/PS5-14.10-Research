-- CRASH_CLASS: HIGH
-- PROBE 540a: sys 625 index guard on the admitted commands
--
-- Context: commands 17..20 accept domain 0 with a nonzero value and return 0;
-- 21..23 accept only value 0; everything else is -1. The dossier's writes are
-- indexed (0xc0010230+2*index, 0xc0010240+2*index, 0xc0010188+2*index) with
-- index -1 meaning "all", and a hardware-dependent maximum of 3 or 7.
--
-- This probe maps the index guard for the four admitted commands and for the
-- three zero-only ones, without changing the value from 1.

print("=== PROBE 540a: SYS 625 INDEX MAP ===")
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

local idxs = {0xFFFFFFFF, 0, 1, 2, 3, 4, 5, 6, 7, 8}
for cmd = 17, 23 do
    local line = string.format("cmd=%2d", cmd)
    for i = 1, #idxs do
        local ret = -999
        pcall(function()
            ret = N(sc625(uint64(cmd), uint64(0), uint64(idxs[i]), uint64(1)))
        end)
        line = line .. string.format(" i%X=%d", idxs[i], ret)
    end
    print(line)
end
print("=== DONE ===")
