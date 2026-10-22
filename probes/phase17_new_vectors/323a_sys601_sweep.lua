-- CRASH_CLASS: MODERATE
-- PROBE 323a: which of the 40 sys 601 commands write anything into a caller buffer?
--
-- 322a: cmd 0x00 returned 0 and put 0x00000100 in the first word. The commands
-- the dossier marks as leaks (0x05 process info, 0x10 kernel allocation, 0x12
-- process write) all returned -1, which reads as "no debug session".
--
-- The page is pre-filled with a sentinel, so any command that copies out
-- changes it. Both argument orders are tried for every command in the table
-- (0x00-0x27), which is the cheap way to find a command that answers with data
-- instead of guessing one at a time.

print("=== PROBE 323a: SYS 601 command sweep ===")

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
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, to_num(v.l) end
    return 0, to_num(v)
end
local function sgn(v)
    local h, l = hi_lo(v)
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function U32(v) return uint64(v) end
local function U64(x) return uint64(string.format("0x%X", x)) end

local sc = make_syscall(601)
local page = memory.alloc(0x1000)
local SENT = 0xB1B2B3B4
local function fill()
    for i = 0, 0xFFC, 8 do pcall(function() memory.write_qword(page + i, uint64(0xB1B2B3B4B5B6B7B8)) end) end
end
local function peek()
    return string.format("%08X %08X", to_num(memory.read_dword(page)), to_num(memory.read_dword(page + 4)))
end
local function changed()
    return to_num(memory.read_dword(page)) ~= SENT
end

for cmd = 0x00, 0x27 do
    local line = string.format("cmd 0x%02X:", cmd)
    for _, shape in ipairs({"buf,size", "0,buf"}) do
        fill()
        local ok, rv = pcall(function()
            if shape == "buf,size" then
                return sc(U32(cmd), uint64(page), U64(0x100))
            else
                return sc(U32(cmd), uint64(0), uint64(page))
            end
        end)
        if not ok then
            line = line .. string.format("  [%s DIED]", shape)
        else
            line = line .. string.format("  [%s ret=%d %s%s]", shape, sgn(rv), peek(),
                changed() and " *" or "")
        end
    end
    print(line)
end

print("")
print("(* = the command changed the caller buffer)")
print("=== PROBE 323a COMPLETE ===")
