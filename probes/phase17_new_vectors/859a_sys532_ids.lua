-- CRASH_CLASS: HIGH
-- PROBE 859a: SYS 532 ID ENUMERATION
--
-- Context: 858a gave 532 a real 0x18-byte record in arg4. With record[0] == 0
-- the status is 0x800D0203; with record[0] != 0 it is 0x800D0204, i.e. the
-- handler looks the first dword up in a table and reports "not found". Command
-- 0x1E instead WRITES a value into the status dword (0 for id 0, 3 for a
-- non-zero id).
--
-- This probe sweeps record[0] over the plausible id ranges for each command and
-- prints only the answers that are not the two known codes, so a valid id shows
-- up immediately in the log even if the process dies later.

print("=== PROBE 859a: SYS 532 ID ENUMERATION ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X",
        math.floor(a / 4294967296), a % 4294967296))
end
local function hex(v)
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("%016X", n)
end

local sc532 = make_syscall(532)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local st = to_num(memory.alloc(0x1000))
local rec = to_num(memory.alloc(0x1000))

local function zero(p, n)
    for i = 0, n - 1 do memory.write_dword(p + i * 4, 0) end
end
local function d(p, i)
    return to_num(memory.read_dword(p + i * 4))
end

-- returns nil on pcall failure, else the status dword
local function probe(cmd, id)
    memory.write_dword(st, 0)
    memory.write_dword(rec, id)
    local ok = pcall(function() return sc532(U(cmd), U(0), U(st), U(rec), U(0)) end)
    if not ok then return nil end
    return to_num(memory.read_dword(st))
end

print(string.format("[0] pid=%s", tostring(make_syscall(20)())))
print("")

local KNOWN = { ["800D0203"] = true, ["800D0204"] = true }
local CMDS = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x20}
local CMDS_B = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x20}

-- candidate ids first: values seen elsewhere in this kernel surface
local CAND = {0x19810000, 0x1000, 0x1001, 0x2000, 0x2001, 0x10000, 0x4000,
              0x4205, 0x2205, 0x6205, 0x1FC, 0x1FD, 0x206, 0x2AA, 0x2AB}

print("[A] candidate ids")
for _, cmd in ipairs(CMDS) do
    for _, id in ipairs(CAND) do
        local s = probe(cmd, id)
        local code = s == nil and "PCALLFAIL" or string.format("%08X", s)
        if s == nil or not KNOWN[code] then
            print(string.format("[A] cmd=%02X id=%08X -> %s %08X %08X",
                cmd, id, code, d(st, 1), d(st, 2)))
        end
    end
end
print("[A] done")
print("")

print("[B] sweep 1..0x1000")
for _, cmd in ipairs(CMDS_B) do
    local hits = 0
    for id = 1, 0x1000 do
        local s = probe(cmd, id)
        if s == nil then
            print(string.format("[B] cmd=%02X id=%08X PCALLFAIL - stopping", cmd, id))
            break
        end
        local code = string.format("%08X", s)
        if not KNOWN[code] then
            print(string.format("[B] cmd=%02X id=%08X -> %s %08X %08X",
                cmd, id, code, d(st, 1), d(st, 2)))
            hits = hits + 1
            if hits > 24 then print("[B] cmd=" .. string.format("%02X", cmd) .. " more hits suppressed") break end
        end
    end
    print(string.format("[B] cmd=%02X sweep done", cmd))
end
print("")

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local s = "h859" .. tag
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 859a COMPLETE ===")
