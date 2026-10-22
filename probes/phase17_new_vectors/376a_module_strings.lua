-- CRASH_CLASS: LOW
-- PROBE 376a: which module knows the system socket names
--
-- 375a showed the module layout: text is p=0x4 (execute-only, unreadable), while
-- .rodata and .data are p=0x1 or p=0x3, which read fine. eboot's text has no
-- reference to any of the socket names, so the client is a system library if it
-- exists at all. This probe reads every readable region up to 8 MiB and looks for
-- the socket names, reporting the region and offset of each hit.

print("=== PROBE 376a: SOCKET NAMES IN MODULES ===")
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
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return 0 end
local function rb(a) local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end return 0 end
local function hi(a) return math.floor(a / 4294967296) end
local function lo(a) return a % 4294967296 end

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX)
local countp = memory.alloc(16)
for i = 0, STRIDE * 4 - 1, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
for i = 0, 12, 4 do pcall(function() memory.write_dword(countp + i, 0) end) end
make_syscall(674)(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
local count = rd(countp)
if count > MAX then count = MAX end

local patterns = {"/system_tmp", "GnmCompositor", "VrTracker", "AgcCompositor", "system_tmp/"}
local CHUNK = 0x40000
local total_scanned = 0
local hits = 0
local scanned_regions = 0

for i = 0, count - 1 do
    local rec = buf + i * STRIDE
    local s = hi(rd(rec)) * 4294967296 + lo(rd(rec))
    local e = hi(rd(rec + 8)) * 4294967296 + lo(rd(rec + 8))
    local prot = rd(rec + 0x18)
    local name = {}
    for k = 0, 31 do
        local c = rb(rec + 0x20 + k)
        if c == 0 then break end
        if c >= 32 and c < 127 then name[#name + 1] = string.char(c) end
    end
    local nm = table.concat(name)
    local size = e - s
    -- only module data: .sprx names, readable protection, and never the low
    -- device mappings at 0x0-0x1328000 that killed 376a's first revision
    local readable = (prot == 1 or prot == 3 or prot == 5) and s >= 0x10000
    local is_module = string.find(nm, ".sprx", 1, true) ~= nil
    if readable and is_module and size > 0 and size <= 0x800000 then
        scanned_regions = scanned_regions + 1
        local pos = s
        while pos < e do
            local n = CHUNK
            if pos + n > e then n = e - pos end
            local ok, v = pcall(function() return memory.read_buffer(pos, n) end)
            if not ok or not v then break end
            for _, pat in ipairs(patterns) do
                local from = 1
                while true do
                    local a, b = string.find(v, pat, from, true)
                    if not a then break end
                    hits = hits + 1
                    if hits <= 20 then
                        print(string.format("  %-28s 0x%X  %s", nm, pos + a - 1, pat))
                    end
                    from = b + 1
                end
            end
            total_scanned = total_scanned + n
            pos = pos + n
        end
    end
end

print("")
print(string.format("regions scanned: %d   bytes scanned: 0x%X   hits: %d", scanned_regions, total_scanned, hits))

print("")
print("=== 376a DONE ===")
