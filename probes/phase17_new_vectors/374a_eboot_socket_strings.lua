-- CRASH_CLASS: LOW
-- PROBE 374a: does the game's own code know the compositor socket
--
-- The daemon answers {size, command} with a fixed error for commands 2-6 and a
-- clean 16-byte reply for command 1, and nothing we put in the header changes it.
-- Guessing the rest of the protocol is hopeless unless the client side is visible.
-- eboot.bin is RX - readable - and this process is the game, so if the game ever
-- talks to that socket its code is in front of us. This probe finds the eboot text
-- region in the VM map, then reads it in 256 KiB chunks looking for the socket
-- names, which costs nothing and cannot fault outside the region.

print("=== PROBE 374a: SOCKET NAMES IN EBOOT ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi(a) return math.floor(a / 4294967296) end
local function lo(a) return a % 4294967296 end
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return 0 end

local info = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do pcall(function() memory.write_dword(info + i, 0) end) end
pcall(function() memory.write_dword(info, 0x160) end)
sgn(make_syscall(593)(uint64(0), uint64(to_num(info))))
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local text_base = hi(text_lo) * 4294967296 + lo(text_lo)
print(string.format("eboot text base = 0x%X%08X", hi(text_base), lo(text_base)))

-- [A] the region that contains it
local STRIDE, MAX = 72, 256
local buf = memory.alloc(STRIDE * MAX)
local countp = memory.alloc(16)
for i = 0, STRIDE * 4 - 1, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
for i = 0, 12, 4 do pcall(function() memory.write_dword(countp + i, 0) end) end
sgn(make_syscall(674)(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000)))
local count = rd(countp)
if count > MAX then count = MAX end
print(string.format("vm regions reported: %d", count))

local rstart, rend, rprot, rname = nil, nil, nil, "?"
for i = 0, count - 1 do
    local rec = buf + i * STRIDE
    local s = hi(rd(rec)) * 4294967296 + lo(rd(rec))
    local e = hi(rd(rec + 8)) * 4294967296 + lo(rd(rec + 8))
    if text_base >= s and text_base < e then
        rstart, rend, rprot = s, e, rd(rec + 0x18)
        break
    end
end
if not rstart then print("  text base is not inside any reported region") else
    print(string.format("  region 0x%X - 0x%X prot=0x%X size=0x%X",
        rstart, rend, rprot, rend - rstart))
end

if rstart then
    local CHUNK = 0x40000
    local patterns = {"/system_tmp", "GnmCompositor", "VrTracker", "AgcCompositor", "SceImageUtil"}
    local hits = 0
    local pos = rstart
    local chunks = 0
    while pos < rend and chunks < 1024 do
        local n = CHUNK
        if pos + n > rend then n = rend - pos end
        local s = nil
        local ok, v = pcall(function() return memory.read_buffer(pos, n) end)
        if ok then s = v end
        if not s then print(string.format("  read stopped at 0x%X", pos)) break end
        for _, pat in ipairs(patterns) do
            local from = 1
            while true do
                local a, b = string.find(s, pat, from, true)
                if not a then break end
                hits = hits + 1
                if hits <= 12 then
                    print(string.format("  %s at 0x%X", pat, pos + a - 1))
                end
                from = b + 1
            end
        end
        pos = pos + n
        chunks = chunks + 1
    end
    print(string.format("  scanned 0x%X bytes, %d hits", pos - rstart, hits))
end

print("")
print("=== 374a DONE ===")
