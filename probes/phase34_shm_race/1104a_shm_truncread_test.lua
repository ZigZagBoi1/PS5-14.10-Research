-- CRASH_CLASS: HIGH
-- PROBE 1104a: Does reading a truncated-away shm page kill past pcall?
--
-- If yes, the ftruncate race can't use parent reads on boundary pages.
-- We need to know this before investing more in the race approach.

print("=== PROBE 1104a: SHM TRUNCATED PAGE READ TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc477 = mk(477)
local sc480 = mk(480)
local sc482 = mk(482)

local LARGE = 0x40000  -- 256KB = 16 pages
local SMALL = 0x4000   -- 16KB = 1 page

-- [A] Create shm, map at LARGE, write sentinels
print("[A] setup")
local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
if shm_fd < 0 then print("FAIL") return end

N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
print("map=" .. fmt(map))

for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end
print("sentinels written")

-- [B] Read all pages - should work
print("")
print("[B] read all pages (before truncation)")
for p = 0, 15 do
    local v = rd(map_n + p * 0x4000)
    print(string.format("  page %d: 0x%X", p, v or -1))
end
print("alive=" .. tostring(alive()))

-- [C] Truncate to SMALL (1 page)
print("")
print("[C] ftruncate to SMALL (1 page)")
local ret = N(native.fcall_with_rax(stub, 480, shm_fd, SMALL))
print("ftruncate ret=" .. ret)

-- [D] Read page 0 (should still be valid)
print("")
print("[D] read page 0 (still within truncated size)")
local v0 = rd(map_n)
print("page 0: " .. (v0 and string.format("0x%X", v0) or "nil"))
print("alive=" .. tostring(alive()))

-- [E] Read page 1 (BEYOND truncated size - THIS IS THE KEY TEST)
print("")
print("[E] read page 1 (BEYOND truncated size)")
print("about to read...")
local ok_e, val_e = pcall(function()
    return memory.read_dword(uint64(map_n + 0x4000))
end)
if ok_e then
    print("page 1 read OK: " .. (val_e and string.format("0x%X", N(val_e)) or "nil"))
else
    print("page 1 read PCALL CAUGHT: " .. tostring(val_e))
end
print("alive=" .. tostring(alive()))

-- [F] If we survived, read remaining pages
print("")
print("[F] read remaining pages")
for p = 2, 15 do
    local ok_f, val_f = pcall(function()
        return memory.read_dword(uint64(map_n + p * 0x4000))
    end)
    if ok_f then
        print(string.format("  page %d: 0x%X", p, N(val_f)))
    else
        print(string.format("  page %d: PCALL CAUGHT", p))
    end
end
print("alive=" .. tostring(alive()))

-- [G] Re-expand to LARGE
print("")
print("[G] ftruncate back to LARGE")
local ret2 = N(native.fcall_with_rax(stub, 480, shm_fd, LARGE))
print("ftruncate ret=" .. ret2)

-- [H] Read all pages after re-expansion
print("")
print("[H] read all pages after re-expansion")
for p = 0, 15 do
    local ok_h, val_h = pcall(function()
        return memory.read_dword(uint64(map_n + p * 0x4000))
    end)
    if ok_h then
        local v = N(val_h)
        local tag = ""
        if v == 0 then tag = " (ZEROED)" end
        if v == (0xAA000000 + p) then tag = " (sentinel)" end
        print(string.format("  page %d: 0x%X%s", p, v, tag))
    else
        print(string.format("  page %d: PCALL CAUGHT", p))
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 1104a COMPLETE ===")
