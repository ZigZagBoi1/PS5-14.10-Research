-- CRASH_CLASS: LOW
-- PROBE 940a: can the loader open the file behind an executable mapping?
--
-- Context: 939e proved mmap strips PROT_EXEC at entry creation, so no mapping
-- we create can run.  The one remaining shape that can produce executable
-- memory is a mapping the kernel already made executable (module text, eboot)
-- sharing a page cache page with a mapping we are allowed to write.
--
-- That requires three things, all measured here:
--   A: open(5) O_RDONLY on the game's eboot.bin (path probe, no write)
--   B: whether MAP_SHARED prot=1 of that fd returns the ELF header bytes
--   C: whether O_RDWR is granted at all (the decisive permission)
--   D: the same for a .sprx under /app0 if one is reachable
--
-- Nothing is written to any file; this probe only reads.

print("=== PROBE 940a: FILE BEHIND AN EXECUTABLE MAPPING ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return nil end
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end

local sc_open, sc_mmap = mk(5), mk(477)
local PAGE = 0x4000

print("[0] pid=" .. tostring(call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)))

local candidates = {
    "/app0/eboot.bin",
    "/app0/eboot.bin.sprx",
    "/app0/image0/eboot.bin",
    "/savedata0/misc.lua",
}

for _, path in ipairs(candidates) do
    local fro = call(function() return sc_open(path, uint64(0), uint64(0)) end)
    local frw = call(function() return sc_open(path, uint64(0x2), uint64(0)) end)
    print(string.format("[A] open(%s) O_RDONLY=%s O_RDWR=%s", path, tostring(fro), tostring(frw)))
    if type(fro) == "number" and fro >= 0 then
        local m = call(function() return sc_mmap(uint64(0), uint64(PAGE), uint64(1), uint64(0x1), uint64(fro), uint64(0)) end)  -- MAP_SHARED prot=1
        if type(m) == "number" and m > 0 then
            local hi, lo = rd(m + 4) or 0, rd(m) or 0
            print(string.format("[B]   MAP_SHARED prot=1 -> 0x%X first8=0x%08X%08X", m, hi, lo))
        else
            print("[B]   MAP_SHARED prot=1 -> " .. tostring(m))
        end
        -- write permission on the shared mapping tells us if the fd is writable
        local mw = call(function() return sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(0x1), uint64(fro), uint64(0)) end)
        print("[C]   MAP_SHARED prot=3 -> " .. tostring(mw))
    end
end

print("")
print("=== PROBE 940a COMPLETE ===")
