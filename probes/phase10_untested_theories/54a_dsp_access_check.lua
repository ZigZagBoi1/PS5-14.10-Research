-- CRASH_CLASS: LOW
-- PROBE 54a: /dev/dsp availability check for CVE-2026-45258
--
-- This is an access-only check. It performs open(O_RDONLY) and closes any
-- returned descriptor. It does not issue ioctl(), mmap(), or overflow inputs.

print("=== PROBE 54a: /dev/dsp ACCESS CHECK ===")
print("scope: open/close only; no mmap or ioctl")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

-- /dev/null is a positive control for syscall 5 and this loader path.
local paths = {"/dev/null", "/dev/dsp", "/dev/dsp0.0", "/dev/sndstat"}
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end

for _, path in ipairs(paths) do
    local buf = memory.alloc(#path + 1)
    for i = 1, #path do memory.write_byte(buf + i - 1, string.byte(path, i)) end
    memory.write_byte(buf + #path, 0)

    local ok, fd = pcall(function() return sc_open(buf, 0, 0) end)
    if not ok then
        print(path .. ": OPEN_ERROR " .. tostring(fd))
    else
        local n = to_num(fd)
        if n >= 0 then
            print(path .. ": OPEN_OK fd=" .. tostring(n) .. " (closing immediately)")
            local close_ok, close_ret = pcall(function() return sc_close(fd) end)
            print(path .. ": CLOSE_" .. (close_ok and "RESULT " .. tostring(close_ret) or "ERROR " .. tostring(close_ret)))
        else
            print(path .. ": OPEN_DENIED_OR_ABSENT ret=" .. tostring(fd))
        end
    end
end

print("RESULT_LIMIT: accessibility only; CVE trigger and patch state not tested")
print("=== PROBE 54a COMPLETE ===")
