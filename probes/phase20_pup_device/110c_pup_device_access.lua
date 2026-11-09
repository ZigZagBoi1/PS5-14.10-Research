-- CRASH_CLASS: LOW
-- Open/close only. No PUP input, ioctl, decryption, or install action.
print("=== PROBE 110c: PUP DEVICE ACCESS ===")

local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local function cstr(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    memory.write_byte(p + #s, 0)
    return p
end

local open = sc(5)
local close = sc(6)
print("pid=" .. num(sc(20)()))
for _, path in ipairs({"/dev/null", "/dev/pup_update0"}) do
    local ok, rv = pcall(function()
        return open(uint64(cstr(path)), uint64(2), uint64(0)) -- O_RDWR
    end)
    if not ok then
        print(path .. " open_exception=" .. tostring(rv))
    else
        local fd = num(rv)
        print(path .. " open_rdwr=" .. tostring(rv))
        if fd >= 0 then
            local cok, crv = pcall(function() return close(uint64(fd)) end)
            print(path .. " close_ok=" .. tostring(cok) .. " close_rv=" .. tostring(crv))
        end
    end
end
print("canary_pid=" .. num(sc(20)()))
print("=== PROBE 110c COMPLETE ===")
