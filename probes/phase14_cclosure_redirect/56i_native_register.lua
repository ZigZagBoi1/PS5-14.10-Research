-- CRASH_CLASS: LOW
-- PROBE 56i: Test native.register() and get_lua_opt() to populate addrofs
--
-- Context: native.addrofs is nil but native.register and native.get_lua_opt exist.
-- Need to find if register() can set up threading addresses.
-- Also fix module name extraction (read bytes not dwords).

print("=== PROBE 56i: NATIVE REGISTER TEST ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- SECTION A: Test native.register()
print("")
print("--- A: NATIVE.REGISTER ---")

-- Enumerate all native table keys first
print("native keys:")
for k, v in pairs(native) do
    print("  " .. tostring(k) .. " = " .. type(v))
end

-- Try register with no args
local ok1, r1 = pcall(function() return native.register() end)
print("register() ok=" .. tostring(ok1) .. " ret=" .. tostring(r1))

-- Try register with various string args
local ok2, r2 = pcall(function() return native.register("addrofs") end)
print("register('addrofs') ok=" .. tostring(ok2) .. " ret=" .. tostring(r2))

-- Check if addrofs appeared after register
print("addrofs after register=" .. tostring(native.addrofs))

-- SECTION B: Test native.get_lua_opt()
print("")
print("--- B: GET_LUA_OPT ---")

local opt_names = {"addrofs", "libc_addrofs", "Thrd_create", "Thrd_join",
    "Atomic_fetch_add_8", "config", "debug", "version", "loader",
    "pipe", "syscall", "memory", "native", "rop", "chain"}

for _, name in ipairs(opt_names) do
    local ok, ret = pcall(function() return native.get_lua_opt(name) end)
    if ok and ret ~= nil then
        print("  " .. name .. " = " .. tostring(ret) .. " (" .. type(ret) .. ")")
    end
end

-- Try get_lua_opt with no args
local ok3, r3 = pcall(function() return native.get_lua_opt() end)
print("get_lua_opt() ok=" .. tostring(ok3) .. " ret=" .. tostring(r3))

-- SECTION C: Check native.fcall
print("")
print("--- C: NATIVE.FCALL ---")
if native.fcall then
    print("fcall exists, type=" .. type(native.fcall))
    -- Try calling it to see its signature
    local ok4, r4 = pcall(function() return native.fcall() end)
    print("fcall() ok=" .. tostring(ok4) .. " ret=" .. tostring(r4))
end

-- SECTION D: Check pivot_handler_rop for address clues
print("")
print("--- D: PIVOT HANDLER ---")
if native.pivot_handler_rop then
    local rop_str = tostring(native.pivot_handler_rop)
    -- Print first 500 chars
    if #rop_str > 500 then
        print(rop_str:sub(1, 500))
    else
        print(rop_str)
    end
end

-- SECTION E: Module names via byte read
print("")
print("--- E: MODULE NAMES ---")
local info = memory.alloc(0x200)
local sc_info = make_syscall(593)

for handle = 0, 50 do
    for i = 0, 0x1FF do
        pcall(function() memory.write_byte(info + i, 0) end)
    end
    pcall(function() memory.write_dword(info, 0x160) end)

    local ok, ret = pcall(function()
        return sc_info(uint64(handle), uint64(to_num(info)))
    end)
    if ok and to_num(ret) == 0 then
        -- Read name bytes at offset +4
        local name_chars = {}
        for i = 0, 63 do
            local ok_b, b = pcall(function() return memory.read_byte(info + 4 + i) end)
            if ok_b then
                b = to_num(b)
                if b > 0 and b < 128 then
                    name_chars[#name_chars + 1] = string.char(b)
                else
                    break
                end
            else
                break
            end
        end
        local name = table.concat(name_chars)

        -- Also try reading name at other offsets if empty
        if #name == 0 then
            -- Try offset +0x08 (some structs have padding)
            for _, noff in ipairs({0x08, 0x10, 0x04, 0x00}) do
                local nc2 = {}
                for i = 0, 31 do
                    local ok_b, b = pcall(function() return memory.read_byte(info + noff + i) end)
                    if ok_b then
                        b = to_num(b)
                        if b >= 0x20 and b < 0x7F then
                            nc2[#nc2 + 1] = string.char(b)
                        elseif b == 0 and #nc2 > 0 then
                            break
                        else
                            nc2 = {}
                            break
                        end
                    end
                end
                if #nc2 > 2 then
                    name = "[@" .. string.format("0x%X", noff) .. "]" .. table.concat(nc2)
                    break
                end
            end
        end

        -- Read text base
        local text_q = safe_rq(info + 0x108)
        local th, tl = get_hi_lo(text_q)

        print(string.format("  h=%d name='%s' text=0x%X_%08X",
            handle, name, th, tl))
    end
end

print("")
print("canary=" .. pid)
print("=== PROBE 56i COMPLETE ===")
