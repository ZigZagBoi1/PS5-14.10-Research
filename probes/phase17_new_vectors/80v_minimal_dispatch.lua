-- CRASH_CLASS: LOW
-- PROBE 80v: Minimal dispatch info — just print everything

print("=== PROBE 80v ===")

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

syscall.resolve({ sc_getpid = 20 })
print("pid=" .. syscall.sc_getpid():tonumber())

-- Step 1: pipe_str
local ps = tostring(syscall.pipe)
print("pipe_len=" .. #ps)
-- Print in chunks
for i = 1, #ps, 120 do
    print("PS:" .. ps:sub(i, i + 119))
end

-- Step 2: metatable
local mt = getmetatable(syscall.pipe)
if mt then
    print("MT_FOUND")
    for k, v in pairs(mt) do
        print("MT:" .. tostring(k) .. "=" .. tostring(v))
    end
    if mt.__call then
        print("CALL_TYPE=" .. type(mt.__call))
        print("CALL_STR=" .. tostring(mt.__call))
    end
    if mt.__index and type(mt.__index) == "table" then
        for k, v in pairs(mt.__index) do
            print("IDX:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
else
    print("NO_MT")
end

-- Step 3: Try reading CClosure +0x20 for all functions found
local funcs = {}
if mt then
    if mt.__call then table.insert(funcs, {"__call", mt.__call}) end
    if mt.__index and type(mt.__index) == "table" then
        for k, v in pairs(mt.__index) do
            if type(v) == "function" then
                table.insert(funcs, {k, v})
            end
        end
    end
end

-- Get eboot base for comparison
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = to_num(pcall(function() return memory.read_dword(info + 0x108) end) or 0)
local eb_hi = to_num(pcall(function() return memory.read_dword(info + 0x10C) end) or 0)

local ok1, v1 = pcall(function() return memory.read_dword(info + 0x108) end)
local ok2, v2 = pcall(function() return memory.read_dword(info + 0x10C) end)
if ok1 then eb_lo = to_num(v1) end
if ok2 then eb_hi = to_num(v2) end
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

for _, pair in ipairs(funcs) do
    local name = pair[1]
    local fn = pair[2]
    local s = tostring(fn)
    -- Try parsing address
    local hex = s:match("function:%s*(%x+)")
    if hex then
        -- Read +0x20 using uint64
        local ok, addr = pcall(function() return uint64("0x" .. hex) end)
        if ok and addr then
            local ok2, cfp = pcall(function() return memory.read_qword(addr + 0x20) end)
            if ok2 and cfp then
                local h, l = 0, 0
                if type(cfp) == "table" and cfp.h then h = cfp.h; l = cfp.l
                else l = to_num(cfp) end
                print(string.format("FUNC:%s addr=0x%s cfunc=0x%X%08X", name, hex, h, l))
                if h == eb_hi then
                    print(string.format("  EBOOT_OFF=+0x%X", l - eb_lo))
                end
            else
                print("FUNC:" .. name .. " addr=0x" .. hex .. " READ_FAIL")
            end
        end
    end
end

-- Step 4: fn_addr slot dump
local fn_str = ps:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if fn_str then
    print("FN_SLOT=" .. fn_str)
    local ok, fn_addr = pcall(function() return uint64(fn_str) end)
    if ok and fn_addr then
        for off = -0x10, 0x70, 8 do
            local ok3, v3 = pcall(function() return memory.read_qword(fn_addr + off) end)
            if ok3 and v3 then
                local h, l = 0, 0
                if type(v3) == "table" and v3.h then h = v3.h; l = v3.l
                else l = to_num(v3) end
                print(string.format("FN%+d: 0x%X%08X", off, h, l))
            end
        end
    end
end

print("=== PROBE 80v COMPLETE ===")
