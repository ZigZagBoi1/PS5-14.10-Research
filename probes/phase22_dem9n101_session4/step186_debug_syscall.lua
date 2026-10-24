-- step186: Debug make_syscall and getsockopt
print("=== STEP186 ===")

local function tn(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rq(a) return memory.read_qword(a) end
local function wq(a, v) memory.write_qword(a, v) end
local function rd(a) return memory.read_dword(a) end
local function wd(a, v) memory.write_dword(a, v) end
local function wb(a, v) memory.write_byte(a, v) end
local Z = uint64(0)

-- T1: Check if make_syscall exists
print("---T1: available functions---")
print("make_syscall type=" .. type(make_syscall))
print("syscall type=" .. type(syscall))

-- Check syscall table keys
local skeys = {}
for k, v in pairs(syscall) do
    table.insert(skeys, k .. "=" .. type(v))
end
print("syscall keys: " .. table.concat(skeys, ", "))

-- T2: Try calling make_syscall(593) with error details
print("---T2: syscall 593 test---")
local ok, err = pcall(function()
    local sc593 = make_syscall(593)
    print("sc593 type=" .. type(sc593))

    local info = memory.alloc(0x200)
    for i = 0, 0x1FF do wb(info + i, 0) end
    wd(info, 0x160)

    local rv = sc593(Z, info, Z, Z, Z, Z)
    print("rv=" .. tostring(rv))

    -- Print size field back
    print("struct_size=" .. rd(info))

    -- Dump first 20 qwords
    for off = 0, 0x9F, 8 do
        local v = rq(info + off)
        if tn(v) ~= 0 then
            print(string.format("  +%03x: %s", off, tostring(v)))
        end
    end
end)
if not ok then print("ERR: " .. tostring(err)) end

-- T3: Try dynlib_get_list (592) first
print("---T3: syscall 592 test---")
local ok2, err2 = pcall(function()
    local sc592 = make_syscall(592)
    print("sc592 type=" .. type(sc592))

    local id_buf = memory.alloc(0x400)
    local cnt = memory.alloc(8)
    wq(cnt, uint64(0x40))

    local rv = sc592(id_buf, cnt, Z, Z, Z, Z)
    print("rv=" .. tostring(rv))
    local mc = tn(rq(cnt))
    print("modules=" .. mc)
    if mc > 0 then
        -- Print first 5 module IDs
        for i = 0, math.min(mc - 1, 4) do
            print("  id[" .. i .. "]=" .. rd(id_buf + i * 4))
        end
    end
end)
if not ok2 then print("ERR: " .. tostring(err2)) end

-- T4: getsockopt with direct syscall number
print("---T4: getsockopt via make_syscall---")
local ok3, err3 = pcall(function()
    syscall.resolve({ socket = 97, setsockopt = 105, close = 6 })

    local s = syscall.socket(uint64(28), uint64(2), Z)
    print("sock=" .. tostring(s))

    -- Set PKTINFO
    local pk = memory.alloc(0x20)
    for i = 0, 0x1F do wb(pk + i, 0) end
    local rv_set = syscall.setsockopt(s, uint64(41), uint64(46), pk, uint64(20))
    print("set=" .. tostring(rv_set))

    -- getsockopt = syscall 118
    local sc118 = make_syscall(118)
    local buf = memory.alloc(0x100)
    local olen = memory.alloc(4)
    for i = 0, 0xFF do wb(buf + i, 0xDD) end
    wd(olen, 256)
    local rv_get = sc118(s, uint64(41), uint64(46), buf, olen, Z)
    print("get=" .. tostring(rv_get))
    local got_len = rd(olen)
    print("len=" .. got_len)

    -- Dump returned bytes
    if got_len > 0 then
        for i = 0, math.min(got_len - 1, 31) do
            local b = tn(memory.read_byte(buf + i))
            if i % 8 == 0 then
                local line = string.format("  +%02x:", i)
                for j = 0, math.min(7, got_len - i - 1) do
                    line = line .. string.format(" %02x", tn(memory.read_byte(buf + i + j)))
                end
                print(line)
            end
        end
    end

    syscall.close(s)
end)
if not ok3 then print("ERR: " .. tostring(err3)) end

-- T5: Check if resolved syscalls need uint64 wrappers
print("---T5: getsockopt via resolve---")
local ok4, err4 = pcall(function()
    syscall.resolve({ getsockopt = 118 })
    local s = syscall.socket(uint64(28), uint64(2), Z)
    print("s=" .. tostring(s))

    local pk = memory.alloc(0x20)
    for i = 0, 0x1F do wb(pk + i, 0) end
    syscall.setsockopt(s, uint64(41), uint64(46), pk, uint64(20))

    local buf = memory.alloc(0x100)
    local olen = memory.alloc(4)
    wd(olen, 0x100)
    local rv = syscall.getsockopt(s, uint64(41), uint64(46), buf, olen)
    print("rv=" .. tostring(rv))
    print("len=" .. rd(olen))

    syscall.close(s)
end)
if not ok4 then print("ERR: " .. tostring(err4)) end

print("=== STEP186_DONE ===")
