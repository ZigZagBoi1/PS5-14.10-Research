print("=== PROBE 58f: MSYNC DMEM ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local sc_open  = make_syscall(5)
local sc_close = make_syscall(6)
local sc_mmap  = make_syscall(477)
local sc_msync = make_syscall(65)
local sc_munmap = make_syscall(73)
local PAGE = 0x4000

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- Open /dev/dmem0 with O_RDWR=2
local pb = memory.alloc(32)
local s = "/dev/dmem0"
for i = 1, #s do memory.write_byte(pb + i - 1, string.byte(s, i)) end
memory.write_byte(pb + #s, 0)

print("opening dmem0")
local ok_o, fd = pcall(function()
    return sc_open(uint64(pb), uint64(2), uint64(0))
end)
local fdv = ok_o and to_num(fd) or -1
print("fd=" .. fdv)

if fdv >= 0 then
    -- PROT_READ=1, MAP_SHARED=1
    print("mmap RD_SH")
    local ok_m, m = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(1),
            uint64(0x0001), uint64(fdv), uint64(0))
    end)
    if ok_m then
        local mh, ml = get_hi_lo(m)
        print("map=0x" .. string.format("%X%08X", mh, ml))

        if ml ~= 0 or mh ~= 0 then
            -- Read first dword
            local ok_r, v = pcall(function() return memory.read_dword(m) end)
            if ok_r then print("rd=0x" .. string.format("%08X", to_num(v)))
            else print("rd=FAULT") end

            -- MS_INVALIDATE
            local ok1, r1 = pcall(function()
                return sc_msync(uint64(m), uint64(PAGE), uint64(2))
            end)
            print("INV=" .. (ok1 and tostring(to_num(r1)) or "PCALL"))

            -- MS_SYNC
            local ok2, r2 = pcall(function()
                return sc_msync(uint64(m), uint64(PAGE), uint64(0))
            end)
            print("SYN=" .. (ok2 and tostring(to_num(r2)) or "PCALL"))

            -- MS_ASYNC
            local ok3, r3 = pcall(function()
                return sc_msync(uint64(m), uint64(PAGE), uint64(1))
            end)
            print("ASY=" .. (ok3 and tostring(to_num(r3)) or "PCALL"))

            -- Post-invalidate read
            local ok_r2, v2 = pcall(function() return memory.read_dword(m) end)
            if ok_r2 then print("rd_post=0x" .. string.format("%08X", to_num(v2)))
            else print("rd_post=FAULT") end

            pcall(function() sc_munmap(uint64(m), uint64(PAGE)) end)
        end
    else
        print("mmap PCALL-FAIL")
    end

    pcall(function() sc_close(uint64(fdv)) end)
else
    print("dmem0 open failed")
end

-- Also try /dev/gc
print("")
print("--- GC ---")
s = "/dev/gc"
for i = 1, #s do memory.write_byte(pb + i - 1, string.byte(s, i)) end
memory.write_byte(pb + #s, 0)

local ok_g, gfd = pcall(function()
    return sc_open(uint64(pb), uint64(2), uint64(0))
end)
local gfdv = ok_g and to_num(gfd) or -1
print("gc_fd=" .. gfdv)

if gfdv >= 0 then
    for _, combo in ipairs({{1,1},{3,1},{0x33,1},{1,2}}) do
        local ok_m, m = pcall(function()
            return sc_mmap(uint64(0), uint64(PAGE), uint64(combo[1]),
                uint64(combo[2]), uint64(gfdv), uint64(0))
        end)
        if ok_m then
            local mh, ml = get_hi_lo(m)
            if ml ~= 0 or mh ~= 0 then
                print("gc_map=0x" .. string.format("%X%08X p=%d f=%d", mh, ml, combo[1], combo[2]))
                local ok1, r1 = pcall(function()
                    return sc_msync(uint64(m), uint64(PAGE), uint64(2))
                end)
                print("gc_INV=" .. (ok1 and tostring(to_num(r1)) or "PCALL"))
                pcall(function() sc_munmap(uint64(m), uint64(PAGE)) end)
                break
            end
        end
    end
    pcall(function() sc_close(uint64(gfdv)) end)
end

print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
