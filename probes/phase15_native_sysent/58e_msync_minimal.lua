print("=== PROBE 58e START ===")

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

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_mmap = make_syscall(477)
local sc_msync = make_syscall(65)
local sc_munmap = make_syscall(73)
local PAGE = 0x4000

print("A")
local ok_g, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("B ok=" .. tostring(ok_g))

if ok_g then
    local h, l = 0, 0
    if type(gpu) == "table" and gpu.h then h = gpu.h; l = gpu.l
    else l = to_num(gpu) end
    print("gpu=0x" .. string.format("%X%08X", h, l))

    print("C msync_inv")
    local ok1, r1 = pcall(function()
        return sc_msync(uint64(gpu), uint64(PAGE), uint64(2))
    end)
    print("inv=" .. (ok1 and tostring(to_num(r1)) or "FAIL"))

    print("D msync_sync")
    local ok2, r2 = pcall(function()
        return sc_msync(uint64(gpu), uint64(PAGE), uint64(0))
    end)
    print("sync=" .. (ok2 and tostring(to_num(r2)) or "FAIL"))
end

print("=== DONE ===")
