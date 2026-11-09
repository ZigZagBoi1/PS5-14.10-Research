-- CRASH_CLASS: LOW
-- PROBE 93d8: device mmap check (NO reads of mapped pages)
--
-- Just tests whether mmap returns a valid address for each /dev node
-- Does NOT read mapped memory (avoids binary output + crashes)

print("=== PROBE 93d8: DEV MMAP NO-READ ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_addr(val)
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l), h, l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local function open_dev(name)
    local path = memory.alloc(64)
    local full = "/dev/" .. name
    for i = 1, #full do wd(N(path) + i - 1, string.byte(full, i)) end
    wd(N(path) + #full, 0)
    local ok, ret = pcall(function() return mk(5)(path, uint64(2)) end)
    if ok and N(ret) >= 0 and N(ret) < 200 then return N(ret) end
    ok, ret = pcall(function() return mk(5)(path, uint64(0)) end)
    if ok and N(ret) >= 0 and N(ret) < 200 then return N(ret) end
    return nil
end

-- ======== SECTION A: mmap on device nodes (NO READ) ========
print("--- A: mmap accessibility (no read) ---")

local devs = {"ajm", "gc", "dce", "dmem0", "dmem1", "camera", "rng",
              "gic", "hid", "bt", "zero", "null", "urandom",
              "notification0", "notification1", "usbctl"}

for _, dname in ipairs(devs) do
    local fd = open_dev(dname)
    if fd then
        local results = {}
        -- PROT_READ(1), MAP_SHARED(1)
        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(1),
                uint64(1), uint64(fd), uint64(0))
        end)
        if ok_m then
            local s, h, l = fmt_addr(rv_m)
            if h > 0 or l > 0x1000 then
                results[#results+1] = "R:" .. s
                pcall(function() mk(73)(rv_m, uint64(0x4000)) end)
            else
                results[#results+1] = "R:fail"
            end
        else
            results[#results+1] = "R:pcall_fail"
        end

        -- PROT_READ|PROT_WRITE(3), MAP_SHARED(1)
        local ok_m2, rv_m2 = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(fd), uint64(0))
        end)
        if ok_m2 then
            local s2, h2, l2 = fmt_addr(rv_m2)
            if h2 > 0 or l2 > 0x1000 then
                results[#results+1] = "RW:" .. s2
                pcall(function() mk(73)(rv_m2, uint64(0x4000)) end)
            else
                results[#results+1] = "RW:fail"
            end
        else
            results[#results+1] = "RW:pcall_fail"
        end

        print(string.format("  /dev/%-16s fd=%2d %s", dname, fd, table.concat(results, " ")))
        pcall(function() mk(6)(uint64(fd)) end)
    else
        print(string.format("  /dev/%-16s OPEN_FAIL", dname))
    end
    if not alive() then print("  DEAD!"); return end
end

-- ======== SECTION B: TCP getsockopt full scan ========
print("")
print("--- B: TCP opts with data (len>4) ---")

local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(6))
end)
local tcp_fd = ok_s and N(rv_s) or -1

if tcp_fd >= 0 then
    local buf = memory.alloc(0x200)
    local lenp = memory.alloc(8)

    for optnum = 0, 0x100 do
        for i = 0, 0x1F8, 4 do wd(N(buf) + i, 0xCCCCCCCC) end
        wd(N(lenp), 0x200)
        local ok_o, rv_o = pcall(function()
            return mk(118)(uint64(tcp_fd), uint64(6), uint64(optnum),
                uint64(N(buf)), uint64(N(lenp)))
        end)
        local oret = ok_o and N(rv_o) or -999
        if oret >= 0x80000000 then oret = oret - 0x100000000 end
        if oret == 0 then
            local olen = rd(N(lenp)) or 0
            local kp = 0
            local overcopy = 0
            for off = 0, math.min(olen - 4, 0x1FC), 8 do
                local lo = rd(N(buf) + off) or 0
                local hi = rd(N(buf) + off + 4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then kp = kp + 1 end
            end
            for off = olen, math.min(olen + 32, 0x1FC), 4 do
                local v = rd(N(buf) + off)
                if v and v ~= 0xCCCCCCCC then overcopy = overcopy + 1 end
            end
            if olen > 4 or kp > 0 or overcopy > 0 then
                print(string.format("  TCP 0x%02X: len=%3d kp=%d oc=%d", optnum, olen, kp, overcopy))
            end
        end
        if not alive() then break end
    end
    pcall(function() mk(6)(uint64(tcp_fd)) end)
end

-- ======== SECTION C: exec variants ========
print("")
print("--- C: exec/fork variants ---")
local tests = {
    {59, "execve"}, {66, "vfork"}, {492, "fexecve"}, {518, "pdfork"},
    {2, "fork"}, {251, "rfork"},
}
for _, t in ipairs(tests) do
    local ok_t, rv_t = pcall(function() return mk(t[1])(uint64(0), uint64(0), uint64(0)) end)
    local tret = ok_t and N(rv_t) or -999
    if tret >= 0x80000000 then tret = tret - 0x100000000 end
    print(string.format("  %s(%d): ret=%d ok=%s", t[2], t[1], tret, tostring(ok_t)))
end

print("")
print("alive=" .. tostring(alive()))
print("=== 93d8 COMPLETE ===")
