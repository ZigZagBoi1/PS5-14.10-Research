-- CRASH_CLASS: MODERATE
-- PROBE 481a: do the implemented dmem commands need a real argument?
--
-- The sweep gave -1 for every command 0x80108000..0x80108016 with a zeroed
-- 0x10 page, which cannot separate "absent" from "rejected the arguments".
-- The 13.60 dispatcher does route 0x80108002, 0x80108015, 0xC010801A,
-- 0xC030801E and 0x40048023 to real bodies that read [uap], [uap+8],
-- [uap+0x10] and [uap+0x14]. This probe feeds those fields a mapped page and
-- small lengths, one command at a time, and skips 0x80108017 entirely.
--
-- Sizes start small (0x10) and grow to 0x1000 only for commands that already
-- returned something other than -1, so a bad DMA has the least room to work.

print("=== PROBE 481a: dmem command argument matrix ===")
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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end
local function page_fill(addr, n, base)
    for off = 0, n - 4, 4 do pcall(function() memory.write_dword(addr + off, base + off) end) end
end
local function page_head(addr)
    return string.format("%08X %08X %08X %08X",
        to_num(memory.read_dword(addr)), to_num(memory.read_dword(addr + 4)),
        to_num(memory.read_dword(addr + 8)), to_num(memory.read_dword(addr + 12)))
end

local pg = memory.alloc(0x1000)
local arg = memory.alloc(0x100)
local ioctl = make_syscall(54)
local open = make_syscall(5)

local cmds = { 0x4008800A, 0x80108002, 0x80108006, 0x80108015, 0xC010801A, 0xC030801E, 0x40048023, 0x80048022 }
local nodes = { "/dev/dmem1", "/dev/dmem2" }

for _, node in ipairs(nodes) do
    local fd = sgn(open(uint64(put_str(node)), uint64(2), uint64(0)))
    print(string.format("[node] %s fd=%d", node, fd))
    if fd >= 0 then
        for _, cmd in ipairs(cmds) do
            local lo = cmd % 0x1000000
            local name = string.format("0x%08X", cmd)
            for _, shape in ipairs({ "zero", "page", "page16", "page_nolen", "len_only" }) do
                page_fill(pg, 0x1000, 0x41410000)
                for off = 0, 0xF8, 4 do pcall(function() memory.write_dword(arg + off, 0) end) end
                if shape == "page" then
                    pcall(function() memory.write_qword(arg, uint64(pg)) end)
                elseif shape == "page16" then
                    pcall(function() memory.write_qword(arg, uint64(pg)) end)
                    pcall(function() memory.write_qword(arg + 8, uint64(0x10)) end)
                elseif shape == "page_nolen" then
                    pcall(function() memory.write_qword(arg, uint64(pg)) end)
                    pcall(function() memory.write_qword(arg + 8, uint64(0x1000)) end)
                elseif shape == "len_only" then
                    pcall(function() memory.write_qword(arg, uint64(0)) end)
                    pcall(function() memory.write_qword(arg + 8, uint64(0x10)) end)
                end
                local ok, r = pcall(function() return ioctl(uint64(fd), uint64(cmd), uint64(arg)) end)
                local ret = ok and sgn(r) or -999
                print(string.format("[%s] %s %-11s ret=%d pg=%s", node, name, shape, ret, page_head(pg)))
                if ret == -999 then print("=== PROBE 481a COMPLETE (exception) ==="); return end
            end
            local _ = lo
        end
    end
end
print("=== PROBE 481a COMPLETE ===")
