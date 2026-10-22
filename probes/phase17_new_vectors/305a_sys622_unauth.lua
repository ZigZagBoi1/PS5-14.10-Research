-- CRASH_CLASS: HIGH
-- PROBE 305a: the 622 commands that skip the credential gate
--
-- results/kernel_handlers/analysis/sys_622_deep.md section 4.1: commands
-- 0x100-0x133 pass through a bitmap test, and the commands whose bit is zero
-- skip the privilege check entirely:
--   0x101 0x103 0x105 0x108-0x10F 0x11B 0x11C 0x11D 0x12C 0x12E 0x12F
--   0x131 0x132 0x133
-- 241a measured only 0x100 (the gated one, which returned 0x8002004E without
-- credentials). This probe calls the ungated fifteen with a valid output page
-- and a valid input page and dumps what comes back - the dossier flags a fixed
-- 0x19-byte copy in this handler, which would be a kernel stack leak.
--
-- Every command prints its own BEFORE line, so a death names the command.

print("=== PROBE 305a: SYS 622 UNAUTHENTICATED COMMANDS ===")

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
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end

local out = memory.alloc(0x1000)
local inp = memory.alloc(0x1000)
local sc = make_syscall(622)

local function fill(addr, byte)
    for i = 0, 0xFFF, 4 do memory.write_dword(addr + i, byte) end
end
fill(out, 0x41414141)
fill(inp, 0x42424242)

local cmds = { 0x101, 0x103, 0x105, 0x108, 0x109, 0x10A, 0x10B, 0x10C, 0x10D,
               0x10E, 0x10F, 0x11B, 0x11C, 0x11D, 0x12C, 0x12E, 0x12F,
               0x131, 0x132, 0x133 }

for _, cmd in ipairs(cmds) do
    fill(out, 0x41414141)
    print(string.format("[BEFORE] cmd=0x%X", cmd))
    local okc, r = pcall(function()
        return sc(uint64(cmd), uint64(0), uint64(out), uint64(inp), uint64(0x40), uint64(0))
    end)
    if not okc then
        print(string.format("[0x%X] PCALL-FAIL %s", cmd, tostring(r)))
    else
        local ret = sgn(r)
        local changed = false
        for i = 0, 0x3C, 4 do
            if rd(out + i) ~= 0x41414141 then changed = true end
        end
        print(string.format("[0x%X] ret=%d changed=%s", cmd, ret, tostring(changed)))
        if changed then
            local line = {}
            for i = 0, 0x3C, 4 do line[#line + 1] = string.format("%08X", rd(out + i)) end
            print("   out: " .. table.concat(line, " "))
        end
    end
end

print("=== DONE ===")
