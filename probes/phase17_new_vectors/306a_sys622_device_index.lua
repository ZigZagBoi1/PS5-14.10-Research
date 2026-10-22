-- CRASH_CLASS: MEDIUM
-- PROBE 306a: does the device index change the 622 answer?
--
-- 305a: every ungated command in 0x100-0x133 writes one status dword -
-- 0xFFFFFFFF (not found) or 0x8002004E (no device/credential) - and returns 0.
-- The handler looks the device up by argument 1, which has always been 0.
-- If any index resolves to a real device, the status should change and the
-- handler should write more than one dword.

print("=== PROBE 306a: SYS 622 DEVICE INDEX ===")

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

local cmds = { 0x101, 0x10D, 0x12C, 0x12E }
local seen = {}
for _, cmd in ipairs(cmds) do
    for idx = 0, 15 do
        fill(out, 0x41414141)
        fill(inp, 0x42424242)
        local okc, r = pcall(function()
            return sc(uint64(cmd), uint64(idx), uint64(out), uint64(inp), uint64(0x40), uint64(0))
        end)
        if okc then
            local ret = sgn(r)
            local written = 0
            for i = 0, 0x3C, 4 do
                if rd(out + i) ~= 0x41414141 then written = written + 1 end
            end
            local key = string.format("0x%X/idx%d ret=%d first=0x%X words=%d", cmd, idx, ret, rd(out), written)
            print(key)
        else
            print(string.format("[0x%X/idx%d] PCALL-FAIL %s", cmd, idx, tostring(r)))
            break
        end
    end
end

print("=== DONE ===")
