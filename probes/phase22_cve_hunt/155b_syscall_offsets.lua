-- CRASH_CLASS: LOW
-- PROBE 155b: Get exact offsets of syscall (0F 05) in eboot
-- Quick scan of first 4MB of eboot, list all hits with context

print("=== PROBE 155b: EBOOT SYSCALL OFFSETS ===")
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

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=0x" .. string.format("%X%08X", text_hi, text_lo))

local found = {}
local max_off = 0x400000

for off = 0, max_off - 4, 4 do
    local ok, val = pcall(function() return memory.read_dword(eboot + off) end)
    if not ok then break end
    local v = to_num(val)
    local b0 = v % 256
    local b1 = math.floor(v / 256) % 256
    local b2 = math.floor(v / 65536) % 256
    local b3 = math.floor(v / 16777216) % 256
    if b0 == 0x0F and b1 == 0x05 then found[#found + 1] = off end
    if b1 == 0x0F and b2 == 0x05 then found[#found + 1] = off + 1 end
    if b2 == 0x0F and b3 == 0x05 then found[#found + 1] = off + 2 end
    -- Cross boundary
    if b3 == 0x0F then
        local ok2, v2 = pcall(function() return memory.read_dword(eboot + off + 4) end)
        if ok2 and (to_num(v2) % 256) == 0x05 then
            found[#found + 1] = off + 3
        end
    end
end

print("found=" .. #found)
for i = 1, #found do
    local off = found[i]
    -- Read the byte after syscall
    local ok, post = pcall(function() return memory.read_dword(eboot + off + 2) end)
    local after = "?"
    if ok then
        local pb = to_num(post)
        local a0 = pb % 256
        if a0 == 0xC3 then after = "ret"
        elseif a0 == 0x72 then after = "jc"
        elseif a0 == 0x73 then after = "jnc"
        elseif a0 == 0x48 then after = "rex.w"
        elseif a0 == 0x90 then after = "nop"
        elseif a0 == 0xEB then after = "jmp"
        elseif a0 == 0x0F then after = "0f(2byte)"
        else after = string.format("%02X", a0) end
    end
    print(string.format("  +0x%06X after=%s", off, after))
end

print("")
print("=== DONE ===")
