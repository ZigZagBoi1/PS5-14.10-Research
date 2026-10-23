-- CRASH_CLASS: LOW
-- PROBE 155c: Read context around each eboot syscall instruction
-- Dump 32 bytes before and after each to identify usable paths to ret

print("=== PROBE 155c: SYSCALL CONTEXT ===")
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

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=0x" .. string.format("%X%08X", text_hi, text_lo))

-- Known syscall offsets from 155b
local offsets = {
    0x093CBD, 0x1017E2, 0x12403C, 0x1577A6,
    0x2BBC23, 0x2BBDDD, 0x33E6DC, 0x3CFE7E,
    0x3F1FB9, 0x3F1FBF, 0x3F30D4, 0x3FCAB9,
}

for _, off in ipairs(offsets) do
    print(string.format("\n+0x%06X:", off))
    -- Read 16 bytes before and 16 bytes after the syscall
    local bytes = {}
    for b = -8, 17 do
        local ok, val = pcall(function() return memory.read_dword(eboot + off + b) end)
        if ok then
            local v = to_num(val)
            bytes[b] = v % 256
        end
    end

    -- Print bytes
    local hex_before = ""
    for b = -8, -1 do
        if bytes[b] then hex_before = hex_before .. string.format("%02X ", bytes[b])
        else hex_before = hex_before .. "?? " end
    end
    local hex_at = ""
    if bytes[0] and bytes[1] then hex_at = string.format("%02X %02X", bytes[0], bytes[1]) end
    local hex_after = ""
    for b = 2, 17 do
        if bytes[b] then hex_after = hex_after .. string.format("%02X ", bytes[b])
        else hex_after = hex_after .. "?? " end
    end

    print("  before: " .. hex_before)
    print("  syscall: " .. hex_at)
    print("  after:  " .. hex_after)

    -- Quick disassembly of key patterns after syscall
    if bytes[2] then
        local a = bytes[2]
        if a == 0xC3 then print("  => syscall; ret ***PERFECT***")
        elseif a == 0x72 and bytes[3] then
            print("  => syscall; jc +" .. bytes[3] .. " (error branch)")
        elseif a == 0x73 and bytes[3] then
            print("  => syscall; jnc +" .. bytes[3])
        elseif a == 0x48 and bytes[3] then
            if bytes[3] == 0x89 then print("  => syscall; mov reg,reg (rex.w)")
            elseif bytes[3] == 0x8B then print("  => syscall; mov reg,[...] (rex.w)")
            elseif bytes[3] == 0x85 then print("  => syscall; test reg,reg (rex.w)")
            elseif bytes[3] == 0x3D then print("  => syscall; cmp rax,imm32")
            end
        elseif a == 0x89 and bytes[3] then
            print("  => syscall; mov ...")
        elseif a == 0x85 and bytes[3] then
            print("  => syscall; test ...")
        elseif a == 0x3D then
            print("  => syscall; cmp eax,imm")
        end
    end
end

print("\n=== DONE ===")
