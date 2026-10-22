-- CRASH_CLASS: LOW
-- PROBE 181a: map what sys 625 opmc_set_hw accepts, and whether 626 reads it back
--
-- Context: 180a found exactly one accepted shape, arg1=0x10 with arg2 in {1,2,3};
-- every other combination returns -1. This walks arg1 over 0..0x80 with arg2=1,
-- then arg2 over 0..0x20 for each accepted arg1, then asks 626 for the same
-- arguments with an output page to see whether the pair is a setter/getter.
-- Compact output: only accepted calls are printed individually.

print("=== PROBE 181a: SYS 625 opmc_set_hw SURFACE ===")
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
local function u64(v)
    return uint64(string.format("0x%08X", v))
end
local zero = u64(0)

local sc625 = make_syscall(625)
local sc626 = make_syscall(626)
local buf = memory.alloc(0x1000)
for off = 0, 0xFF8, 8 do
    pcall(function() memory.write_qword(buf + off, u64(0xA5A5A5A5)) end)
end

local function call625(a1, a2, a3)
    local ok, ret = pcall(function() return sc625(a1, a2, a3 or zero, zero, zero, zero) end)
    if not ok then return nil end
    return to_num(ret)
end
local function call626(a1, a2, a3)
    local ok, ret = pcall(function() return sc626(a1, a2, a3 or zero, zero, zero, zero) end)
    if not ok then return nil end
    return to_num(ret)
end

print("[0] arg1 sweep 0..0x80 with arg2=1")
local accepted = {}
for a1 = 0, 0x80 do
    local r = call625(u64(a1), u64(1))
    if r == nil then
        print("[!] killed at arg1=" .. string.format("0x%X", a1))
        break
    elseif r == 0 then
        accepted[#accepted + 1] = a1
        print(string.format("[*] 625(0x%02X, 1) -> 0", a1))
    end
end
print("")

if #accepted == 0 then
    print("[!] nothing accepted")
else
    print("[0] arg2 sweep for the accepted arg1 values")
    for _, a1 in ipairs(accepted) do
        local row = {}
        for a2 = 0, 0x20 do
            local r = call625(u64(a1), u64(a2))
            if r == nil then
                row[#row + 1] = string.format("%d:KILLED", a2)
                break
            elseif r == 0 then
                row[#row + 1] = tostring(a2)
            end
        end
        print(string.format("[*] 625(0x%02X, *) -> %s", a1, table.concat(row, " ")))
    end
    print("")

    print("[0] 626 readback for each accepted pair, plain and with a page in arg3")
    for _, a1 in ipairs(accepted) do
        for a2 = 0, 0x20 do
            if call625(u64(a1), u64(a2)) == 0 then
                local r_plain = call626(u64(a1), u64(a2))
                local r_buf = call626(u64(a1), u64(a2), buf)
                print(string.format("[*] 625 ok (0x%02X,%d) 626 plain=%s buf=0x%s",
                    a1, a2,
                    r_plain and string.format("0x%016X", r_plain) or "KILLED",
                    r_buf and string.format("%016X", r_buf) or "KILLED"))
            end
        end
    end
end

print("")
print("[*] done")
