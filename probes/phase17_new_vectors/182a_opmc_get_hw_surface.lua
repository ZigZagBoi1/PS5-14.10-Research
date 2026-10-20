-- CRASH_CLASS: LOW
-- PROBE 182a: surface of sys 626 opmc_get_hw after enabling opmc
--
-- Context: 181a mapped 625 opmc_set_hw to arg1 in {0x0D..0x10} with arg2 in {1,2,3}
-- and 626 returned -1 for exactly those pairs. Either get_hw has a different shape
-- or the setter is another silent stub. This enables opmc first (563, which returns
-- 0), then walks 626 over arg1 0..0x40 and arg2 0..0x10 with a zeroed page in arg3,
-- printing every call that is not -1.

print("=== PROBE 182a: SYS 626 opmc_get_hw SURFACE ===")
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

local function is_neg1(txt)
    local h = tostring(txt):gsub("^0x", ""):gsub("^0+", "")
    return h ~= "" and h:match("^f+$") ~= nil
end

local sc563 = make_syscall(563)
local sc625 = make_syscall(625)
local sc626 = make_syscall(626)
local buf = memory.alloc(0x1000)
for off = 0, 0xFF8, 8 do
    pcall(function() memory.write_qword(buf + off, u64(0xA5A5A5A5)) end)
end

print("[0] enable: 563(0,0) -> " .. string.format("0x%X", to_num(sc563(zero, zero, zero, zero, zero, zero))))
print("[0] set_hw: 625(0x0D,1) -> " .. string.format("0x%X", to_num(sc625(u64(0x0D), u64(1), zero, zero, zero, zero))))
print("")

local hits = 0
local kills = 0
for a1 = 0, 0x40 do
    for a2 = 0, 0x10 do
        local ok, ret = pcall(function() return sc626(u64(a1), u64(a2), buf, zero, zero, zero) end)
        if not ok then
            kills = kills + 1
            print(string.format("[!] killed at (0x%X,0x%X)", a1, a2))
            break
        end
        local txt = tostring(ret)
        if not is_neg1(txt) then
            hits = hits + 1
            print(string.format("[*] 626(0x%02X,0x%02X,buf) -> %s", a1, a2, txt))
        end
    end
    if kills > 0 then break end
end
print("")
print(string.format("[0] %d non -1 results, %d kills over %d calls", hits, kills, (0x41 * 0x11)))
print("")

print("[0] same sweep with arg3 = NULL")
hits = 0
for a1 = 0, 0x20 do
    for a2 = 0, 0x04 do
        local ok, ret = pcall(function() return sc626(u64(a1), u64(a2), zero, zero, zero, zero) end)
        if ok then
            local txt = tostring(ret)
            if not is_neg1(txt) then
                hits = hits + 1
                print(string.format("[*] 626(0x%02X,0x%02X,NULL) -> %s", a1, a2, txt))
            end
        end
    end
end
print(string.format("[0] %d non -1 results with NULL", hits))

print("")
print("[*] done")
