-- CRASH_CLASS: LOW
-- PROBE 349c: the osem wait and the shared-name registry
--
-- 349b confirmed the slot order (name, attributes, initial, maximum), then
-- parked the Lua thread in 553(h,1,NULL): wait with no timeout, on a semaphore
-- nobody posts, blocks for ever. This probe posts first and always passes a
-- timeout, and then asks the two questions 349b never reached:
--   - does 553 return once a count is available, and what does it return when
--     the timeout expires instead?
--   - does 549 with the registry attribute let 551 resolve the name, and do
--     550 delete / 552 close split on the role predicate as the dossier says?

print("=== PROBE 349c: OSEM WAIT AND SHARED NAMES ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local Z = uint64(0)
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function call(n, a1, a2, a3, a4)
    local ok, rv = pcall(function()
        return make_syscall(n)(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0),
            uint64(a4 or 0), Z, Z)
    end)
    if not ok then return nil end
    return sgn(rv)
end

local nameWait = put_str("omp349c_wait")
local nameShared = put_str("omp349c_shared")
local tmo = memory.alloc(0x10)
local res = memory.alloc(0x10)

-- 0x800 = 2048; if the slot is a microsecond budget that is 2 ms, if it is a
-- millisecond budget it is 2 s. Either way the call must come back.
wd(tmo, 0x800)
wd(res, 0)

print("[A] a count is available, so wait must return at once")
local h = call(549, nameWait, 0, 0, 1)
print(string.format("  549(wait,0,0,1)          = %s", tostring(h)))
if h and h ~= -1 then
    print(string.format("  555(h,1) post            = %s", tostring(call(555, h, 1))))
    print(string.format("  553(h,1,&tmo) wait       = %s  tmo=0x%X", tostring(call(553, h, 1, tmo)), rd(tmo)))
end

print("[B] nothing available and a timeout budget, so wait must time out")
wd(tmo, 0x800)
print(string.format("  553(h,1,&tmo) wait empty = %s  tmo=0x%X", tostring(call(553, h, 1, tmo)), rd(tmo)))

print("[C] cancel resets the count")
print(string.format("  555(h,1) post            = %s", tostring(call(555, h, 1))))
print(string.format("  556(h,1,&res) cancel      = %s  res=0x%X", tostring(call(556, h, 1, res)), rd(res)))
print(string.format("  554(h,1) poll after reset= %s", tostring(call(554, h, 1))))

print("[D] the shared registry: register with the name attribute, then open")
local hs = call(549, nameShared, 0x100, 0, 1)
print(string.format("  549(shared,0x100,0,1)    = %s", tostring(hs)))
print(string.format("  551(shared) open         = %s", tostring(call(551, nameShared))))
print(string.format("  551(absent) open         = %s", tostring(call(551, put_str("omp349c_absent")))))

print("[E] delete and close on the same handle")
if hs and hs ~= -1 then
    print(string.format("  550(hs) delete           = %s", tostring(call(550, hs))))
    print(string.format("  552(hs) close            = %s", tostring(call(552, hs))))
end
if h and h ~= -1 then
    print(string.format("  552(h) close             = %s", tostring(call(552, h))))
    print(string.format("  550(h) delete            = %s", tostring(call(550, h))))
end

print("")
print("=== 349c DONE ===")
