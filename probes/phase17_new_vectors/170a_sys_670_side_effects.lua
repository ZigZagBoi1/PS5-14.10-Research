-- CRASH_CLASS: LOW
-- PROBE 170a: does sys 670 leave observable state behind?
--
-- 670 is the only number in 661-670 that returns 0 (success) to six zero
-- arguments, and nothing in that call could plausibly have done work. The
-- closest precedent is 675, which also returned 0 and reset three globals.
--
-- This probe takes the same four measurements before and after 670 and prints
-- them side by side, so any state change the call causes shows up as a
-- difference between the two blocks:
--   A. mprotect(RWX) on a GPU-mapped page, syscall 74
--   B. fork, syscall 2
--   C. sys 587 credential metadata (ret and first dword of its buffer)
--   D. sys 629 (returns -1 for every argument pattern tested so far)
--
-- No threads, no blocking calls, so the probe cannot wedge the loader.

print("=== PROBE 170a: SYS 670 SIDE EFFECTS ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc20 = make_syscall(20)
local sc2 = make_syscall(2)
local sc74 = make_syscall(74)
local sc477 = make_syscall(477)
local sc587 = make_syscall(587)
local sc629 = make_syscall(629)
local sc670 = make_syscall(670)

print("[0] canary pid=" .. tostring(to_num(sc20())))

local gpu = sc477(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("[0] gpu=" .. string.format("0x%X", to_num(gpu)))

local crit = memory.alloc(0x100)
for off = 0, 0xFC, 4 do safe_wd(crit + off, 0) end

local function measure(label)
    local ok_mp, mp = pcall(function() return sc74(uint64(gpu), uint64(0x4000), uint64(7)) end)
    local ok_fk, fk = pcall(function() return sc2() end)
    local ok_cr, cr = pcall(function() return sc587(uint64(crit), uint64(0x100)) end)
    local cred0 = safe_rd(crit)
    local ok_j, j = pcall(function() return sc629(uint64(0), uint64(0), uint64(0)) end)
    print(label .. " mprotect_rwx=" .. (ok_mp and tostring(to_num(mp)) or "CRASH") ..
        " fork=" .. (ok_fk and tostring(to_num(fk)) or "CRASH") ..
        " s587=" .. (ok_cr and tostring(to_num(cr)) or "CRASH") ..
        " cred0=0x" .. string.format("%X", cred0) ..
        " s629=" .. (ok_j and tostring(to_num(j)) or "CRASH"))
end

measure("[1] BEFORE")

local ok670, rv670 = pcall(function() return sc670(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print("[2] sys 670 ok=" .. tostring(ok670) .. " rv=" .. (ok670 and tostring(to_num(rv670)) or "CRASH"))

measure("[3] AFTER")

print("[4] canary after: ok=true pid=" .. tostring(to_num(sc20())))
print("=== PROBE 170a DONE ===")
