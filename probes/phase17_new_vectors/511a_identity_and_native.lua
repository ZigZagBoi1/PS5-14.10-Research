-- CRASH_CLASS: LOW
-- PROBE 511a: what identity does the loader run as, and does it expose a raw
-- call helper?
--
-- Two questions decide the next step:
--   1) getuid/geteuid: if the process is root-like, sysctl writes and other
--      privileged surfaces open up (sys 587 reported credential bit 0x20000000).
--   2) is there a `native` table (CLAUDE.md claims native.fcall_with_rax)?  A
--      direct C-level call would bypass the loader's serialized ROP path, which
--      is what blocks every concurrent experiment (509a/509b).

print("=== PROBE 511a: identity and native surface ===")
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
local function call(n, a1, a2, a3)
    local sc = make_syscall(n)
    local ok, rv = pcall(function() return sc(a1 or uint64(0), a2 or uint64(0), a3 or uint64(0)) end)
    if not ok then return "pcall-fail" end
    return tostring(to_num(rv))
end

print("[0] getuid(24)   = " .. call(24))
print("[0] geteuid(25)  = " .. call(25))
print("[0] getgid(47)   = " .. call(47))
print("[0] getegid(43)  = " .. call(43))
print("[0] getpid(20)   = " .. call(20))

print("")
print("[1] globals:")
local names = {"native", "syscall", "memory", "thread", "uint64", "kernel_offset", "kernel"}
for i = 1, #names do
    local v = _G and _G[names[i]]
    print(string.format("    %-14s %s", names[i], type(v)))
end

print("")
print("[2] native contents:")
local nt = rawget(_G or {}, "native")
if nt == nil then
    local okn, v = pcall(function() return native end)
    if okn then nt = v end
end
if type(nt) ~= "table" then
    print("    native is " .. type(nt))
else
    local count = 0
    for k, v in pairs(nt) do
        count = count + 1
        if count <= 40 then print(string.format("    %-24s %s", tostring(k), type(v))) end
    end
    print("    entries=" .. count)
end

print("")
print("[3] syscall table keys (filtered):")
local n_sc = 0
for k, v in pairs(syscall) do
    n_sc = n_sc + 1
    if n_sc <= 60 then print(string.format("    syscall.%-24s %s", tostring(k), type(v))) end
end
print("    syscall entries=" .. n_sc)
print("    pipe type=" .. type(syscall.pipe))
local ps = tostring(syscall.pipe)
print("    pipe str len=" .. #ps)
print("    pipe str=" .. ps:sub(1, 220):gsub("[^%g ]", "."))
print("=== DONE ===")
