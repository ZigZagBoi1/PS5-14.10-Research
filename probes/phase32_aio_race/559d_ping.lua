-- CRASH_CLASS: LOW
-- PROBE 559d: Minimal ping test
print("=== PING ===")
print("alive")
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local sc20 = mk(20)
local pid = sc20()
if type(pid) == "table" and pid.tonumber then pid = pid:tonumber() end
print("pid=" .. tostring(pid))
print("=== DONE ===")
