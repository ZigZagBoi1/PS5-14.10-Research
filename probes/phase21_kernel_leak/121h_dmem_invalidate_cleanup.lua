-- Clean up only the mapping and fd left by probe 121g in loader PID 247.
print("=== PROBE 121h: DMEM CLEANUP ===")
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local pid = sc(20)()
print("pid=" .. tostring(pid))
if type(pid) ~= "table" or pid:tonumber() ~= 247 then
    print("STOP: loader PID changed")
    return
end
local ok_unmap, unmap_rv = pcall(function()
    return sc(73)(uint64("0x310e30000"), uint64(0x4000))
end)
print("unmap_ok=" .. tostring(ok_unmap) .. " rv=" .. tostring(unmap_rv))
local ok_close, close_rv = pcall(function() return sc(6)(uint64(22)) end)
print("close_ok=" .. tostring(ok_close) .. " rv=" .. tostring(close_rv))
print("=== PROBE 121h COMPLETE ===")
