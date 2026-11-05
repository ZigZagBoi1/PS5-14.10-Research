-- CRASH_CLASS: LOW
-- PROBE 930a: what can this process actually touch on disk?
--
-- Why: the loader runs inside the game's jail, so "can we read PS5 system files" is a
-- question about that jail, not about the FTP payload. This answers it in one connection
-- with the standard Lua io library - no sockets, no threads, no blocking devices.
-- Directories are probed the same way: a failed open with EISDIR behind the error proves
-- the path resolves; ENOENT/EACCES do not.
print("=== PROBE 930a: path access ===")

local paths = {
    "/",
    "/savedata0",
    "/savedata0/main.lua",
    "/app0",
    "/system",
    "/system/common/lib",
    "/system/common/lib/libkernel.sprx",
    "/system_ex",
    "/system_data",
    "/user",
    "/user/app",
    "/data",
    "/mnt",
    "/mnt/sda",
    "/dev",
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/dmem0",
    "/av_contents",
    "/av_contents/content_tmp",
    "/download0",
    "/update",
    "/license",
    "/preinst",
}

for _, p in ipairs(paths) do
    local f, err, code = io.open(p, "rb")
    if f then
        local head = f:read(16)
        f:close()
        local hexs = ""
        if head then
            for i = 1, #head do hexs = hexs .. string.format("%02x", string.byte(head, i)) end
        else
            hexs = "(no data)"
        end
        print(string.format("[OK ] %-34s len16=%d %s", p, head and #head or 0, hexs))
    else
        print(string.format("[ERR] %-34s %s | %s", p, tostring(err), tostring(code)))
    end
end

-- second route: the raw syscall, to separate jail from library behaviour
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc_open = mk(5)
local sc_close = mk(6)
local function try_open(path)
    local ok, fd = pcall(function() return sc_open(uint64(path), uint64(0), uint64(0)) end)
    if not ok then return "pcall-fail" end
    local n = fd
    if type(fd) == "table" and fd.tonumber then n = fd:tonumber() end
    if type(n) == "number" and n >= 0 then
        pcall(function() sc_close(uint64(n)) end)
        return "fd=" .. tostring(n)
    end
    return "ret=" .. tostring(n)
end
print("")
for _, p in ipairs({ "/", "/system", "/manual", "/app0", "/dev/dmem0" }) do
    print(string.format("[SYS] open(%-20s) %s", p, try_open(p)))
end
print("[Z] COMPLETE")
