-- CRASH_CLASS: HIGH
-- PROBE 1350a: does a lethal 622 command kill the thread or the process?
--
-- Context: 622 low cmds 0x00 and 0x01 kill the whole process with a null arg3
-- and with a mapped zero page alike (1346a/1347a/1348a). Every sweep of that
-- range therefore costs one relaunch per killer, and nothing past the first
-- killer can ever be measured.
--
-- The loader ships run_lua_code_in_new_thread(code, {async=true, client_fd=fd})
-- (1175a: a thread that parked inside 601 0x0C while main kept printing; the
-- fault oracle 1199a-1199c ran 512 children that faulted on supervisor pages
-- and the parent survived all of them). If the 622 kill is thread-local, the
-- same harness turns the whole lethal range into a one-connection sweep.
--
-- Stage A: a Lua thread calls 622(0x01, 0, buf, page, 0x40, 0) and writes a
--   marker afterwards. Main spins and prints MAIN-n.
--   marker written  -> the kill is contained; sweep it from threads.
--   main output stops -> the kill is process-wide, and this range stays a
--   relaunch-per-command wall.
-- Stage B (only if A survived): the same call for cmd 0x00 and for cmd 0x400,
--   the other measured killer of this family.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1346a_sys622_low_commands_20261109_104306.txt
--   results/phase35_dead_end_reruns/1347a_sys622_low_resume_20261109_104444.txt
--   results/phase35_dead_end_reruns/1348a_sys622_low_page_20261109_104528.txt
--   results/phase17_new_vectors/1175a_loader_thread_api_20261104_160547.txt
--   .local/1331a.lua (512 faulting thr_create children, parent survived)

print("=== PROBE 1350a: 622 KILL CONTAINMENT ===")

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
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local sc477 = make_syscall(477)
local fd = 0
do
    local ok, v = pcall(function() return to_num(memory.read_qword(signal.fd_addr)) end)
    if ok then fd = v end
end

local shared = memory.alloc(0x40)
local page = to_num(sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
local buf = to_num(memory.alloc(0x200))
print(string.format("[0] pid=%d fd=%d page=0x%X buf=0x%X", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), fd, page, buf))

G = G or {}
G.shared = to_num(shared)
G.page = page
G.buf = buf

local function spin(n)
    local x = 0
    for i = 1, n do x = x + i end
    return x
end

local function stage(label, cmd, size, spins)
    safe_wq(to_num(shared), 0)
    print(string.format("[%s] spawn cmd=0x%X", label, cmd))
    local ok, res = pcall(run_lua_code_in_new_thread, [[
        local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
        local t = {}
        for k, v in pairs(syscall.pipe) do t[k] = v end
        t.syscall_no = 622
        setmetatable(t, getmetatable(syscall.pipe))
        print(string.format("T-ENTER cmd=0x%X", G.cmd))
        local okc, rv = pcall(function()
            return t(uint64(G.cmd), uint64(0), uint64(G.buf), uint64(G.page), uint64(G.size), uint64(0))
        end)
        print("T-CALLED ok=" .. tostring(okc) .. " rv=" .. tostring(rv))
        memory.write_qword(uint64(G.shared), uint64(0xC0DE))
    ]], { async = true, client_fd = fd })
    if not ok then
        print(string.format("[%s] spawn FAILED: %s", label, tostring(res)))
        return false
    end
    for i = 1, spins do
        print(string.format("[%s] MAIN-%d", label, i))
        spin(4000000)
    end
    local marker = safe_rq(to_num(shared))
    print(string.format("[%s] marker=0x%X %s", label, marker or 0, marker == 0xC0DE and "CONTAINED" or "NO-MARKER"))
    return marker == 0xC0DE
end

G.cmd, G.size = 0x01, 0x40
local a = stage("A", 0x01, 0x40, 40)

if a then
    G.cmd, G.size = 0x00, 0x40
    stage("B", 0x00, 0x40, 30)
    G.cmd, G.size = 0x400, 0x40
    stage("C", 0x400, 0x40, 30)
else
    print("[A] no marker - a 622 kill takes the process, threads do not contain it")
end

print(string.format("[Z] alive pid=%d", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1350a COMPLETE ===")
