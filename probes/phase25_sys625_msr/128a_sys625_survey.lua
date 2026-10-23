-- CRASH_CLASS: LOW
-- PROBE 128a: Sys 625 performance MSR interface survey
--
-- Context: 13.60 Ghidra analysis shows sys 625 is a PMC interface with
-- 23 commands, NO credential check, and direct rdmsr/wrmsr. Never called
-- on 14.10. Args: cmd(+0), domain(+8), index(+0x10), value(+0x18).
--
-- Commands 1-23 are admitted; 0 and 24+ return error 22.
-- This probe maps which commands exist and what they return.

print("=== PROBE 128a: SYS 625 PMC SURVEY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

local sc = mk(625)

-- [A] Command sweep: cmd 0-25, domain=0, index=0, value=0
print("")
print("[A] Command sweep (domain=0, index=0, value=0)")
for cmd = 0, 25 do
    local ok, rv = pcall(function()
        return sc(uint64(cmd), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  cmd=%2d PCALL_FAIL", cmd))
    else
        print(string.format("  cmd=%2d ret=%s", cmd, fmt(rv)))
    end
    if not alive() then
        print(string.format("  *** DIED at cmd=%d ***", cmd))
        return
    end
end

-- [B] Domain sweep for cmd 1-5 (most likely to be basic query/control)
print("")
print("[B] Domain sweep (cmd 1-5, domain 0-4, index=0, value=0)")
for cmd = 1, 5 do
    local row = string.format("  cmd=%d:", cmd)
    for dom = 0, 4 do
        local ok, rv = pcall(function()
            return sc(uint64(cmd), uint64(dom), uint64(0), uint64(0))
        end)
        if ok then
            row = row .. string.format(" d%d=%s", dom, fmt(rv))
        else
            row = row .. string.format(" d%d=FAIL", dom)
        end
    end
    print(row)
    if not alive() then print("  DIED!") return end
end

-- [C] Index sweep for the commands that returned 0 in [A]
-- (those are the "working" ones)
print("")
print("[C] Index sweep (working cmds, domain=0, index -1..8)")
local working = {}
for cmd = 1, 23 do
    local ok, rv = pcall(function()
        return sc(uint64(cmd), uint64(0), uint64(0), uint64(0))
    end)
    if ok and rv ~= nil then
        local rv_n = N(rv)
        if rv_n == 0 then
            working[#working + 1] = cmd
        end
    end
end

print("  working cmds: " .. table.concat(working, ","))

for _, cmd in ipairs(working) do
    local row = string.format("  cmd=%d:", cmd)
    for idx = -1, 8 do
        local idx_u = idx
        if idx < 0 then idx_u = 0xFFFFFFFF end
        local ok, rv = pcall(function()
            return sc(uint64(cmd), uint64(0), uint64(idx_u), uint64(0))
        end)
        if ok then
            row = row .. string.format(" i%d=%d", idx, N(rv))
        else
            row = row .. string.format(" i%d=F", idx)
        end
        if not alive() then print("  DIED at cmd=" .. cmd .. " idx=" .. idx) return end
    end
    print(row)
end

-- [D] Value test on working commands — write a value and see if it sticks
print("")
print("[D] Value write test (working cmds, domain=1, index=0, value=0x42)")
for _, cmd in ipairs(working) do
    -- Try with domain=0
    local ok0, rv0 = pcall(function()
        return sc(uint64(cmd), uint64(0), uint64(0), uint64(0x42))
    end)
    -- Try with domain=1
    local ok1, rv1 = pcall(function()
        return sc(uint64(cmd), uint64(1), uint64(0), uint64(0x42))
    end)
    -- Try with domain=2
    local ok2, rv2 = pcall(function()
        return sc(uint64(cmd), uint64(2), uint64(0), uint64(0x42))
    end)
    print(string.format("  cmd=%d: d0=%s d1=%s d2=%s",
        cmd,
        ok0 and fmt(rv0) or "FAIL",
        ok1 and fmt(rv1) or "FAIL",
        ok2 and fmt(rv2) or "FAIL"))
    if not alive() then print("  DIED at cmd=" .. cmd) return end
end

-- [E] Read-back test: does cmd 1 read and cmd 2 write?
-- From analysis: cmd 4 might be RDPMC-like (read counter)
print("")
print("[E] Read-after-write test")
for _, write_cmd in ipairs(working) do
    for _, read_cmd in ipairs(working) do
        if write_cmd ~= read_cmd then
            -- Write 0x1234 via write_cmd
            pcall(function()
                sc(uint64(write_cmd), uint64(1), uint64(0), uint64(0x1234))
            end)
            -- Read via read_cmd
            local ok, rv = pcall(function()
                return sc(uint64(read_cmd), uint64(1), uint64(0), uint64(0))
            end)
            if ok and rv ~= nil and N(rv) ~= 0 and N(rv) ~= 6 and N(rv) ~= 22 then
                print(string.format("  write(cmd=%d) read(cmd=%d) = %s", write_cmd, read_cmd, fmt(rv)))
            end
        end
        if not alive() then print("  DIED!") return end
    end
end

-- [F] RDMSR test: cmd with domain=0 and various indices
-- The analysis shows some commands tail-call helpers that do rdmsr
print("")
print("[F] Potential RDMSR commands (domain=0, index 0-7)")
for cmd = 1, 23 do
    local interesting = false
    local row = string.format("  cmd=%2d:", cmd)
    for idx = 0, 7 do
        local ok, rv = pcall(function()
            return sc(uint64(cmd), uint64(0), uint64(idx), uint64(0))
        end)
        if ok and rv ~= nil then
            local rv_n = N(rv)
            -- Look for non-standard returns (not 0, 6, 22, -1)
            if rv_n ~= 0 and rv_n ~= 6 and rv_n ~= 22 and rv_n ~= 0xFFFFFFFF and rv_n ~= 0xFFFFFFFFFFFFFFFF then
                interesting = true
                row = row .. string.format(" [%d]=%s", idx, fmt(rv))
            end
        end
        if not alive() then print("  DIED!") return end
    end
    if interesting then print(row) end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 128a COMPLETE ===")
