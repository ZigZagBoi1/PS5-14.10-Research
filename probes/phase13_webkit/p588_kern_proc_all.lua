-- CRASH_CLASS: LOW
-- PROBE p588: Enumerate visible processes via sysctl KERN_PROC_ALL
--
-- Context: trying to find the WebProcess PID and any info about its address space.
-- The game runs in a FreeBSD jail; KERN_PROC_ALL may be filtered to our own jail.
-- Quick probe - either returns data or ret=-1.

print("=== PROBE p588: KERN_PROC_ALL ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc_sysctl = make_syscall(202)

-- Get our own PID first
local sc_getpid = make_syscall(20)
local pid_ret = sc_getpid()
local our_pid = to_num(pid_ret)
print("Our PID: " .. our_pid)

-- KERN_PROC_ALL: mib = {CTL_KERN=1, KERN_PROC=14, KERN_PROC_ALL=0}
local mib = memory.alloc(12)
safe_wd(mib, 1)      -- CTL_KERN
safe_wd(mib + 4, 14) -- KERN_PROC
safe_wd(mib + 8, 0)  -- KERN_PROC_ALL

local bufsize = 0x20000  -- 128KB, enough for ~119 kinfo_proc entries (1096B each)
local buf = memory.alloc(bufsize)
local lenp = memory.alloc(8)
safe_wd(lenp, bufsize)
safe_wd(lenp + 4, 0)

-- Zero the buffer
for i = 0, 255 do
    safe_wd(buf + i * 4, 0)
end

print("[A] Calling sysctl KERN_PROC_ALL...")
local ok, ret = pcall(function()
    return sc_sysctl(uint64(mib), uint64(3), uint64(buf), uint64(lenp), uint64(0), uint64(0))
end)

if not ok then
    print("[A] PCALL FAIL: " .. tostring(ret))
else
    local rv = to_num(ret)
    print("[A] ret=" .. rv)

    local outlen = safe_rd(lenp)
    print("[A] outlen=" .. (outlen or "nil") .. " bytes")

    if rv == 0 and outlen and outlen > 0 then
        -- Parse kinfo_proc entries (1096 bytes each on PS5 FreeBSD)
        local entry_size = 1096
        local count = math.floor(outlen / entry_size)
        print("[A] Found " .. count .. " process entries")

        for i = 0, math.min(count - 1, 49) do
            local base = buf + i * entry_size

            -- ki_pid at +0x2C (int32)
            local pid = safe_rd(base + 0x2C)

            -- ki_ppid at +0x30 (int32)
            local ppid = safe_rd(base + 0x30)

            -- ki_uid at +0x44 (uint32)
            local uid = safe_rd(base + 0x44)

            -- ki_comm at +0x1BF (20 bytes, null-terminated string)
            -- Read 5 dwords = 20 bytes
            local comm = ""
            for j = 0, 4 do
                local dw = safe_rd(base + 0x1BF + j * 4)
                if dw then
                    for b = 0, 3 do
                        local byte = math.floor(dw / (256 ^ b)) % 256
                        if byte == 0 then break end
                        comm = comm .. string.char(byte)
                    end
                end
            end

            print(string.format("  [%d] pid=%s ppid=%s uid=%s comm='%s'",
                i, tostring(pid), tostring(ppid), tostring(uid), comm))

            -- Also check for interesting fields
            -- ki_jid (jail ID) at +0x1E4
            local jid = safe_rd(base + 0x1E4)
            if jid and jid ~= 0 then
                print(string.format("       jid=%d", jid))
            end
        end
    elseif rv == -1 then
        print("[A] BLOCKED (expected in jail)")
    end
end

-- Also try KERN_PROC_PID for our own process to verify kinfo_proc layout
print("")
print("[B] Verifying layout with KERN_PROC_PID (self)...")
safe_wd(mib + 8, 1)      -- KERN_PROC_PID
safe_wd(mib + 4, 14)     -- KERN_PROC

-- Need 4 MIB entries for KERN_PROC_PID
local mib4 = memory.alloc(16)
safe_wd(mib4, 1)          -- CTL_KERN
safe_wd(mib4 + 4, 14)    -- KERN_PROC
safe_wd(mib4 + 8, 1)     -- KERN_PROC_PID
safe_wd(mib4 + 12, our_pid)

local buf2 = memory.alloc(0x800)
local lenp2 = memory.alloc(8)
safe_wd(lenp2, 0x800)

local ok2, ret2 = pcall(function()
    return sc_sysctl(uint64(mib4), uint64(4), uint64(buf2), uint64(lenp2), uint64(0), uint64(0))
end)

if ok2 then
    local rv2 = to_num(ret2)
    local outlen2 = safe_rd(lenp2)
    print("[B] ret=" .. rv2 .. " outlen=" .. (outlen2 or "nil"))

    if rv2 == 0 and outlen2 and outlen2 > 0 then
        local pid_check = safe_rd(buf2 + 0x2C)
        local ppid_check = safe_rd(buf2 + 0x30)
        local uid_check = safe_rd(buf2 + 0x44)

        local comm_check = ""
        for j = 0, 4 do
            local dw = safe_rd(buf2 + 0x1BF + j * 4)
            if dw then
                for b = 0, 3 do
                    local byte = math.floor(dw / (256 ^ b)) % 256
                    if byte == 0 then break end
                    comm_check = comm_check .. string.char(byte)
                end
            end
        end

        print(string.format("[B] pid=%s ppid=%s uid=%s comm='%s'",
            tostring(pid_check), tostring(ppid_check), tostring(uid_check), comm_check))

        -- Dump first 256 bytes as hex for layout verification
        print("[B] First 256 bytes:")
        for row = 0, 15 do
            local line = string.format("  +%03X:", row * 16)
            for col = 0, 3 do
                local dw = safe_rd(buf2 + row * 16 + col * 4)
                if dw then
                    line = line .. string.format(" %08X", dw)
                else
                    line = line .. " ????????"
                end
            end
            print(line)
        end
    end
end

print("")
print("=== PROBE p588 COMPLETE ===")
