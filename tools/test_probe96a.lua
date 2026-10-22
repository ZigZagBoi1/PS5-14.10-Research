-- Offline control-flow check for the unmodified 96a probe.
-- Run with Lua 5.1 (or lupa.lua51) from the repository root.

local probe = assert(loadfile("probes/phase17_new_vectors/96a_aio_duplicate_delete.lua"))
local checks = 0
local function check(ok, label)
    checks = checks + 1
    assert(ok, label)
end

local function run(mode)
    local words = {}
    local next_ptr = 0x10000000
    local calls, lines = {}, {}
    local memory = {
        alloc = function(size)
            local p = next_ptr
            next_ptr = next_ptr + 0x1000
            return p
        end,
        write_dword = function(p, v) words[p] = v % 0x100000000 end,
        read_dword = function(p) return words[p] or 0 end,
        write_qword = function(p, v)
            words[p] = v % 0x100000000
            words[p + 4] = math.floor(v / 0x100000000)
        end,
    }
    local pipe = {}
    setmetatable(pipe, {__call = function(self, ...)
        local args = {...}
        local n = self.syscall_no
        calls[#calls + 1] = {n=n, args=args}
        if n == 20 then return 123 end
        if n == 670 then return 0 end
        if n == 669 then
            if mode == "submit_fail" then return -1 end
            words[args[5]] = 0x4205
            return 0
        end
        if n == 664 then
            words[args[3]] = mode == "pending" and 1 or 3
            return 0
        end
        if n == 240 then return 0 end
        if n == 662 then
            check(args[2] == 2, "batch count must be exactly two")
            check(words[args[1]] == 0x4205 and words[args[1]+4] == 0x4205,
                "batch must contain the same published ID twice")
            words[args[3]] = 0
            words[args[3]+4] = 0x80020003
            return 0
        end
        error("unexpected syscall " .. tostring(n))
    end})
    local env = {
        memory=memory,
        syscall={pipe=pipe},
        uint64=function(v) return v end,
        print=function(...) lines[#lines+1] = table.concat({...}, " ") end,
        pcall=pcall, pairs=pairs, unpack=unpack, type=type,
        tonumber=tonumber, tostring=tostring, string=string,
        math=math, table=table,
    }
    setmetatable(env, {__index=_G})
    setfenv(probe, env)
    probe()
    local deletes = 0
    local polls = 0
    for _, c in ipairs(calls) do
        if c.n == 662 then deletes = deletes + 1 end
        if c.n == 664 then polls = polls + 1 end
    end
    return {deletes=deletes, polls=polls, lines=lines}
end

local success = run("complete")
check(success.deletes == 1, "completed request must trigger one duplicate batch")
check(success.polls == 2, "completed request must poll before and after delete")
check(table.concat(success.lines, "\n"):find("PROBE 96a COMPLETE", 1, true),
    "completed path must finish")

local failure = run("submit_fail")
check(failure.deletes == 0 and failure.polls == 0,
    "failed submission must not reach poll or delete")

local pending = run("pending")
check(pending.deletes == 0 and pending.polls == 20,
    "pending request must stop after the bounded poll count")

print("PASS test_probe96a: " .. checks .. " assertions")
