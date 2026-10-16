-- 14.10 Recon Probe 08: Read exploit kit offset files
-- Dump /savedata0/offsets.lua and /savedata0/kernel_offset.lua

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: OFFSET FILES ===")
log("fw: " .. tostring(FW_VERSION))

syscall.resolve({ sc_open = 5, sc_close = 6, sc_read = 3 })

local function read_file(path, max)
    max = max or 16384
    local ok, result = pcall(function()
        local fd = syscall.sc_open(path, 0):tonumber()
        if fd < 0 then return nil end
        local buf = memory.alloc(max + 1)
        local total = {}
        local pos = 0
        while pos < max do
            local chunk = math.min(4096, max - pos)
            local n = syscall.sc_read(fd, buf, chunk):tonumber()
            if n <= 0 then break end
            local chars = {}
            for i = 0, n - 1 do
                local b = memory.read_byte(buf + i):tonumber()
                if b == 0 then break end
                chars[#chars+1] = string.char(b)
            end
            total[#total+1] = table.concat(chars)
            pos = pos + n
        end
        syscall.sc_close(fd)
        return table.concat(total)
    end)
    return ok and result or nil
end

local files = {
    "/savedata0/offsets.lua",
    "/savedata0/kernel_offset.lua",
    "/savedata0/kernel.lua",
    "/savedata0/main.lua",
    "/savedata0/ropchain.lua",
    "/savedata0/memory.lua",
    "/savedata0/syscall.lua",
}

for _, path in ipairs(files) do
    log("")
    log("========== " .. path .. " ==========")
    local content = read_file(path, 32768)
    if content then
        log("size: " .. #content .. " bytes")
        log("")
        log(content)
    else
        log("FAILED to read")
    end
end

log("")
log("=== OFFSET FILES DONE ===")
return table.concat(out, "\n")
