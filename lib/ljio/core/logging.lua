-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local bit = require("bit")

local M = {}

local tinsert = table.insert
local tconcat = table.concat
local bor = bit.bor

local g_log_level
local g_flags
local opened = false

local levels = {
    emerg = C.LOG_EMERG,
    alert = C.LOG_ALERT,
    crit = C.LOG_CRIT,
    err = C.LOG_ERR,
    warn = C.LOG_WARNING,
    notice = C.LOG_NOTICE,
    info = C.LOG_INFO,
    debug = C.LOG_DEBUG,
}

function M.init(cfg)
    g_log_level = levels[cfg.log_level] or C.LOG_INFO
    g_flags = bor(C.LOG_PID, C.LOG_CONS, cfg.log_stderr and C.LOG_PERROR or 0)
    if opened then C.closelog() end
    C.openlog("ljio", g_flags, C.LOG_DAEMON)
    opened = true
end

function M.log(level, ...)
    level = levels[level]
    if level <= g_log_level then
        local t = {...}
        for i, v in ipairs(t) do
            if type(v) ~= "string" then
                t[i] = tostring(v)
            end
        end
        local dinfo = ""
        if level == C.LOG_DEBUG then
            dinfo = debug.getinfo(2, "nSl")
            dinfo = dinfo.name .. dinfo.source .. ":" .. dinfo.currentline
        end
        C.syslog(level, "%s %s\n", dinfo, tconcat(t))
    end
end

function M.import_print()
    _G.print = function(...) log("notice", ...) end
end

return M
