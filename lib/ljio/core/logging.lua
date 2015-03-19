-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local bit = require("bit")

local tconcat = table.concat
local bor = bit.bor

local g_log_level
local g_flags
local g_pid

local levels = {
	emerg = C.LOG_EMERG,
	alert = C.LOG_ALERT,
	crit = C.LOG_CRIT,
	err = C.LOG_ERR,
	warning = C.LOG_WARNING,
	notice = C.LOG_NOTICE,
	info = C.LOG_INFO,
	debug = C.LOG_DEBUG,
}

local function init(cfg)
	g_log_level = levels[cfg.log_level] or C.LOG_INFO
	g_flags = bor(C.LOG_PID, C.LOG_CONS)
	if cfg.log_stderr then
		g_flags = bor(g_flags, C.LOG_PERROR)
	end
end

local function log(level, ...)
	local pid = C.getpid()
	if pid ~= g_pid then
		if g_pid then C.closelog() end
		C.openlog("ljio", g_flags, C.LOG_DAEMON)
		g_pid = pid
	end
	level = levels[level]
	if level <= g_log_level then
		local t = {...}
		table.insert(t, "\n")
		local str = tconcat(t)
		C.syslog(level, str)
	end
end

local function import_print()
	_G.print = function(...) log("notice", ...) end
end

return {
	init = init,
	log = log,
	import_print = import_print,
}
