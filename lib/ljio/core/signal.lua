-- Copyright (C) Jinhua Luo

local ffi = require("ffi")
local C = require("ljio.cdef")
local epoll = require("ljio.core.epoll")

local SIG_BLOCK = 0
local SIG_UNBLOCK = 1
local SIG_SETMASK = 2
local SIG_IGN = 1

local handlers
local g_signalfd
local g_mask = ffi.new("sigset_t")
local siginfo = ffi.new("struct signalfd_siginfo")
local signal_ev

local function add_signal_handler(signo, handler)
	if not handlers[signo] then
		handlers[signo] = setmetatable({},{__mode="v"})
	end
	if #handlers[signo] == 0 then
		C.sigaddset(g_mask, signo)
		assert(C.sigprocmask(SIG_BLOCK, g_mask, nil) == 0)
		assert(C.signalfd(g_signalfd, g_mask, 0) > 0)
	end
	table.insert(handlers[signo], handler)
end

local function del_signal_handler(signo, handler)
	if handlers[signo] then
		for i,h in ipairs(handlers[signo]) do
			if h == handler then
				table.remove(handlers[signo], i)
				break
			end
		end
		if #handlers[signo] == 0 then
			C.sigdelset(g_mask, signo)
			assert(C.sigprocmask(SIG_SETMASK, g_mask, nil) == 0)
			assert(C.signalfd(g_signalfd, g_mask, 0) > 0)
		end
	end
end

local function ignore_signal(signo)
	C.signal(signo, ffi.cast("sighandler_t",SIG_IGN))
end

local function init()
	if g_signalfd then
		assert(C.close(g_signalfd) == 0)
	end
	g_signalfd = C.signalfd(-1, g_mask, 0)
	assert(g_signalfd > 0)
	handlers = {}
	C.sigemptyset(g_mask)
	signal_ev = {fd = g_signalfd, handler = function()
		assert(C.read(g_signalfd, siginfo, ffi.sizeof(siginfo)) == ffi.sizeof(siginfo))
		for _, handler in ipairs(handlers[siginfo.ssi_signo]) do
			handler(siginfo)
		end
	end}
	epoll.add_event(signal_ev, C.EPOLLIN)
end

return {
	init = init,
	ignore_signal = ignore_signal,
	add_signal_handler = add_signal_handler,
	del_signal_handler = del_signal_handler,
}
