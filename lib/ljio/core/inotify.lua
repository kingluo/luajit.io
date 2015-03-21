-- Copyright (C) Jinhua Luo

local ffi = require("ffi")
local bit = require("bit")
local C = require("ljio.cdef")
local epoll = require("ljio.core.epoll")

local IN_CLOEXEC = tonumber("02000000", 8)

local bor = bit.bor
local band = bit.band

local inotify_fd
local inotify_ev
local MAXLEN = 8192
local g_ev = ffi.new("char[?]", MAXLEN)

local M = {}

local watch_files = {}

function M.add_watch(path, handler, ...)
	local mask = bor(...)
	local wd = C.inotify_add_watch(inotify_fd, path, mask)
	watch_files[wd] = handler
	return wd
end

function M.remove_watch(wd)
	print("rmwatch", C.inotify_rm_watch(inotify_fd, wd))
	print(ffi.string(C.strerror(ffi.errno())))
	watch_files[wd] = nil
end

function M.init()
	inotify_fd = C.inotify_init1(IN_CLOEXEC)
	assert(inotify_fd > 0)
	inotify_ev = {fd = inotify_fd, handler = function()
		assert(C.read(inotify_fd, g_ev, MAXLEN) >= ffi.sizeof("struct inotify_event"))
		local ev = ffi.cast("struct inotify_event*", g_ev)
		return watch_files[ev.wd](ev.mask)
	end}
	epoll.add_event(inotify_ev, C.EPOLLIN)
end

return M
