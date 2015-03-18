-- Copyright (C) Jinhua Luo

local ffi = require("ffi")
local C = require("ljio.cdef")
local rt = ffi.load("rt")
local epoll = require("ljio.core.epoll")
local rbtree = require("ljio.core.rbtree")

local g_timer_fd
local g_timer_ev
local g_timer_rbtree

local function timer_lt(a,b)
	if a.tv_sec < b.tv_sec then return true end
	if a.tv_sec == b.tv_sec and a.tv_nsec < b.tv_nsec then
		return true
	end
	return false
end

local timer_mt = {
	__index = {
		cancel = function(self)
			g_timer_rbtree:delete(self)
		end
	},
	__lt = timer_lt
}

local function timerfd_settime(fd, sec, nsec)
	sec = sec or 0
	nsec = nsec or 0
	local timespec = ffi.new("struct itimerspec")
	timespec.it_value.tv_sec = sec
	timespec.it_value.tv_nsec = nsec
	assert(C.timerfd_settime(fd, 0, timespec, nil) == 0)
end

local function add_timer(fn, sec)
	assert(sec > 0)
	local nsec = (sec%1) * 1000 * 1000 * 1000
	sec = math.floor(sec)

	local tv = ffi.new("struct timespec")
	assert(rt.clock_gettime(C.CLOCK_MONOTONIC_RAW, tv) == 0)
	local timer = setmetatable({
		tv_sec = tv.tv_sec + sec,
		tv_nsec = tv.tv_nsec + nsec,
		fn = fn
	}, timer_mt)

	g_timer_rbtree:insert(timer)

	if g_timer_rbtree:min() == timer then
		timerfd_settime(g_timer_fd, sec, nsec)
	end

	return timer
end

local function process_all_timers()
	if g_timer_rbtree:size() == 0 then return 0 end

	local tv = ffi.new("struct timespec")
	assert(rt.clock_gettime(C.CLOCK_MONOTONIC_RAW, tv) == 0)

	local n_process = 0

	while g_timer_rbtree:size() > 0 do
		local t = g_timer_rbtree:min()
		if not timer_lt(t, tv) then break end
		t.fn()
		g_timer_rbtree:delete(t)
		n_process = n_process + 1
	end

	return n_process
end

local function get_next_interval()
	if g_timer_rbtree:size() == 0 then return nil end
	local t = g_timer_rbtree:min()
	local tv = ffi.new("struct timespec")
	assert(rt.clock_gettime(C.CLOCK_MONOTONIC_RAW, tv) == 0)
	assert(timer_lt(tv, t))

	local sec = t.tv_sec - tv.tv_sec
	local nsec
	if  tv.tv_nsec > t.tv_nsec then
		sec = sec - 1
		nsec = t.tv_nsec + 1000*1000*1000 - tv.tv_nsec
	else
		nsec = t.tv_nsec - tv.tv_nsec
	end

	return sec, nsec
end

local function init()
	if g_timer_fd then
		assert(C.close(g_timer_fd) == 0)
	end
	g_timer_fd = C.timerfd_create(C.CLOCK_MONOTONIC, 0)
	assert(g_timer_fd > 0)
	g_timer_ev = {}
	g_timer_ev.fd = g_timer_fd
	g_timer_ev.handler = function()
		print("child pid=" .. C.getpid() .. " timer fired")
		timerfd_settime(g_timer_fd, 0, 0)
		while process_all_timers() > 0 do end
		local sec,nsec = get_next_interval()
		if sec then timerfd_settime(g_timer_fd, sec, nsec) end
	end
	epoll.add_event(g_timer_ev, C.EPOLLIN)
	g_timer_rbtree = rbtree.new(timer_lt)
end

return {
	init = init,
	add_timer = add_timer,
}
