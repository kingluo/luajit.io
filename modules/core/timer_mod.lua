local ffi = require("ffi")
local rt = ffi.load("rt")
local ep = require("core.epoll_mod")
local rbtree = require("core.rbtree")

ffi.cdef[[
int getpid(void);

typedef int time_t;

struct timespec {
   time_t tv_sec;                /* Seconds */
   long   tv_nsec;               /* Nanoseconds */
};

int clock_gettime(int clk_id, struct timespec *tp);

struct itimerspec {
   struct timespec it_interval;  /* Interval for periodic timer */
   struct timespec it_value;     /* Initial expiration */
};
int timerfd_create(int clockid, int flags);

int timerfd_settime(int fd, int flags,
				   const struct itimerspec *new_value,
				   struct itimerspec *old_value);
]]

local CLOCK_MONOTONIC=1
local CLOCK_MONOTONIC_RAW=4

local g_timer_fd
local g_timer_ev = {}

local function timer_lt(a,b)
	if a.tv_sec < b.tv_sec then return true end
	if a.tv_sec == b.tv_sec and a.tv_nsec < b.tv_nsec then
		return true
	end
	return false
end

local g_timer_rbtree = rbtree.new(timer_lt)

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
	assert(ffi.C.timerfd_settime(fd, 0, timespec, nil) == 0)
end

local function add_timer(fn, sec)
	assert(sec > 0)
	local nsec = (sec%1) * 1000 * 1000 * 1000
	sec = math.floor(sec)

	local tv = ffi.new("struct timespec")
	assert(rt.clock_gettime(CLOCK_MONOTONIC_RAW, tv) == 0)
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
	assert(rt.clock_gettime(CLOCK_MONOTONIC_RAW, tv) == 0)

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
	assert(rt.clock_gettime(CLOCK_MONOTONIC_RAW, tv) == 0)
	assert(timer_lt(tv, t))

	local sec = t.tv_sec - tv.tv_sec
	if  tv.tv_nsec > t.tv_nsec then
		sec = sec - 1
		nsec = t.tv_nsec + 1000*1000*1000 - tv.tv_nsec
	else
		nsec = t.tv_nsec - tv.tv_nsec
	end

	return sec, nsec
end

local function init()
	if g_timer_fd then return end
	g_timer_fd = ffi.C.timerfd_create(CLOCK_MONOTONIC, 0)
	assert(g_timer_fd > 0)
	g_timer_ev.fd = g_timer_fd
	g_timer_ev.handler = function()
		print("child pid=" .. ffi.C.getpid() .. " timer fired")
		timerfd_settime(g_timer_fd, 0, 0)
		while process_all_timers() > 0 do end
		local sec,nsec = get_next_interval()
		if sec then timerfd_settime(g_timer_fd, sec, nsec) end
	end
	ep.add_event(g_timer_ev, ep.EPOLLIN)
end

return {
	init = init,
	add_timer = add_timer,
}
