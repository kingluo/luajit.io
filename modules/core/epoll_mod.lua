local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
typedef union epoll_data {
	void *ptr;
	int fd;
	int	u32;
	long u64;
} epoll_data_t;

struct epoll_event {
	int	events;
	epoll_data_t data;
};

int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

int getpid(void);
]]

local EPOLL_CTL_ADD=1
local EPOLL_CTL_DEL=2
local EPOLL_CTL_MOD=3

local EPOLLIN=0x1
local EPOLLPRI=0x2
local EPOLLOUT=0x4
local EPOLLERR=0x8
local EPOLLHUP=0x10
local EPOLLET=0x8000
local EPOLLRDHUP=0x2000

local g_epoll_fd
local g_prepare_hooks = {}
local handlers = setmetatable({},{__mode="v"})

local MAX_EPOLL_EVENT = 128
local ev_set = ffi.new("struct epoll_event[?]", MAX_EPOLL_EVENT)
local ev_c = ffi.new("struct epoll_event")

local function add_event(ev, ...)
	handlers[ev.fd] = ev
	local cmd
	if not ev.events then
		ev.events = 0
		cmd = EPOLL_CTL_ADD
	else
		cmd = EPOLL_CTL_MOD
	end
	if bit.band(ev.events, ...) == 0 then
		ev_c.data.fd = ev.fd
		ev_c.events = bit.bor(ev.events, ...)
		ev.events = ev_c.events
		assert(ffi.C.epoll_ctl(g_epoll_fd, cmd, ev.fd, ev_c) == 0)
	end
end

local function del_event(ev, ...)
	if not handlers[ev.fd] then return end
	local n_event = select('#',...)
	if n_event == 0 then
		assert(handlers[ev.fd] == ev)
		assert(ffi.C.epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ev.fd, nil) == 0)
		handlers[ev.fd] = nil
		ev.events = nil
	else
		ev_c.data.fd = ev.fd
		ev_c.events = bit.band(ev.events, bit.bnot(bit.bor(...)))
		ev.events = ev_c.events
		assert(ffi.C.epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, ev.fd, ev_c) == 0)
	end
end

local function init(epoll_size)
	if not g_epoll_fd then
		g_epoll_fd = ffi.C.epoll_create(epoll_size or 20000)
	end
end

local function add_prepare_hook(hook)
	table.insert(g_prepare_hooks, hook)
end

local function run(expect_events)
	assert((expect_events == nil) or (expect_events >= 0))
	local n_events = 0
	while true do
		local wait_timeout = -1
		local to_exit = false
		for _,hook in ipairs(g_prepare_hooks) do
			local t
			t,to_exit = hook()
			if to_exit == true then return n_events end
			if t and t >= 0 then
				if wait_timeout == -1 or t < wait_timeout then
					wait_timeout = t
				end
			end
		end

		print("# pid=" .. ffi.C.getpid() .. " epoll_wait enter...")
		local n = ffi.C.epoll_wait(g_epoll_fd, ev_set, MAX_EPOLL_EVENT, wait_timeout)
		print("# pid=" .. ffi.C.getpid() .. " epoll_wait exit...")

		if n == -1 then return n_events, utils.strerror() end

		if n > 0 then
			for ev_idx = 0, n-1 do
				local fd = ev_set[ev_idx].data.fd
				n_events = n_events + 1
				assert(handlers[fd])
				handlers[fd].handler(handlers[fd], ev_set[ev_idx].events)
			end
		end

		if expect_events and n_events >= expect_events then
			return n_events
		end
	end
end

return {
	-- functions
	add_event = add_event,
	del_event = del_event,
	add_prepare_hook = add_prepare_hook,
	init = init,
	run = run,

	-- constants
	EPOLLIN=EPOLLIN,
	EPOLLPRI=EPOLLPRI,
	EPOLLOUT=EPOLLOUT,
	EPOLLERR=EPOLLERR,
	EPOLLHUP=EPOLLHUP,
	EPOLLET=EPOLLET,
	EPOLLRDHUP=EPOLLRDHUP,
}
