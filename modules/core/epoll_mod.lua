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
local handlers = {}

local ev_c = ffi.new("struct epoll_event")
local MAX_EPOLL_EVENT = 128
local ev_set = ffi.new("struct epoll_event[?]", MAX_EPOLL_EVENT)

local function add_event(ev, ...)
	local fd = ev.fd
	assert(fd)
	if not handlers[fd] then handlers[fd] = ev end
	local cmd
	if not ev.ev_c then
		ev.ev_c = ffi.new("struct epoll_event")
		ev.ev_c.data.fd = fd
		cmd = EPOLL_CTL_ADD
	else
		cmd = EPOLL_CTL_MOD
	end
	ev.ev_c.events = bit.bor(ev.ev_c.events, ...)
	assert(ffi.C.epoll_ctl(g_epoll_fd, cmd, fd, ev.ev_c) == 0)
end

local function del_event(ev, ...)
	if not handlers[ev.fd] then return end
	assert(ev.fd)
	assert(ev.ev_c)
	local n_event = select('#',...)
	if n_event == 0 then
		assert(ffi.C.epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ev.fd, nil) == 0)
		handlers[ev.fd] = nil
	else
		ev.ev_c.events = bit.band(ev.ev_c.events, bit.bnot(bit.bor(...)))
		assert(ffi.C.epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, ev.fd, ev.ev_c) == 0)
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
	assert((expect_events == nil) or (expect_events > 0))
	local n_events = 0
	while true do
		local wait_timeout,to_exit
		for _,hook in ipairs(g_prepare_hooks) do
			wait_timeout,to_exit = hook()
			if to_exit == true then return n_events end
		end

		print("child pid=" .. ffi.C.getpid() .. " epoll_wait enter...")
		local nevents = ffi.C.epoll_wait(g_epoll_fd, ev_set, MAX_EPOLL_EVENT, wait_timeout)
		print("child pid=" .. ffi.C.getpid() .. " epoll_wait exit...")

		for ev_idx = 0, nevents-1 do
			local fd = ev_set[ev_idx].data.fd
			n_events = n_events + 1
			assert(handlers[fd])
			handlers[fd].handler(handlers[fd], ev_set[ev_idx].events)
			if expect_events and n_events >= expect_events then
				return n_events
			end
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
