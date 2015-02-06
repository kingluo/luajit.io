local ffi = require("ffi")
local ep = require("core.epoll_mod")

ffi.cdef[[
typedef struct {
	unsigned long int __val[1024 / (8 * sizeof (unsigned long int))];
} sigset_t;
int signalfd(int fd, const sigset_t *mask, int flags);

typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
struct signalfd_siginfo {
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint8_t __pad[48];
};
int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
]]

local SIG_BLOCK = 0
local SIG_UNBLOCK = 1
local SIG_SETMASK = 2
local SIG_IGN = 1

local handlers = {}
local g_signalfd = -1
local g_mask = ffi.new("sigset_t")
ffi.C.sigemptyset(g_mask)
local siginfo = ffi.new("struct signalfd_siginfo")
local signal_ev

local function add_signal_handler(signo, handler)
	if not handlers[signo] then
		handlers[signo] = setmetatable({},{__mode="v"})
	end
	if #handlers[signo] == 0 then
		ffi.C.sigaddset(g_mask, signo)
		ffi.C.sigprocmask(SIG_BLOCK, g_mask, nil)
		table.insert(handlers[signo], handler)
		g_signalfd = ffi.C.signalfd(g_signalfd, g_mask, 0)
		assert(g_signalfd > 0)
	end
	return handler
end

local function del_signal_handler(signo, handler)
	if handlers[signo] then
		for i,h in ipairs(handlers[signo]) do
			if h == handler then
				table.remove(handlers[signo], i)
				break
			end
		end
		-- if #handlers[signo] == 0 then
			-- ffi.C.sigdelset(g_mask, signo)
			-- ffi.C.sigprocmask(SIG_SETMASK, g_mask, nil)
			-- ffi.C.signalfd(g_signalfd, g_mask, 0)
		-- end
	end
end

local function ignore_signal(signo)
	ffi.C.signal(signo, ffi.cast("sighandler_t",SIG_IGN))
end

local function init()
	if g_signalfd == -1 then
		g_signalfd = ffi.C.signalfd(g_signalfd, g_mask, 0)
		assert(g_signalfd > 0)
	end
	if not signal_ev then
		signal_ev = {fd = g_signalfd, handler = function()
			local siginfo = ffi.new("struct signalfd_siginfo")
			assert(ffi.C.read(g_signalfd, siginfo, ffi.sizeof(siginfo)) == ffi.sizeof(siginfo))
			for _, handler in ipairs(handlers[siginfo.ssi_signo]) do
				handler(siginfo)
			end
		end}
		ep.add_event(signal_ev, ep.EPOLLIN)
	end
end

return {
	init = init,
	ignore_signal = ignore_signal,
	add_signal_handler = add_signal_handler,
	del_signal_handler = del_signal_handler,
}
