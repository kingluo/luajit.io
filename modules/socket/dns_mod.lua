local ffi = require("ffi")
require("socket.base")
local co = require("core.co_mod")
local signal = require("core.signal_mod")

ffi.cdef[[
struct addrinfo {
int              ai_flags;
int              ai_family;
int              ai_socktype;
int              ai_protocol;
socklen_t        ai_addrlen;
struct sockaddr *ai_addr;
char            *ai_canonname;
struct addrinfo *ai_next;
};

typedef union sigval
  {
    int sival_int;
    void *sival_ptr;
  } sigval_t;
typedef int pid_t;
typedef struct sigevent
  {
    sigval_t sigev_value;
    int sigev_signo;
    int sigev_notify;

           void       (*sigev_notify_function) (union sigval);
                            /* Function used for thread
                               notification (SIGEV_THREAD) */
           void        *sigev_notify_attributes;
                            /* Attributes for notification thread
                               (SIGEV_THREAD) */
           pid_t        sigev_notify_thread_id;
                            /* ID of thread to signal (SIGEV_THREAD_ID) */
  } sigevent_t;

struct gaicb {
const char            *ar_name;
const char            *ar_service;
const struct addrinfo *ar_request;
struct addrinfo       *ar_result;
};
void freeaddrinfo(struct addrinfo *res);
int getaddrinfo_a(int mode, struct gaicb *list[],
	   int nitems, struct sigevent *sevp);
int gai_error(struct gaicb *req);
int gai_cancel(struct gaicb *req);
]]

local SIGIO = 29
local SIGUSR1 = 10
local SIGEV_SIGNAL = 0
local GAI_NOWAIT = 1
local SI_ASYNCNL = -60

local requests = {}
local handler_registered = false
local anl = ffi.load("anl")

local function handle_answer(siginfo)
	assert(siginfo.ssi_code == SI_ASYNCNL)
	local key = siginfo.ssi_int
	local req = requests[key]
	local gaicb = req.gaicb
	local caller = req.co
	local runp = gaicb.ar_result
	local ip, port
	while runp ~= nil do
		local addr = ffi.cast("struct sockaddr_in *", runp.ai_addr)
		local val = ffi.cast("unsigned short",ffi.C.ntohs(addr[0].sin_port))
		port = tonumber(val)
		ip = ffi.string(ffi.C.inet_ntoa(addr[0].sin_addr))
		if ip ~= "0.0.0.0" then
			break
		end
	    runp = runp.ai_next
	end
	anl.freeaddrinfo(gaicb.ar_result)
	requests[key] = nil
	return co.resume(caller, ip, port)
end

local tmp = ffi.new("struct gaicb*[1]")
local sig = ffi.new("struct sigevent")
local next_req_key = 1
local function resolve(host, port)
	if handler_registered == false then
		handler_registered = true
		signal.add_signal_handler(SIGIO, handle_answer)
	end

	local gaicb = ffi.new("struct gaicb")
	assert(requests[next_req_key] == nil)
	requests[next_req_key] = {gaicb = gaicb, co = coroutine.running()}
	gaicb.ar_name = host
	port = (type(port) == "number") and tostring(port) or port
	gaicb.ar_service = port
	sig.sigev_notify = SIGEV_SIGNAL
	sig.sigev_value.sival_int = next_req_key
	next_req_key = next_req_key + 1
	sig.sigev_signo = SIGIO
	tmp[0] = gaicb
	assert(anl.getaddrinfo_a(GAI_NOWAIT, tmp, 1, sig) == 0)
	return co.yield()
end

return {
	resolve = resolve,
}
