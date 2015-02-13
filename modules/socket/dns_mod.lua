local ffi = require("ffi")
require("socket.base")
local co = require("core.co_mod")
local signal = require("core.signal_mod")

if ffi.arch == "x86" then
ffi.cdef[[
struct addrinfo
{
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  socklen_t ai_addrlen;
  struct sockaddr *ai_addr;
  char *ai_canonname;
  struct addrinfo *ai_next;
};

typedef int __pid_t;
typedef union sigval
  {
    int sival_int;
    void *sival_ptr;
  } sigval_t;
typedef struct sigevent
  {
    sigval_t sigev_value;
    int sigev_signo;
    int sigev_notify;

    union
      {
 int _pad[((64 / sizeof (int)) - 3)];



 __pid_t _tid;

 struct
   {
     void (*_function) (sigval_t);
     void *_attribute;
   } _sigev_thread;
      } _sigev_un;
  } sigevent_t;

struct gaicb
{
  const char *ar_name;
  const char *ar_service;
  const struct addrinfo *ar_request;
  struct addrinfo *ar_result;

  int __return;
  int __unused[5];
};
void freeaddrinfo(struct addrinfo *res);
int getaddrinfo_a(int mode, struct gaicb *list[],
	   int nitems, struct sigevent *sevp);
int gai_error(struct gaicb *req);
int gai_cancel(struct gaicb *req);
]]
else
error("arch not support: " .. ffi.arch)
end

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
	if not req then return end
	local gaicb = req.gaicb
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
	if req.handler then return handler(ip, port) end
	return co.resume(req.co, ip, port)
end

local tmp = ffi.new("struct gaicb*[1]")
local sig = ffi.new("struct sigevent")
local next_req_key = 1
local function resolve(host, port, handler)
	if handler_registered == false then
		handler_registered = true
		signal.add_signal_handler(SIGIO, handle_answer)
	end

	local gaicb = ffi.new("struct gaicb")
	assert(requests[next_req_key] == nil)
	local data = {gaicb = gaicb}
	if handler then data.handler = handler
	else data.co = coroutine.running() end
	requests[next_req_key] = data

	gaicb.ar_name = host
	port = (type(port) == "number") and tostring(port) or port
	gaicb.ar_service = port
	sig.sigev_notify = SIGEV_SIGNAL
	sig.sigev_value.sival_int = next_req_key
	next_req_key = next_req_key + 1
	sig.sigev_signo = SIGIO
	tmp[0] = gaicb
	assert(anl.getaddrinfo_a(GAI_NOWAIT, tmp, 1, sig) == 0)

	if handler then return sig.sigev_value.sival_int end
	return co.yield()
end

local function cancel_resolve(key)
	local req = requests[key]
	if req then
		anl.gai_cancel(req.gaicb)
		requests[key] = nil
	end
end

return {
	resolve = resolve,
	cancel_resolve = cancel_resolve,
}
