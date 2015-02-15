local ffi = require"ffi"

if ffi.arch == "x86" then
ffi.cdef[[
int getpid(void);

typedef long int __time_t;
typedef __time_t time_t;

struct timespec
  {
    __time_t tv_sec;
    long int tv_nsec;
  };

typedef int __clockid_t;
typedef __clockid_t clockid_t;
int clock_gettime(clockid_t clk_id, struct timespec *tp);

struct itimerspec {
   struct timespec it_interval;  /* Interval for periodic timer */
   struct timespec it_value;     /* Initial expiration */
};
int timerfd_create(clockid_t clockid, int flags);
int timerfd_settime(int fd, int flags,
				   const struct itimerspec *new_value,
				   struct itimerspec *old_value);

const static clockid_t CLOCK_MONOTONIC=1;
const static clockid_t CLOCK_MONOTONIC_RAW=4;
]]
else
error("arch not support: " .. ffi.arch)
end
