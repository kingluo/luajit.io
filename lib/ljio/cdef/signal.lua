local ffi = require("ffi")

ffi.cdef[[
typedef struct
  {
    unsigned long int __val[(1024 / (8 * sizeof (unsigned long int)))];
  } __sigset_t;
typedef __sigset_t sigset_t;
int signalfd(int fd, const sigset_t *mask, int flags);

struct signalfd_siginfo
{
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

typedef void (*sighandler_t) (int);
sighandler_t signal (int __sig, sighandler_t __handler);

static const int32_t SI_ASYNCNL = -60;

static const int SIGHUP = 1;
static const int SIGINT = 2;
static const int SIGQUIT = 3;
static const int SIGUSR1 = 10;
static const int SIGSEGV = 11;
static const int SIGUSR2 = 12;
static const int SIGPIPE = 13;
static const int SIGTERM = 15;
static const int SIGCHLD = 17;
static const int SIGWINCH = 28;
static const int SIGIO = 29;
]]
