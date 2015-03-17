local ffi = require("ffi")

if ffi.arch == "x86" then
ffi.cdef[[
typedef int ssize_t;
struct stat {
        unsigned long  st_dev;
        unsigned long  st_ino;
        unsigned short st_mode;
        unsigned short st_nlink;
        unsigned short st_uid;
        unsigned short st_gid;
        unsigned long  st_rdev;
        unsigned long  st_size;
        unsigned long  st_blksize;
        unsigned long  st_blocks;
        unsigned long  st_atime;
        unsigned long  st_atime_nsec;
        unsigned long  st_mtime;
        unsigned long  st_mtime_nsec;
        unsigned long  st_ctime;
        unsigned long  st_ctime_nsec;
        unsigned long  __unused4;
        unsigned long  __unused5;
};
static const int SYS_stat = 106;
]]
elseif ffi.arch == "x64" then
ffi.cdef[[
typedef long int ssize_t;
struct stat {
        unsigned long   st_dev;
        unsigned long   st_ino;
        unsigned long   st_nlink;

        unsigned int    st_mode;
        unsigned int    st_uid;
        unsigned int    st_gid;
        unsigned int    __pad0;
        unsigned long   st_rdev;
        long            st_size;
        long            st_blksize;
        long            st_blocks;      /* Number 512-byte blocks allocated. */

        unsigned long   st_atime;
        unsigned long   st_atime_nsec;
        unsigned long   st_mtime;
        unsigned long   st_mtime_nsec;
        unsigned long   st_ctime;
        unsigned long   st_ctime_nsec;
        long            __unused[3];
};
static const int SYS_stat = 4;
]]
end

ffi.cdef[[
typedef unsigned int mode_t;
typedef int __pid_t;
typedef long int __off_t;
typedef __off_t off_t;

struct iovec {
   void  *iov_base;    /* Starting address */
   size_t iov_len;     /* Number of bytes to transfer */
};
struct flock
  {
    short int l_type;
    short int l_whence;

    __off_t l_start;
    __off_t l_len;




    __pid_t l_pid;
  };

typedef long int __time_t;
typedef __time_t time_t;
typedef long int __suseconds_t;
typedef __suseconds_t suseconds_t;

struct timespec
  {
    __time_t tv_sec;
    long int tv_nsec;
  };
struct itimerspec
  {
    struct timespec it_interval;
    struct timespec it_value;
  };
typedef int __clockid_t;
typedef __clockid_t clockid_t;

struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
  long int tm_gmtoff;
  __const char *tm_zone;
};

struct timeval
  {
    __time_t tv_sec;
    __suseconds_t tv_usec;
  };
struct timezone
  {
    int tz_minuteswest;
    int tz_dsttime;
  };
typedef unsigned int uid_t;
typedef unsigned int gid_t;
struct passwd
{
  char *pw_name;
  char *pw_passwd;
  uid_t pw_uid;
  gid_t pw_gid;
  char *pw_gecos;
  char *pw_dir;
  char *pw_shell;
};
struct group
  {
    char *gr_name;
    char *gr_passwd;
    gid_t gr_gid;
    char **gr_mem;
  };
]]

ffi.cdef[[
int fcntl (int __fd, int __cmd, ...);
long int syscall (long int __sysno, ...);
int fork(void);
int getpid(void);
char *strerror(int errnum);

int open(const char *pathname, int flags, ...);
off_t lseek(int fd, off_t offset, int whence);
int close(int fd);
int ioctl (int fd, unsigned long int request, ...);
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, __off_t offset);
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
int unlink(const char *pathname);

int clock_gettime(clockid_t clk_id, struct timespec *tp);
int timerfd_create(clockid_t clockid, int flags);
int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
time_t time(time_t *t);
struct tm *gmtime(const time_t *timep);
struct tm *gmtime_r(const time_t *timep, struct tm *result);
time_t mktime(struct tm *tm);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);
char *strptime(const char *s, const char *format, struct tm *tm);
int gettimeofday(struct timeval *tv, struct timezone *tz);

char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
int strncmp(const char *s1, const char *s2, size_t n);

void *memchr(const void *s, int c, size_t n);
void *memrchr(const void *s, int c, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memmove(void *dest, const void *src, size_t n);

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);

uid_t getuid(void);
uid_t geteuid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
struct passwd *getpwnam(const char *name);
struct group *getgrnam(const char *name);
int initgroups(const char *user, gid_t group);
int daemon(int nochdir, int noclose);
]]

ffi.cdef[[
static const int PROT_READ = 0x1;
static const int PROT_WRITE = 0x2;
static const int MAP_ANON = 0x20;
static const int MAP_SHARED = 0x01;

static const int F_SETLKW = 7;
static const short int F_RDLCK         =0;
static const short int F_WRLCK         =1;
static const short int F_UNLCK         =2;
static const short int SEEK_SET         =0;

static const int EAGAIN = 11;
static const int EINTR = 4;
static const int EINPROGRESS = 115;

const static clockid_t CLOCK_MONOTONIC = 1;
const static clockid_t CLOCK_MONOTONIC_RAW = 4;
]]
