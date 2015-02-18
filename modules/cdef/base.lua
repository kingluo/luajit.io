local ffi = require("ffi")

if ffi.arch == "x86" then
ffi.cdef[[
typedef int ssize_t;
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);
struct iovec {
   void  *iov_base;    /* Starting address */
   size_t iov_len;     /* Number of bytes to transfer */
};
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
int fork(void);
int getpid(void);

int close(int fd);
int ioctl(int d, int request, ...);

ssize_t sendfile(int out_fd, int in_fd, void *offset, size_t count);
int open(const char *pathname, int flags);

typedef int time_t;
typedef long suseconds_t;
time_t time(time_t *t);
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
struct tm *gmtime_r(const time_t *timep, struct tm *result);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);

struct timeval {
	time_t      tv_sec;     /* seconds */
	suseconds_t tv_usec;    /* microseconds */
};
struct timezone {
	int tz_minuteswest;     /* minutes west of Greenwich */
	int tz_dsttime;         /* type of DST correction */
};
int gettimeofday(struct timeval *tv, struct timezone *tz);

int ioctl(int d, int request, ...);
int close(int fd);
char *strerror(int errnum);

char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
int strncmp(const char *s1, const char *s2, size_t n);

void *memchr(const void *s, int c, size_t n);
void *memrchr(const void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memmove(void *dest, const void *src, size_t n);

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);

typedef unsigned int uid_t;
typedef unsigned int gid_t;
uid_t getuid(void);
uid_t geteuid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);

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
struct passwd *getpwnam(const char *name);
struct group {
   char   *gr_name;       /* group name */
   char   *gr_passwd;     /* group password */
   gid_t   gr_gid;        /* group ID */
   char  **gr_mem;        /* group members */
};
struct group *getgrnam(const char *name);
int initgroups(const char *user, gid_t group);

int daemon(int nochdir, int noclose);

static const int EAGAIN = 11;
static const int EINTR = 4;
static const int EINPROGRESS = 115;
]]
else
error("arch not support: " .. ffi.arch)
end
