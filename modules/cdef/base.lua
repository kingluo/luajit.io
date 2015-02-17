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

static const int EAGAIN = 11;
static const int EINTR = 4;
static const int EINPROGRESS = 115;
]]
else
error("arch not support: " .. ffi.arch)
end
