local ffi = require("ffi")

ffi.cdef[[
typedef int ssize_t;
typedef unsigned int size_t;
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
]]
