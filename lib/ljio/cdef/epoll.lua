local ffi = require("ffi")

ffi.cdef[[
typedef union epoll_data
{
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

struct epoll_event
{
  uint32_t events;
  epoll_data_t data;
} __attribute__ ((__packed__));

int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

static const int EPOLL_CTL_ADD = 1;
static const int EPOLL_CTL_DEL = 2;
static const int EPOLL_CTL_MOD = 3;

static const uint32_t EPOLLIN = 0x1;
static const uint32_t EPOLLPRI = 0x2;
static const uint32_t EPOLLOUT = 0x4;
static const uint32_t EPOLLERR = 0x8;
static const uint32_t EPOLLHUP = 0x10;
static const uint32_t EPOLLET = 0x8000;
static const uint32_t EPOLLRDHUP = 0x2000;
]]
