local ffi = require("ffi")

if ffi.arch == "x86" then
ffi.cdef[[
typedef unsigned int socklen_t;
typedef unsigned int __u32;
typedef __u32 __be32;
typedef unsigned short __u16;
typedef __u16 __be16;
typedef unsigned short __kernel_sa_family_t;
typedef unsigned short int sa_family_t;

struct in_addr {
 __be32 s_addr;
};

struct sockaddr_in {
  __kernel_sa_family_t sin_family;
  __be16 sin_port;
  struct in_addr sin_addr;


  unsigned char __pad[16 - sizeof(short int) -
   sizeof(unsigned short int) - sizeof(struct in_addr)];
};

struct sockaddr {
	short int sa_family;
	char sa_data[14];
};

struct sockaddr_un
  {
    sa_family_t sun_family;
    char sun_path[108];
  };

short int ntohs(short int netshort);
short int htons(short int hostshort);
int inet_aton(const char *cp, struct in_addr *inp);
char *inet_ntoa(struct in_addr in);

int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

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

static const int SIGEV_SIGNAL = 0;
static const int GAI_NOWAIT = 1;

static const int AF_UNIX=1;
static const int AF_INET=2;
static const int SOCKET_STREAM=1;
static const int SOL_SOCKET=1;
static const int SO_REUSEADDR=2;
static const int SO_ERROR = 4;
static const int IPPROTO_TCP=6;
static const int TCP_CORK = 3;
]]
else
error("arch not support: " .. ffi.arch)
end
