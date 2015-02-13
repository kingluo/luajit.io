local ffi = require("ffi")

if ffi.arch == "x86" then
ffi.cdef[[
typedef unsigned int socklen_t;
typedef unsigned int __u32;
typedef __u32 __be32;
typedef unsigned short __u16;
typedef __u16 __be16;
typedef unsigned short __kernel_sa_family_t;

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
]]
else
error("arch not support: " .. ffi.arch)
end
