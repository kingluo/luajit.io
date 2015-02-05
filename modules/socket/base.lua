local ffi = require("ffi")

ffi.cdef[[
struct in_addr {
	unsigned int  s_addr;
};
struct sockaddr_in {
  short int  sin_family;	 /* Address family			   */
  unsigned short int				sin_port;	   /* Port number				  */
  struct in_addr		sin_addr;	   /* Internet address			 */

  /* Pad to size of `struct sockaddr'. */
  unsigned char		 __pad[16 - sizeof(short int) -
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
int bind(int sockfd, const struct sockaddr *addr,
		unsigned int addrlen);
int connect(int sockfd, const struct sockaddr *addr,
		   unsigned int addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, unsigned int *addrlen);

int setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);
]]