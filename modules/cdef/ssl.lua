local ffi = require("ffi")

if ffi.arch == "x86" then
ffi.cdef[[
int SSL_library_init(void);
void *SSLv23_method(void);
void SSL_load_error_strings(void );
void *SSL_CTX_new(const void *method);
int SSL_CTX_use_PrivateKey_file(void *ctx, const char *file, int type);
int SSL_CTX_use_certificate_file(void *ctx, const char *file, int type);
int SSL_CTX_set_cipher_list(void *,const char *str);
void *SSL_new(void *ctx);
int SSL_set_fd(void *ssl, int fd);
int SSL_accept(void *ssl);
int SSL_connect(void *ssl);
int SSL_read(void *ssl, void *buf, int num);
int SSL_write(void *ssl, const void *buf, int num);
int SSL_shutdown(void *ssl);
int SSL_get_error(const void *ssl, int ret);
void SSL_set_connect_state(void *ssl);
void SSL_set_accept_state(void *ssl);

static const int SSL_FILETYPE_PEM = 1;
static const int SSL_ERROR_WANT_READ = 2;
static const int SSL_ERROR_WANT_WRITE = 3;
static const int SSL_ERROR_SYSCALL = 5;
static const int SSL_ERROR_ZERO_RETURN = 6;
]]
else
error("arch not support: " .. ffi.arch)
end
