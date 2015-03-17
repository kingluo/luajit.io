local ffi = require("ffi")

ffi.cdef[[
void OPENSSL_config(const char *config_name);
void OPENSSL_add_all_algorithms_noconf(void);
int SSL_library_init(void);
void *SSLv23_method(void);
void SSL_load_error_strings(void );
void *SSL_CTX_new(const void *method);
void SSL_set_read_ahead(void *s, int yes);
long SSL_CTX_ctrl(void *ctx,int cmd, long larg, void *parg);
int SSL_CTX_use_PrivateKey_file(void *ctx, const char *file, int type);
int SSL_CTX_use_certificate_file(void *ctx, const char *file, int type);
int SSL_CTX_set_cipher_list(void *,const char *str);
void *SSL_new(void *ctx);
void SSL_free(void *ssl);
int SSL_set_fd(void *ssl, int fd);
int SSL_accept(void *ssl);
int SSL_connect(void *ssl);
int SSL_read(void *ssl, void *buf, int num);
int SSL_write(void *ssl, const void *buf, int num);
void SSL_set_quiet_shutdown(void *ssl,int mode);
int SSL_shutdown(void *ssl);
unsigned long ERR_peek_error(void);
int SSL_get_error(const void *ssl, int ret);
void SSL_set_connect_state(void *ssl);
void SSL_set_accept_state(void *ssl);

static const int SSL_FILETYPE_PEM = 1;
static const int SSL_ERROR_SSL = 1;
static const int SSL_ERROR_WANT_READ = 2;
static const int SSL_ERROR_WANT_WRITE = 3;
static const int SSL_ERROR_SYSCALL = 5;
static const int SSL_ERROR_ZERO_RETURN = 6;
static const int SSL_OP_NO_COMPRESSION = 0x00020000;
static const int SSL_MODE_RELEASE_BUFFERS = 0x00000010;
static const int SSL_CTRL_OPTIONS = 32;
static const int SSL_CTRL_MODE = 33;
]]
