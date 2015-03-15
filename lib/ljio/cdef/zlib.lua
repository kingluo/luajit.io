local ffi = require("ffi")

if ffi.arch == "x86" then
ffi.cdef[[
unsigned long compressBound(unsigned long sourceLen);
int compress2(uint8_t *dest, unsigned long *destLen,
	      const uint8_t *source, unsigned long sourceLen, int level);
int uncompress(uint8_t *dest, unsigned long *destLen,
	       const uint8_t *source, unsigned long sourceLen);

typedef unsigned char Byte;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef Byte Bytef;
typedef char charf;
typedef int intf;
typedef uInt uIntf;
typedef uLong uLongf;
typedef void const *voidpc;
typedef void *voidpf;
typedef void *voidp;
typedef voidpf (*alloc_func) (voidpf opaque, uInt items, uInt size);
typedef void (*free_func) (voidpf opaque, voidpf address);

typedef struct z_stream_s {
    Bytef *next_in;
    uInt avail_in;
    uLong total_in;

    Bytef *next_out;
    uInt avail_out;
    uLong total_out;

    char *msg;
    void *state;

    alloc_func zalloc;
    free_func zfree;
    voidpf opaque;

    int data_type;
    uLong adler;
    uLong reserved;
} z_stream;
typedef z_stream *z_streamp;
extern int deflateInit2_ (z_streamp strm, int level, int method,
	int windowBits, int memLevel, int strategy, const char *version, int stream_size);
extern int deflateEnd (z_streamp strm);
extern int deflate (z_streamp strm, int flush);
uLong crc32 (uLong crc, const Bytef *buf, uInt len);

static const int Z_NO_FLUSH      =0;
static const int Z_PARTIAL_FLUSH =1;
static const int Z_SYNC_FLUSH    =2;
static const int Z_FULL_FLUSH    =3;
static const int Z_FINISH        =4;
static const int Z_DEFLATED   = 8;

static const int Z_OK = 0;
static const int Z_STREAM_ERROR = -2;
static const int Z_STREAM_END = 1;
]]
else
error("arch not support: " .. ffi.arch)
end
