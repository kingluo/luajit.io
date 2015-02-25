local ffi = require("ffi")

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

]]

local zlib = ffi.load("z")

local function compress(txt)
	local n = zlib.compressBound(#txt)
	local buf = ffi.new("uint8_t[?]", n)
	local buflen = ffi.new("unsigned long[1]", n)
	local res = zlib.compress2(buf, buflen, txt, #txt, 9)
	assert(res == 0)
	return ffi.string(buf, buflen[0])
end

local function uncompress(comp, n)
	local buf = ffi.new("uint8_t[?]", n)
	local buflen = ffi.new("unsigned long[1]", n)
	local res = zlib.uncompress(buf, buflen, comp, #comp)
	assert(res == 0)
	return ffi.string(buf, buflen[0])
end

return {
	compress = compress,
	uncompress = uncompress,
}
