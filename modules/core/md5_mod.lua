local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable
local error = error

local _M = {}
local mt = { __index = _M }

ffi.cdef[[
typedef unsigned long MD5_LONG ;

enum {
    MD5_CBLOCK = 64,
    MD5_LBLOCK = MD5_CBLOCK/4
};

typedef struct MD5state_st {
	MD5_LONG A,B,C,D;
	MD5_LONG Nl,Nh;
	MD5_LONG data[MD5_LBLOCK];
	unsigned int num;
} MD5_CTX;

int MD5_Init(MD5_CTX *c);
int MD5_Update(MD5_CTX *c, const void *data, size_t len);
int MD5_Final(unsigned char *md, MD5_CTX *c);
]]

local buf = ffi_new("char[16]")
local ctx_ptr_type = ffi.typeof("MD5_CTX[1]")
local ssl = ffi.load("ssl")

function new()
    local ctx = ffi_new(ctx_ptr_type)
    if ssl.MD5_Init(ctx) == 0 then
        return nil
    end
    return setmetatable({ _ctx = ctx }, mt)
end

function _M.update(self, s)
    return ssl.MD5_Update(self._ctx, s, #s) == 1
end

function _M.final(self)
    if ssl.MD5_Final(buf, self._ctx) == 1 then
        return ffi_str(buf, 16)
    end
end

function _M.reset(self)
    return ssl.MD5_Init(self._ctx) == 1
end

return setmetatable({
	new = new,
}, {
	__call = function(func, ...)
		local ctx = ffi_new(ctx_ptr_type)
		if ssl.MD5_Init(ctx) == 0 then
			return nil
		end
		for i=1,select('#', ...) do
			local s = select(i, ...)
			if ssl.MD5_Update(ctx, s, #s) ~= 1 then
				return nil
			end
		end
		if ssl.MD5_Final(buf, ctx) == 1 then
			local s = ffi_str(buf, 16)
			s = string.gsub(s,"(.)",function (x) return string.format("%.2x",string.byte(x)) end)
			return s
		end
	end
})
