local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
struct fd_guard {int fd;};
int ioctl(int d, int request, ...);
int close(int fd);
]]

local fd_guard = ffi.metatype("struct fd_guard", {
	__gc = function(g)
		if g.fd > 0 then ffi.C.close(g.fd) end
	end
})

local FIONBIO=0x5421
local non_block_flag = ffi.new("int[1]",1)
local function set_nonblock(fd)
	assert(ffi.C.ioctl(fd, FIONBIO, non_block_flag) == 0)
end

local imported_modules = {}

local function import(m)
	m = require(m)
	assert(type(m) == "table")
	if not imported_modules[m] then
		imported_modules[m] = true
		for k,v in pairs(m) do
			_G[k] = v
		end
	end
end

local function strerrno()
	return ffi.string(ffi.C.strerror(ffi.C.errno))
end

local function bin2hex(s)
    s = string.gsub(s,"(.)",function (x) return string.format("%x",string.byte(x)) end)
	return s
end

return {
	import = import,
	fd_guard = fd_guard,
	set_nonblock = set_nonblock,
	strerrno = strerrno,
	bin2hex = bin2hex,
}
