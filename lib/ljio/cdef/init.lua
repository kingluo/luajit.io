local ffi = require("ffi")

if ffi.arch ~= "x86" and ffi.arch ~= "x64" then
	error("arch not support: " .. ffi.arch)
end

require"ljio.cdef.base"
require"ljio.cdef.epoll"
require"ljio.cdef.pthread"
require"ljio.cdef.signal"
require"ljio.cdef.socket"
require"ljio.cdef.ssl"
require"ljio.cdef.syslog"
require"ljio.cdef.zlib"
require"ljio.cdef.inotify"

return ffi.C
