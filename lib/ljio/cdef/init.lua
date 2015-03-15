require"ljio.cdef.base"
require"ljio.cdef.time"
require"ljio.cdef.signal"
require"ljio.cdef.epoll"
require"ljio.cdef.socket"
require"ljio.cdef.syslog"
require"ljio.cdef.ssl"
require"ljio.cdef.zlib"
require"ljio.cdef.pthread"

return require"ffi".C
