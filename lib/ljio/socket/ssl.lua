local ffi = require("ffi")
local C = require("ljio.cdef")
local utils = require("ljio.core.utils")

local cryto = ffi.load("crypto")
local ssl = ffi.load("ssl")
local sslctx

local function create_ssl(self)
	if not self.ssl then
		self.ssl = ssl.SSL_new(sslctx)
		ssl.SSL_set_fd(self.ssl, self.fd)
		if self.connected then
			ssl.SSL_set_connect_state(self.ssl)
		else
			ssl.SSL_set_accept_state(self.ssl)
		end
	end
end

local function ssl_read(self, rbuf, size)
	create_ssl(self)
	local len = ssl.SSL_read(self.ssl, rbuf.rp, size)
	local err
	if len > 0 then
		rbuf.rp = rbuf.rp + len
	else
		local sslerr = ssl.SSL_get_error(self.ssl, len)
		if sslerr == C.SSL_ERROR_ZERO_RETURN or sslerr == C.SSL_ERROR_SSL then
			ssl.SSL_set_quiet_shutdown(self.ssl, 1)
			self:close()
			err = "closed"
		elseif sslerr == C.SSL_ERROR_WANT_READ then
			self:yield_r()
		elseif sslerr == C.SSL_ERROR_WANT_WRITE then
			epoll.add_event(self.ev, C.EPOLLOUT)
			self:yield_w()
			epoll.del_event(self.ev, C.EPOLLOUT)
		elseif sslerr == C.SSL_ERROR_SYSCALL then
			local errno = ffi.errno()
			if errno == C.EAGAIN then
				self:yield_r()
			elseif errno ~= C.EINTR then
				ssl.SSL_set_quiet_shutdown(self.ssl, 1)
				self:close()
				err = utils.strerror(errno)
			end
		end
	end
	return len, err
end

local function ssl_write(self, iovec, idx, iovcnt)
	create_ssl(self)
	local buf = ffi.new("char[4096*16]")
	local len = 0
	for i=0,iovcnt-1 do
		local iovec = iovec[idx + i]
		ffi.copy(buf + len, iovec.iov_base, iovec.iov_len)
		len = len + iovec.iov_len
	end
	local len = ssl.SSL_write(self.ssl, buf, len)
	if len <= 0 then
		local sslerr = ssl.SSL_get_error(self.ssl, len)
		if sslerr == C.SSL_ERROR_WANT_READ then
			self:yield_r()
		elseif sslerr == C.SSL_ERROR_WANT_WRITE then
			epoll.add_event(self.ev, C.EPOLLOUT)
			self:yield_w()
			epoll.del_event(self.ev, C.EPOLLOUT)
		elseif sslerr == C.SSL_ERROR_SYSCALL then
			local errno = ffi.errno()
			if errno == C.EAGAIN then
				self:yield_w()
			elseif errno ~= C.EINTR then
				ssl.SSL_set_quiet_shutdown(self.ssl, 1)
				self:close()
				err = utils.strerror(errno)
			end
		end
	end
	return len
end

local function ssl_shutdown(self)
	if coroutine.running() == nil then
		ssl.SSL_set_quiet_shutdown(self.ssl, 1)
	end
	while true do
		local ret = ssl.SSL_shutdown(self.ssl)
		local sslerr = 0
		if ret ~= 1 and ssl.ERR_peek_error() ~= 0 then
			sslerr = ssl.SSL_get_error(self.ssl, len)
		end
		if ret == 1 or sslerr == 0 or sslerr == C.SSL_ERROR_ZERO_RETURN then
			ssl.SSL_free(self.ssl)
			self.ssl = nil
			break
		end
		if sslerr == C.SSL_ERROR_WANT_READ then
			self:yield_r()
		elseif sslerr == C.SSL_ERROR_WANT_WRITE then
			epoll.add_event(self.ev, C.EPOLLOUT)
			self:yield_w()
			epoll.del_event(self.ev, C.EPOLLOUT)
		else
			ssl.SSL_free(self.ssl)
			self.ssl = nil
			break
		end
	end
end

local function init(cfg)
	if cfg.ssl then
		cryto.OPENSSL_config(nil)
		ssl.SSL_library_init()
		ssl.SSL_load_error_strings()
		cryto.OPENSSL_add_all_algorithms_noconf()

		sslctx = ssl.SSL_CTX_new(ssl.SSLv23_method())
		ssl.SSL_set_read_ahead(sslctx, 1)
		ssl.SSL_CTX_ctrl(sslctx, C.SSL_CTRL_OPTIONS, C.SSL_OP_NO_COMPRESSION, nil)
		ssl.SSL_CTX_ctrl(sslctx, C.SSL_CTRL_MODE, C.SSL_MODE_RELEASE_BUFFERS, nil)
		ssl.SSL_CTX_set_cipher_list(sslctx, cfg.ssl_ciphers)
		ssl.SSL_CTX_use_certificate_file(sslctx, cfg.ssl_certificate, C.SSL_FILETYPE_PEM)
		ssl.SSL_CTX_use_PrivateKey_file(sslctx, cfg.ssl_certificate_key, C.SSL_FILETYPE_PEM)
	end
end

return {
	init = init,
	read = ssl_read,
	write = ssl_write,
	shutdown = ssl_shutdown,
}
