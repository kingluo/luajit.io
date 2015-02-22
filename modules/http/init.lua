local C = require("cdef")
local ffi = require("ffi")
local tcp = require("socket.tcp")
local URI = require("uri")
local uri_decode = require("uri._util").uri_decode

local strsub = string.sub
local strfind = string.find
local strmatch = string.match
local strgsub = string.gsub
local strformat = string.format
local tinsert = table.insert
local tsort = table.sort

local function unescape(s)
	s = strgsub(s,"+"," ")
	return uri_decode(s)
end

local function parse_uri_args(query)
	local uri_args = {}
	local i = 0
	local j = 0
	local match
	while true do
		i,j,match = strfind(query, "([^&]+)", j+1)
		if not match then break end
		local n = match
		local v
		local i = strfind(match,"=",1,true)
		if i then
			n = strsub(match,1,i-1)
			v = strsub(match,i+1)
		end

		n = unescape(n)
		if v then v = unescape(v) end
		v = v or true

		if not uri_args[n] then
			uri_args[n] = v
		else
			if type(uri_args[n]) ~= "table" then
				uri_args[n] = {uri_args[n]}
			end
			tinsert(uri_args[n], v)
		end
	end
	return uri_args
end

local function receive_headers(sock, headers)
	local line, name, value, err
	headers = headers or {}

	-- get first line
	line, err = sock:receive()
	if err then return nil, err end

	-- headers go until a blank line is found
	while line ~= "" do
		-- get field-name and value
		name, value = strmatch(line, "^(.-):%s*(.*)")
		if not (name and value) then return nil, "malformed reponse headers" end
		name = string.lower(name)

		-- get next line (value might be folded)
		line, err = sock:receive()
		if err then return nil, err end

		-- unfold any folded values
		while strfind(line, "^%s") do
			value = value .. line
			line = sock:receive()
			if err then return nil, err end
		end

		-- save pair in table
		if headers[name] then headers[name] = headers[name] .. ", " .. value
		else headers[name] = value end
	end

	return headers
end

local function receive_body(sock, headers, chunk_handler)
	local length = tonumber(headers["content-length"])
	if not length or length < 0 then return false, 'invalid content-length' end
	local t = headers["transfer-encoding"]
	if t and t ~= "identity" then
		while true do
			local line, err = sock:receive()
			if err then return false, err end
			-- get chunk size, skip extention
			local size = tonumber(strgsub(line, ";.*", ""), 16)
			if not size then return false, "invalid chunk size" end
			-- was it the last chunk?
			if size > 0 then
				-- if not, get chunk and skip terminating CRLF
				local chunk, err = sock:receive(size)
				if chunk then sock:receive() else return false, err end
				chunk_handler(chunk)
			else
				-- if it was, read trailers into headers table
				receive_headers(sock, headers)
				break
			end
		end
	elseif length then
		local len
		while true do
			if length > 4096 then
				len = 4096
			elseif length == 0 then
				break
			else
				assert(length > 0)
				len = length
			end
			length = length - len
			local chunk, err = sock:receive(len)
			chunk_handler(chunk)
		end
		return true
	end
	return false, 'invalid body'
end

local http_req_mt = {__index={}}
function http_req_mt.__index.read_body(self, sink)
	if self.method ~= 'POST' then return "only support POST" end
	if not self.body_read then
		receive_body(self.sock, self.headers, sink)
		self.body_read = true
	end
end

function http_req_mt.__index.get_uri_args(self)
	if not self.uri_args then
		self.uri_args = parse_uri_args(self.url:query())
	end
	return self.uri_args
end

function http_req_mt.__index.get_post_args(self)
	if self.method ~= "POST" then return nil, "not POST" end
	if not self.post_args then
		receive_body(self.sock, self.headers, function(chunk)
			self.post_args = parse_uri_args(chunk)
		end)
	end
	return self.post_args
end

local status_tbl = {
	[200] = "HTTP/1.1 200 OK\r\n";
	[400] = "HTTP/1.1 400 Bad Request\r\n";
	[403] = "HTTP/1.1 403 Forbidden\r\n";
	[404] = "HTTP/1.1 404 Not Found\r\n";
	[500] = "HTTP/1.1 500 Internal Server Error\r\n";
	[501] = "HTTP/1.1 501 Not Implemented\r\n";
	[503] = "HTTP/1.1 503 Service Unavailable\r\n";
}

local http_rsp_mt = {__index={}}

local v_time_t = ffi.new("time_t[1]")
local date_buf = ffi.new("char[?]", 200)
local tm = ffi.new("struct tm[1]")
local function http_time()
	assert(C.time(v_time_t) > 0)
	assert(C.gmtime_r(v_time_t, tm))
	local len = C.strftime(date_buf, 200, "%a, %d %h %G %H:%M:%S GMT", tm)
	assert(len > 0)
	return ffi.string(date_buf, len)
end

function http_rsp_mt.__index.send_headers(self)
	if not self.headers_sent then
		local sk = self.sock
		local status = status_tbl[self.status or 200] or status_tbl[500]
		local ret,err = sk:send(status)
		if err then return err end

		-- adjust headers
		if not self.headers["content-length"] then
			self.headers["transfer-encoding"] = "chunked"
		end
		if not self.headers["content-type"] then
			self.headers["content-type"] = "text/plain; charset=utf-8"
		end

		self.headers["server"] = "luajit.io"

		self.headers["date"] = http_time()
		self.headers["cache-control"] = "no-cache, private"
		self.headers["connection"] = "Keep-Alive"

		if self.req.headers["connection"] == "close" then
			self.headers["connection"] = "close"
		end

		if not self.output_buf then self.output_buf = {} end
		local tbl = self.output_buf
		local eol = "\r\n"
		local sep = ": "
		for f, v in pairs(self.headers) do
			tinsert(tbl, f)
			tinsert(tbl, sep)
			tinsert(tbl, v)
			tinsert(tbl, eol)
		end
		tinsert(tbl, eol)

		local ret,err = sk:send(tbl)
		if err then return err end
		self.headers_sent = true
	end
end

local postpone_output = 1460

function http_rsp_mt.__index.say(self, ...)
	local err = self:send_headers()
	if err then return nil,err end

	if not self.is_chunked then
		self.is_chunked = self.headers["transfer-encoding"] == "chunked"
	end
	local tbl = self.output_buf
	if not self.output_buf_bytes then self.output_buf_bytes = 0 end
	if not self.output_buf_idx then self.output_buf_idx = 1 end
	local eol = "\r\n"
	for i=1,select("#",...) do
		local str = select(i,...)
		local len = #str
		self.output_buf_bytes = self.output_buf_bytes + len
		if self.is_chunked then
			local size = strformat("%X\r\n", len)
			tbl[self.output_buf_idx] = size
			self.output_buf_idx = self.output_buf_idx + 1
			self.output_buf_bytes = self.output_buf_bytes + #size
			tbl[self.output_buf_idx] = str
			self.output_buf_idx = self.output_buf_idx + 1
			tbl[self.output_buf_idx] = eol
			self.output_buf_idx = self.output_buf_idx + 1
			self.output_buf_bytes = self.output_buf_bytes + 1
		else
			tbl[self.output_buf_idx] = str
			self.output_buf_idx = self.output_buf_idx + 1
		end
	end

	if self.output_buf_bytes >= postpone_output then
		tbl[self.output_buf_idx] = nil
		self.output_buf_idx = 1
		self.output_buf_bytes = 0
		local ret,err = self.sock:send(tbl)
		if err then return nil,err end
	end

	return 1
end

function http_rsp_mt.__index.flush(self)
	if self.output_buf_bytes and self.output_buf_bytes > 0 then
		local tbl = self.output_buf
		tbl[self.output_buf_idx] = nil
		self.output_buf_idx = 1
		self.output_buf_bytes = 0
		local ret,err = self.sock:send(tbl)
		if err then return err end
	end
	return 1
end

local function http_req_new(method, url, headers, sock)
	return setmetatable({body_read = false,
		method = method, url = url,
		headers = headers, sock = sock}, http_req_mt)
end

local function http_rsp_new(req, sock)
	return setmetatable({headers_sent = false, headers = {}, sock = sock, req = req}, http_rsp_mt)
end

local g_http_cfg

local function http_parse_conf(cfg)
	g_http_cfg = cfg

	local function more_than(a,b)
		return a > b
	end

	for _,srv in ipairs(cfg) do
		srv.servlet_hash = {
			exact_hash={},
			prefix_hash={},
			postfix_hash={}, postfix_hash_len=0,
			pattern={}
		}
		local shash = srv.servlet_hash
		for _,servlet in ipairs(srv.servlet) do
			if servlet[1] == "=" then
				shash.exact_hash[servlet[2]] = servlet
			elseif servlet[1] == "^" or servlet[1] == "^~" then
				shash.prefix_hash[servlet[2]] = servlet
			elseif servlet[1] == "$" then
				shash.postfix_hash[servlet[2]] = servlet
				shash.postfix_hash_len = shash.postfix_hash_len + 1
			else
				tinsert(shash.pattern, servlet)
			end
		end

		local tmp = {}
		for k in pairs(shash.prefix_hash) do
			tmp[#k] = 1
		end
		shash.prefix_size_hash = {}
		for k in pairs(tmp) do
			tinsert(shash.prefix_size_hash, k)
		end
		tsort(shash.prefix_size_hash, more_than)
	end

	for port,addresses in pairs(cfg.srv_tbl) do
		for address,srv_list in pairs(addresses) do
			srv_list.extra_hash = {}
			srv_list.prefix_hash = {}
			srv_list.postfix_hash = {}
			srv_list.pattern = {}

			for _,srv in ipairs(srv_list) do
				for _,host in ipairs(srv.server_name) do
					local prefix = strsub(host,1,1)
					local postfix = strsub(host,#host)
					if prefix == "~" then
						tinsert(srv_list.pattern, {host=strsub(host,2),srv=srv})
					elseif prefix == "*" or prefix == "." then
						if prefix == "*" then host = strsub(host,2) end
						srv_list.prefix_hash[host] = srv
						if prefix == "." then
							srv_list.extra_hash[host] = srv
						end
					elseif postfix == "*" then
						srv_list.postfix_hash[strsub(host,1,#host-1)] = srv
					else
						srv_list.extra_hash[host] = srv
					end
				end
			end

			local tmp = {}
			for k in pairs(srv_list.prefix_hash) do
				tmp[#k] = 1
			end
			srv_list.prefix_size_hash = {}
			for k in pairs(tmp) do
				tinsert(srv_list.prefix_size_hash, k)
			end
			tsort(srv_list.prefix_size_hash, more_than)

			srv_list.postfix_size_hash = {}
			local tmp = {}
			for k in pairs(srv_list.postfix_hash) do
				tmp[#k] = 1
			end
			for k in pairs(tmp) do
				tinsert(srv_list.postfix_size_hash, k)
			end
			tsort(srv_list.postfix_size_hash, more_than)
		end
	end
end

local function do_servlet(req, rsp)
	local match_srv
	local srv_list = g_http_cfg.srv_tbl[req.sock.srv_port][req.sock.srv_ip]
		or g_http_cfg.srv_tbl[req.sock.srv_port]["*"]

	if #srv_list > 1 then
		local host = req.headers["host"] or ""
		local hlen = #host

		-- exact name
		match_srv = srv_list.extra_hash[host]

		-- longest wildcard name starting with an asterisk, e.g. "*.example.org"
		if not match_srv then
			for _,v in ipairs(srv_list.prefix_size_hash) do
				if srv_list.prefix_hash[strsub(host, hlen-v+1)] then
					match_srv = v.srv
					break
				end
			end
		end

		-- longest wildcard name ending with an asterisk, e.g. "mail.*"
		if not match_srv then
			for _,v in ipairs(srv_list.postfix_size_hash) do
				if srv_list.postfix_hash[strsub(host, 1, v)] then
					match_srv = v.srv
					break
				end
			end
		end

		-- first matching regular expression (in order of appearance in a configuration file)
		if not match_srv then
			for _,v in ipairs(srv_list.pattern) do
				if strfind(host, v.host) then
					match_srv = v.srv
					break
				end
			end
		end

		if not match_srv then
			match_srv = srv_list.default_server
		end
	end

	if not match_srv then
		match_srv = srv_list[1]
	end

	local servlet
	if match_srv then
		local shash = match_srv.servlet_hash
		local path = req.url:path()
		local pathlen = #path
		local match_done = false

		-- exact match
		servlet = shash.exact_hash[path]
		if servlet then match_done = true end

		-- postfix match
		if not match_done then
			if shash.postfix_hash_len > 0 then
				local p = C.strrchr(path, 46)
				if p ~= nil then
					local postfix = ffi.string(p + 1)
					servlet = shash.postfix_hash[postfix]
					if servlet then match_done = true end
				end
			end
		end

		-- prefix match
		if not match_done then
			for _,v in ipairs(shash.prefix_size_hash) do
				local slcf = shash.prefix_hash[strsub(path, 1, v)]
				if slcf then
					servlet = slcf
					match_done = (slcf[1] == "^~")
					break
				end
			end
		end

		-- pattern match
		if not match_done then
			for _,slcf in ipairs(shash.pattern) do
				local modifier,pat = slcf[1],slcf[2]
				if modifier == "~" then
					if strfind(path, pat) then
						servlet = slcf
						break
					end
				elseif modifier == "~*" then
					if strfind(string.lower(path), string.lower(pat)) then
						servlet = slcf
						break
					end
				elseif modifier == "f"  then
					if pat(req) then
						servlet = slcf
						break
					end
				end
			end
		end
	end

	if servlet then
		local fn = servlet[3]
		local ret, err
		if type(fn) == 'string' then
			fn = require(fn)
		end
		assert(type(fn) == 'function')
		ret,err = fn(req,rsp,match_srv,servlet)
		coroutine.wait_descendants()
		if not err then
			rsp:flush()
			if rsp.headers["transfer-encoding"] == "chunked" then
				ret,err = rsp.sock:send("0\r\n\r\n")
			end
		end
		if err then
			print(err)
			-- TODO 500 page
			return false
		end
	else
		print "no servlet"
		-- TODO 404 page
		return false
	end
end

local function http_handler(sock)
	while true do
		local line,err = sock:receive()
		if err then print(err); break end
		local method,url,ver = line:match("(.*) (.*) HTTP/(%d%.%d)")
		local uri = URI:new(url)
		if uri._path == "" then
			uri._path = "/"
		else
			uri._path = unescape(uri._path)
		end
		local headers = receive_headers(sock)
		local req = http_req_new(method, uri, headers, sock)
		local rsp = http_rsp_new(req, sock)
		sock.read_quota = sock.stats.consume + (headers["content-length"] or 0)
		local ret = do_servlet(req, rsp)
		sock.read_quota = nil
		-- TODO
		-- 1. discard request body if needed
		-- 2. response error pages according to ret
		if headers["connection"] == "close" then
			break
		end
	end
end

local function run(cfg)
	return tcp(cfg, http_parse_conf, http_handler)
end

return run
