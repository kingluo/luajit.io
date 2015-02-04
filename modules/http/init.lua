local ffi = require("ffi")
local tcp = require("core.tcp_mod")

ffi.cdef[[
typedef int ssize_t;
typedef unsigned int size_t;

int getpid(void);

typedef int time_t;
typedef long suseconds_t;
time_t time(time_t *t);
struct tm {
   int tm_sec;         /* seconds */
   int tm_min;         /* minutes */
   int tm_hour;        /* hours */
   int tm_mday;        /* day of the month */
   int tm_mon;         /* month */
   int tm_year;        /* year */
   int tm_wday;        /* day of the week */
   int tm_yday;        /* day in the year */
   int tm_isdst;       /* daylight saving time */
};
struct tm *gmtime_r(const time_t *timep, struct tm *result);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);

struct timeval {
	time_t      tv_sec;     /* seconds */
	suseconds_t tv_usec;    /* microseconds */
};
struct timezone {
	int tz_minuteswest;     /* minutes west of Greenwich */
	int tz_dsttime;         /* type of DST correction */
};
int gettimeofday(struct timeval *tv, struct timezone *tz);
]]

local function unescape(s)
	s = string.gsub(s,"+"," ")
	return (string.gsub(s, "%%(%x%x)", function(hex)
		return string.char(tonumber(hex, 16))
	end))
end

-----------------------------------------------------------------------------
-- Parses a url and returns a table with all its parts according to RFC 2396
-- The following grammar describes the names given to the URL parts
-- <url> ::= <scheme>://<authority>/<path>;<params>?<query>#<fragment>
-- <authority> ::= <userinfo>@<host>:<port>
-- <userinfo> ::= <user>[:<password>]
-- <path> :: = {<segment>/}<segment>
-- Input
--   url: uniform resource locator of request
--   default: table with default values for each field
-- Returns
--   table with the following fields, where RFC naming conventions have
--   been preserved:
--     scheme, authority, userinfo, user, password, host, port,
--     path, params, query, fragment
-- Obs:
--   the leading '/' in {/<path>} is considered part of <path>
-----------------------------------------------------------------------------
local function parse_url(url, default)
	-- initialize default parameters
	local parsed = {}
	for i,v in pairs(default or parsed) do parsed[i] = v end

	-- get fragment
	url = string.gsub(url, "#(.*)$", function(f)
		parsed.fragment = f
		return ""
	end)

	-- get scheme
	url = string.gsub(url, "^([%w][%w%+%-%.]*)%:",
		function(s) parsed.scheme = s; return "" end)

	-- get authority
	url = string.gsub(url, "^//([^/]*)", function(n)
		parsed.authority = n
		return ""
	end)

	-- get query string
	url = string.gsub(url, "%?(.*)", function(q)
		parsed.query = {}
		for k,v in string.gmatch(q,"([^&=]+)=([^&=]+)") do
			parsed.query[k] = unescape(v)
		end
		return ""
	end)

	-- get params
	url = string.gsub(url, "%;(.*)", function(p)
		parsed.params = p
		return ""
	end)

	-- path is whatever was left
	if url ~= "" then parsed.path = unescape(url) end
	local authority = parsed.authority
	if not authority then return parsed end
	authority = string.gsub(authority,"^([^@]*)@",
		function(u) parsed.userinfo = u; return "" end)
	authority = string.gsub(authority, ":([^:%]]*)$",
		function(p) parsed.port = p; return "" end)
	if authority ~= "" then
		-- IPv6?
		parsed.host = string.match(authority, "^%[(.+)%]$") or authority
	end
	local userinfo = parsed.userinfo
	if not userinfo then return parsed end
	userinfo = string.gsub(userinfo, ":([^:]*)$",
		function(p) parsed.password = p; return "" end)
	parsed.user = userinfo

	return parsed
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
		name, value = string.match(line, "^(.-):%s*(.*)")
		if not (name and value) then return nil, "malformed reponse headers" end
		name = string.lower(name)
		-- get next line (value might be folded)
		line, err = sock:receive()
		if err then return nil, err end
		-- unfold any folded values
		while string.find(line, "^%s") do
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
			local size = tonumber(string.gsub(line, ";.*", ""), 16)
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
	if not self.__priv.body_read then
		receive_body(self.sock, self.headers, sink)
		self.__priv.body_read = true
	end
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
	assert(ffi.C.time(v_time_t) > 0)
	assert(ffi.C.gmtime_r(v_time_t, tm))
	local len = ffi.C.strftime(date_buf, 200, "%a, %d %h %G %H:%M:%S GMT", tm)
	assert(len > 0)
	return ffi.string(date_buf, len)
end

function http_rsp_mt.__index.send_headers(self)
	if not self.__priv.headers_sent then
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

		local h = "\r\n"
		for f, v in pairs(self.headers) do
			h = f .. ": " .. v .. "\r\n" .. h
		end

		local ret,err = sk:send(h)
		if err then return err end
		self.__priv.headers_sent = true
	end
end

function http_rsp_mt.__index.say(self, str)
	local err = self:send_headers()
	if err then return err end

	local sk = self.sock

	if self.headers["transfer-encoding"] == "chunked" then
		local size = string.format("%X\r\n", string.len(str))
		local ret,err = sk:send(size, str, "\r\n")
		if err then return err end
	else
		local ret,err = sk:send(str)
		if err then return err end
	end
end

local function http_req_new(method, url, headers, sock)
	return setmetatable({__priv = {},
		method = method, url = url,
		headers = headers, sock = sock}, http_req_mt)
end

local function http_rsp_new(req, sock)
	return setmetatable({__priv = {}, headers = {}, sock = sock, req = req}, http_rsp_mt)
end

local g_http_cfg

local function do_servlet(req, rsp)
	local sk = req.sock
	local target_srv
	local host = req.headers["host"]
	for _,srv in ipairs(g_http_cfg) do
		if string.find(srv.listen, sk.listen, 1, true) then
			for _,h in pairs(srv.host) do
				if h == host then
					target_srv = srv
					break
				elseif h:sub(1,1) == "~" then
					if string.find(host, h:sub(2)) then
						target_srv = srv
						break
					end
				end
			end
			if not target_srv then target_srv = srv end
		end
	end

	local servlet
	if target_srv then
		local longest_n = 0
		local path = req.url.path
		local idx
		local match_done = false
		for i,slcf in ipairs(target_srv.servlet) do
			local modifier,pat = slcf[1],slcf[2]
			if modifier == "=" then
				if path == pat then
					idx = i
					match_done = true
					break
				end
			elseif modifier == "^" or modifier == "^~" then
				local s,e = string.find(path, pat, 1, true)
				if s and e > longest_n then
					longest_n, idx, match_done = e, i, (modifier == "^~")
				end
			end
		end

		if match_done == true then
			servlet = target_srv.servlet[idx]
		else
			for i,slcf in ipairs(target_srv.servlet) do
				local modifier,pat = slcf[1],slcf[2]
				if modifier == "~" then
					if string.find(path, pat) then
						idx = i
						break
					end
				elseif modifier == "~*" then
					if string.find(string.lower(path), string.lower(pat)) then
						idx = i
						break
					end
				elseif modifier == "f"  then
					if pat(req) then
						idx = i
						break
					end
				end
			end
			if idx then servlet = target_srv.servlet[idx] end
		end
	end

	if servlet then
		local fn = servlet[3]
		local extra = servlet[4]
		local err
		if type(fn) == 'string' then
			fn = require(fn)
			assert(fn)
			err = fn.service(req,rsp,target_srv,extra)
		elseif type(fn) == 'function' then
			err = fn(req,rsp,target_srv,extra)
		end
		if not err then
			if rsp.headers["transfer-encoding"] == "chunked" then
				local ret
				ret,err = rsp.sock:send("0\r\n\r\n")
			end
		end
		if err then
			print(err)
			return false
		end
	else
		print "no servlet"
	end
end

local function http_request_handler(sock)
	while true do
		local line,err = sock:receive()
		if err then print(err); break end
		local method,url,ver = string.match(line, "(.*) (.*) HTTP/(%d%.%d)")
		url = parse_url(url)
		local headers = receive_headers(sock)
		local req = http_req_new(method, url, headers, sock)
		local rsp = http_rsp_new(req, sock)
		local success = do_servlet(req, rsp)
		if (success == false) or headers["connection"] == "close" then
			break
		end
	end
end

local function run(cfg)
	g_http_cfg = cfg
	return tcp(cfg, http_request_handler)
end

return run
