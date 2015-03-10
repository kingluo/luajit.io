conf_path = string.match(arg[0], ".*/") or "./"
package.path = package.path .. ";" .. conf_path .. "/modules/?.lua;" .. conf_path .. "/modules/?/init.lua"

require("http") {
	-- toggle strict global env
	strict = true,

	-- logging
	log_level = "debug",
	log_stderr = true,
	log_import_print = false,

	user = "nobody",
	group = "nogroup",
	daemon = false,
	worker_processes = 1,
	worker_connections = 2,

	ssl = true,
	ssl_certificate = "/opt/carbox/sslkey/server.crt",
	ssl_certificate_key = "/opt/carbox/sslkey/server.key",
	ssl_ciphers = "RC4:HIGH:!aNULL:!MD5",

	lua_shared_dict = {
		test = "10m",
		my_locks = "100k"
	},

	gzip = true,
	gzip_comp_level = 1,
	gzip_min_length = 20,
	gzip_types = {
		["text/html"] = true,
		["text/plain"] = true,
	},

	types = "mime.types",

	-- Server blocks
	-- Refer to http://nginx.org/en/docs/http/request_processing.html
	{
		listen = {
			{port = 8080, default_server = true, ssl = true},
			{address = "unix:/var/run/test.sock"}
		},
		server_name = {"example.org", "*.example.com", "~my%d+web%.org"},
		root = "/srv/myserver",
		default_type = 'text/plain',
		location = {
			-- Refer to nginx location directive:
			-- http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			-- Besides nginx modifiers, two new modifiers are added:
			-- "^" explicitly indicates longest prefix matching
			-- "f" matching function for arbitrary matching, with same priority as regexp matching
			--
			-- {<modifier>, (<pattern> | <match function>), (<module> | <inline function>), ...}
			--
			{"=", "/", function(req, rsp) return rsp:exec("/test.luax") end},
			{"=", "/hello", function(req, rsp) rsp:say("hello world!") end},
			{"~*", "%.luax$", "http.luax", luax_prefix = "/WEB-INF/luax/"},
			{"^~", "/foobar", "foo.bar.module"},
			{"^~", "/WEB-INF/", function(req, rsp) return rsp:finalize(403) end},
			{
				"f",
				function(req)
					if string.find(req.headers["user-agent"], "curl") then
						return string.match(req.url:path(), "^/test/([a-zA-Z0-9_%-/]*)")
					end
				end,
				function(req, rsp)
					local test = "test." .. string.gsub(req.match_data[1], "/", ".")
					return require(test)(req, rsp)
				end,
				gzip_types = {
					["application/json"] = true,
				}
			},
		}
	},
	{
		listen = {
			{address = "127.0.0.1", port = 8080},
			{address = "127.0.0.1", port = 10000}
		},
		server_name = {"example.net"},
		root = "/srv/foorbar",
		default_type = 'text/plain',
		location = {
			{"^~", "/static/", "static_mod"}
		}
	},
}
