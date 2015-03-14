conf_file = arg[0]
conf_path = string.match(conf_file, ".*/") or "./"
package.path = package.path .. ";"
	.. conf_path .. "/modules/?.lua;" .. conf_path .. "/modules/?/init.lua"

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
	worker_connections = 100,

	ssl = true,
	ssl_certificate = "/opt/carbox/sslkey/server.crt",
	ssl_certificate_key = "/opt/carbox/sslkey/server.key",
	ssl_ciphers = "RC4:HIGH:!aNULL:!MD5",

	lua_shared_dict = {
		test = "10m",
		my_locks = "100k",
	},

	gzip = true,
	gzip_comp_level = 1,
	gzip_min_length = 20,
	gzip_types = {
		["text/html"] = true,
		["text/plain"] = true,
		["application/javascript"] = true,
		["text/css"] = true,
	},

	types = "mime.types",

	-- Server blocks
	-- Refer to http://nginx.org/en/docs/http/request_processing.html
	{
		listen = {
			{address = "192.168.8.137", port = 80, default_server = true, ssl = false},
			{address = "unix:/var/run/test.sock"}
		},
		server_name = {"luajit.io", "*.example.com", "~my%d+web%.org"},
		root = "/srv/myserver",
		default_type = 'text/plain',
		package_path = package.path
			.. ";/srv/myserver/WEB-INF/?.lua;/srv/myserver/WEB-INF/?/init.lua",
		location = {
			-- Refer to nginx location directive:
			-- http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			-- Besides nginx modifiers, two new modifiers are added:
			-- "^" explicitly indicates longest prefix matching
			-- "f" function for arbitrary matching, with same priority as regexp matching
			--
			-- {<modifier>, (<pattern> | <function>), (<module> | <function>), ...}
			--
			{"=", "/", function(req, rsp) return rsp:exec("/index.html") end},
			{"=", "/demo/tryredis", function(req, rsp) return rsp:exec("/demo.html") end},
			{"=", "/demo/tryredis/exec", "demo.tryredis"},
			{"=", "/demo/tryredis/source",
				function(req, rsp)
					rsp:say("### httpd.lua")
					rsp:say("```lua")
					rsp:try_file(conf_file, false, true)
					rsp:say("```")
					rsp:say("### tryredis.lua")
					rsp:say("```lua")
					rsp:try_file("/WEB-INF/demo/tryredis.lua", false)
					rsp:say("```")
				end
			},
			{"=", "/hello", function(req, rsp) rsp:say("hello world!") end},
			{"~*", "%.luax$", "http.luax", luax_prefix = "/WEB-INF/luax/"},
			{"^~", "/WEB-INF/", function(req, rsp) return rsp:finalize(403) end},
		}
	},
	{
		listen = {
			{address = "127.0.0.1", port = 80, ssl = true},
			{address = "127.0.0.1", port = 8080}
		},
		server_name = {"example.net"},
		root = "/srv/foorbar",
		default_type = 'text/plain',
		location = {
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
}
