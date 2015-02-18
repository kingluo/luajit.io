package.path = package.path .. ";./modules/?.lua;./modules/?/init.lua"

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

	-- Server blocks
	-- See http://nginx.org/en/docs/http/request_processing.html
	{
		listen = {
			{port=8080,default_server=1}
		},
		server_name = {"example.org", "*.example.com", "~my%d+web%.org"},
		root = "/srv/myserver",
		default_type = 'text/plain',
		servlet = {
			-- See nginx location directive:
			-- http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			-- Add two new modifiers:
			-- "^" explicitly denotes longest prefix matching
			-- "$" means postfix matching, if matched, regexp match would be skipped
			-- "f" means matching function, with same matching priority as regexp matching
			-- {<modifier>, (<pattern> | <match function>), (<module> | <inline function>), ...}
			{"=", "/test2", "test"},
			{"^", "/foobar", "foobar_mod"},
			{"$", "luax", "http.luax", alias="WEB-INF/luax/"},
			{"^~", "/static/", "http.static"},
			{
				"f",
				function(req)
					return req.headers["user-agent"]:find("curl")
				end,
				"test"
			},
		}
	},
	{
		listen = {
			{address="127.0.0.1", port=8080},
			{address="127.0.0.1", port=10000}
		},
		server_name = {"example.net"},
		root = "/srv/foorbar",
		default_type = 'text/plain',
		servlet = {
			{"^~", "/static/", "static_mod"}
		}
	},
}
