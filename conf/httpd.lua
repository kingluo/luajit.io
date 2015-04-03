local conf_prefix = string.match(arg[0], ".*/") or "./"
package.path = package.path .. ";"
	.. conf_prefix .. "../lib/?.lua;" .. conf_prefix .. "../lib/?/init.lua"

require("ljio.http") {
	-- toggle strict global env
	strict = true,

	-- logging
	log_level = "info",
	log_stderr = true,
	log_import_print = false,

	user = "nobody",
	group = "nogroup",
	working_directory = conf_prefix .. "../",
	daemon = false,
	worker_processes = 1,
	worker_connections = 512,

	gzip = true,
	gzip_comp_level = 1,
	gzip_min_length = 20,
	gzip_types = {
		["text/html"] = true,
		["text/plain"] = true,
		["application/javascript"] = true,
		["text/css"] = true,
		["application/json"] = true,
	},

	types = "mime.types",

	client_header_timeout = 60,
	large_client_header_buffers = {4, 8 * 1024},
	client_body_timeout = 60,
	client_max_body_size = 1 * 1024 * 1024,

	{
		listen = {
			{port = 80},
		},
		server_name = {"example.net", "*.example.com", "~my%d+web%.org"},
		root = "/srv/foobar",
		default_type = 'text/plain',
		location = {
			{"=", "/hello", function(req, rsp) return rsp:say("hello world!") end},
			{
				"f",
				function(req)
					if string.find(req.headers["user-agent"], "curl", 1, true) then
						return string.match(req.url.path, "^/(test/[a-zA-Z0-9_%-/]*)")
					end
				end,
				function(req, rsp)
					return require(req.match_data[1])(req, rsp)
				end
			},
		}
	},
}
