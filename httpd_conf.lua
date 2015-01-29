-- package.path = '/usr/local/share/lua/5.1/?.lua;/home/resty/?.lua;'
-- package.cpath = '/usr/local/lib/lua/5.1/?.so;'

local function test_servlet(req, rsp, cf, extra)
	return rsp:say("hello world, conf ok!\n")
end

http_conf {
	-- server blocks
	{
		listen = "127.0.0.1:8080",
		-- listen = 80,
		server_name = {"example.com", "~.*%.example%.com"},
		-- server_name = "localhost",
		root = "/srv/mytest",
		default_type = 'text/plain',
		servlet = {
			-- match in array order
			-- {(<url match pattern>|<match function>), (<module name>|<servlet function>)}, [<extra>]
			{"%.lsp$", "lsp_mod"},
			{"^/static/files/", "static_mod"},
			{
				function(req)
					return true
				end,
				test_servlet,
				{foo=1,bar="hello"}
			},
		}
	},
}