local conf_prefix = string.match(arg[0], ".*/") or "./"
package.path = package.path .. ";"
    .. conf_prefix .. "../lib/?.lua;" .. conf_prefix .. "../lib/?/init.lua" .. ";../test"

require("ljio.http") {
    -- toggle strict global env
    strict = true,

    -- logging
    log_level = "info",
    log_stderr = true,
    log_import_print = false,

    user = "nobody",
    group = "nobody",
    working_directory = conf_prefix .. "../",
    daemon = false,
    worker_processes = 1,
    worker_connections = 512,

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
        ["application/json"] = true,
    },

    types = "mime.types",

    client_header_timeout = 60,
    large_client_header_buffers = {4, 8 * 1024},
    client_body_timeout = 60,
    client_max_body_size = 1 * 1024 * 1024,

    -- Server blocks
    -- Refer to http://nginx.org/en/docs/http/request_processing.html
    {
        listen = {
            {port = 80},
        },
        server_name = {"luajit.io"},
        root = "/srv/myserver",
        default_type = 'text/plain',
        package_path = package.path
            .. ";/srv/myserver/WEB-INF/lib/?.lua;/srv/myserver/WEB-INF/lib/?/init.lua",
        location = {
            -- Refer to http://nginx.org/en/docs/http/ngx_http_core_module.html#location
            -- Besides nginx modifiers, two new modifiers are added:
            -- "^" explicitly indicates longest prefix matching
            -- "f" function for arbitrary matching, with same priority as regexp matching
            --
            -- {<modifier>, (<pattern> | <function>), (<module> | <function>), ...}
            --
            {"=", "/", function(req, rsp) return rsp:exec("/index.html") end},
            {"=", "/demo/tryredis/exec", "ljio.demo.tryredis"},
            {"~*", "%.luax$", "ljio.http.luax", luax_prefix = "/WEB-INF/luax/"},
            {"^~", "/WEB-INF/", function(req, rsp) return rsp:finalize(403) end},
        }
    },
    {
        listen = {
            {address = "127.0.0.1", port = 80},
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
