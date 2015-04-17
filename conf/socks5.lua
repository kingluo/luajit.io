local conf_prefix = string.match(arg[0], ".*/") or "./"
package.path = package.path .. ";"
    .. conf_prefix .. "../lib/?.lua;" .. conf_prefix .. "../lib/?/init.lua"

require("ljio.socket.tcpd") {
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

    {
        listen = {
            {port = 12345},
        },
        handler = "ljio.socket.socks5"
    },
}
