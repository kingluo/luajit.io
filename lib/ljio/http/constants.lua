-- Copyright (C) Jinhua Luo

local status_tbl = {
	[200] = "HTTP/1.1 200 OK\r\n";
	[302] = "HTTP/1.1 302 Found\r\n";
	[304] = "HTTP/1.1 304 Not Modified\r\n";
	[400] = "HTTP/1.1 400 Bad Request\r\n";
	[403] = "HTTP/1.1 403 Forbidden\r\n";
	[404] = "HTTP/1.1 404 Not Found\r\n";
	[408] = "HTTP/1.1 408 Request Time-out\r\n";
	[413] = "HTTP/1.1 413 Request Entity Too Large\r\n";
	[414] = "HTTP/1.1 414 Request-URI Too Large\r\n";
	[500] = "HTTP/1.1 500 Internal Server Error\r\n";
	[501] = "HTTP/1.1 501 Not Implemented\r\n";
	[503] = "HTTP/1.1 503 Service Unavailable\r\n";
}

local special_rsp_template = [[
<html>
<head><title>$status</title></head>
<body bgcolor="white">
<center><h1>$status</h1></center>
<hr><center>luajit.io</center>
</body>
</html>
]]

local function content_aux(status)
	return string.gsub(special_rsp_template, "%$(%w+)", {status=status})
end

local special_rsp = {
	[302] = content_aux("302 Found");
	[400] = content_aux("400 Bad Request");
	[403] = content_aux("403 Forbidden");
	[404] = content_aux("404 Not Found");
	[408] = content_aux("408 Request Time-out");
	[413] = content_aux("413 Request Entity Too Large");
	[414] = content_aux("414 Request-URI Too Large");
	[500] = content_aux("500 Internal Server Error");
	[501] = content_aux("501 Not Implemented");
	[503] = content_aux("503 Service Unavailable");
}

return {
	status_tbl = status_tbl,
	special_rsp = special_rsp,
}
