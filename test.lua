
local pg = require("resty.postgres")
local upload = require("resty.upload")
local ffi = require"ffi"











return function(req, rsp)
	-- test_upload(req, rsp)
	-- test_coroutine(req, rsp)



	-- test_lock(req, rsp)

	return rsp:say("hello world! test handler\n")
end
